// Package service is the forwarding daemon's top layer: it wires our own
// rns + lxmf packages into a roster-aware group-chat relay with
// slash-command moderation and replay-on-join.
package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/commands"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/history"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/lxmf"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
)

type Service struct {
	cfg        *config.Config
	identity   *rns.Identity
	transport  *rns.Transport
	delivery   *lxmf.Delivery
	roster     *roster.Roster
	history    *history.Log
	dispatcher *commands.Dispatcher

	logger *log.Logger
	now    func() time.Time
}

// New constructs the Service: loads/creates the identity, builds the
// transport and registers configured interfaces, and registers an LXMF
// delivery destination. It does NOT start any goroutines or dial network
// peers — that happens in Run.
func New(cfg *config.Config) (*Service, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Service.IdentityPath), 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	rosterStore := roster.NewStore(cfg.Service.StatePath)
	r, err := roster.New(rosterStore)
	if err != nil {
		return nil, fmt.Errorf("load roster: %w", err)
	}
	hist, err := history.New(cfg.Service.HistoryPath, cfg.Replay.Count)
	if err != nil {
		return nil, fmt.Errorf("load history: %w", err)
	}

	logger := log.New(os.Stdout, "fwdsvc ", log.LstdFlags)

	id, err := loadOrCreateIdentity(cfg.Service.IdentityPath, logger)
	if err != nil {
		return nil, err
	}

	transport := rns.NewTransport(stdLoggerAdapter{logger})
	delivery, err := lxmf.NewDelivery(transport, id)
	if err != nil {
		return nil, fmt.Errorf("register delivery: %w", err)
	}

	svc := &Service{
		cfg:        cfg,
		identity:   id,
		transport:  transport,
		delivery:   delivery,
		roster:     r,
		history:    hist,
		dispatcher: &commands.Dispatcher{Cfg: cfg, Roster: r},
		logger:     logger,
		now:        time.Now,
	}

	delivery.OnMessage = svc.onLXMFReceived
	delivery.OnError = func(err error) { logger.Printf("inbound: %v", err) }

	transport.RegisterAnnounceHandler(&announceTap{svc: svc})

	return svc, nil
}

// Run starts everything: dial configured interfaces, start the transport
// dispatcher, periodic announce, and prune ticker. Blocks until ctx is
// cancelled.
func (s *Service) Run(ctx context.Context) error {
	for _, iface := range s.cfg.Interfaces {
		if err := s.dialInterface(iface); err != nil {
			s.logger.Printf("interface %s %s: %v", iface.Type, iface.Addr, err)
			// Best-effort: continue with the interfaces that did connect.
		}
	}

	s.logger.Printf("service identity hash: %s", s.identity.HexHash())
	s.logger.Printf("delivery destination : %s", hex.EncodeToString(s.delivery.Hash()))
	s.logger.Printf("display name        : %s", s.cfg.Service.DisplayName)
	s.logger.Printf("roster size         : %d", len(s.roster.Hashes()))
	s.logger.Printf("history size        : %d", s.history.Len())

	tCtx, tCancel := context.WithCancel(ctx)
	defer tCancel()

	go s.transport.Run(tCtx)
	go s.transport.AnnouncePeriodically(tCtx, s.cfg.Service.AnnounceInterval.Std(), s.buildAnnounce)

	pruneTicker := time.NewTicker(s.cfg.Service.PruneInterval.Std())
	defer pruneTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("shutting down")
			return nil
		case t := <-pruneTicker.C:
			s.runPrune(t)
		}
	}
}

func (s *Service) dialInterface(iface config.InterfaceConfig) error {
	switch iface.Type {
	case "tcp_client":
		client, err := rns.DialTCP(iface.Addr, iface.Timeout.Std())
		if err != nil {
			return err
		}
		s.transport.AddInterface(client)
		s.logger.Printf("interface tcp_client connected: %s", iface.Addr)
		return nil
	default:
		return fmt.Errorf("unsupported interface type %q", iface.Type)
	}
}

func (s *Service) buildAnnounce() (*rns.Packet, error) {
	appData, err := rns.EncodeLXMFAppData([]byte(s.cfg.Service.DisplayName), nil)
	if err != nil {
		return nil, err
	}
	return rns.BuildAnnounce(s.identity, lxmf.FullName(), appData, nil)
}

func (s *Service) runPrune(now time.Time) {
	pruned, err := s.roster.Prune(now, s.cfg.Service.PruneAfter.Std())
	if err != nil {
		s.logger.Printf("prune error: %v", err)
		return
	}
	if len(pruned) > 0 {
		s.logger.Printf("pruned %d inactive user(s)", len(pruned))
	}
}

// loadOrCreateIdentity reads an identity from disk, or generates a new
// one and persists it on first run.
func loadOrCreateIdentity(path string, logger *log.Logger) (*rns.Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return rns.IdentityFromFile(path)
	}
	id, err := rns.NewIdentity()
	if err != nil {
		return nil, err
	}
	if err := id.Save(path); err != nil {
		return nil, fmt.Errorf("save new identity: %w", err)
	}
	logger.Printf("created new identity at %s", path)
	return id, nil
}

// announceTap updates a roster member's last_announce_at on every announce
// for the lxmf.delivery aspect. Announces alone do NOT auto-add a user;
// only an LXMF message does (per the user's "join by sending a message"
// rule).
type announceTap struct {
	svc *Service
}

var lxmfDeliveryNameHash = rns.NameHash(lxmf.FullName())

func (t *announceTap) AspectMatch(nameHash []byte) bool {
	return bytes.Equal(nameHash, lxmfDeliveryNameHash)
}

func (t *announceTap) OnAnnounce(a *rns.Announce) {
	if err := t.svc.roster.UpdateLastAnnounce(a.DestHash, t.svc.now()); err != nil {
		t.svc.logger.Printf("announce update: %v", err)
	}
}

// stdLoggerAdapter bridges a *log.Logger into rns.Logger.
type stdLoggerAdapter struct{ l *log.Logger }

func (s stdLoggerAdapter) Printf(format string, args ...any) { s.l.Printf(format, args...) }

// Compile-time guard: announceTap implements rns.AnnounceHandler.
var _ rns.AnnounceHandler = (*announceTap)(nil)

// errSenderUnknown is surfaced from inbound when the LXMF source hasn't
// announced yet. We can't reply to them either, so the message is dropped.
var errSenderUnknown = errors.New("sender hasn't announced yet")
