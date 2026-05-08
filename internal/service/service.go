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
	"io"
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

// replyContentBudget WAS the byte cap on command replies back when
// Delivery.Send was opportunistic-only — large /users replies silently
// vanished because the prefixed msgpack body exceeded
// lxmf.MaxOpportunisticPayload (295). Since v1.1.0 Delivery.Send auto-
// routes oversized replies through a Reticulum Link, so the cap is no
// longer necessary: list commands return the full list and the wire
// path is chosen for us.
//
// We keep the constant defined for documentation + the truncation
// helper still works (callers that want a per-command cap can set
// Dispatcher.MaxReplyContentBytes themselves). The dispatcher wiring
// below uses 0 = unlimited.
const replyContentBudget = lxmf.MaxOpportunisticPayload - 16

type Service struct {
	cfg        *config.Config
	identity   *rns.Identity
	transport  *rns.Transport
	delivery   *lxmf.Delivery
	roster     *roster.Roster
	history    *history.Log
	dispatcher *commands.Dispatcher
	outbound   *OutboundQueue

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

	logWriter, err := openLogWriter(cfg.Service.LogPath)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	logger := log.New(logWriter, "fwdsvc ", log.LstdFlags|log.Lmicroseconds)

	id, err := loadOrCreateIdentity(cfg.Service.IdentityPath, logger)
	if err != nil {
		return nil, err
	}

	transport := rns.NewTransport(stdLoggerAdapter{logger})
	delivery, err := lxmf.NewDelivery(transport, id)
	if err != nil {
		return nil, fmt.Errorf("register delivery: %w", err)
	}

	outboundStore := newOutboundStore(outboundStorePath(cfg.Service.StatePath))
	outbound := newOutboundQueue(
		&deliverySender{delivery: delivery, transport: transport},
		outboundStore,
		logger,
	)
	if err := outbound.Load(); err != nil {
		return nil, fmt.Errorf("load outbound queue: %w", err)
	}

	svc := &Service{
		cfg:       cfg,
		identity:  id,
		transport: transport,
		delivery:  delivery,
		roster:    r,
		history:   hist,
		outbound:  outbound,
		logger:    logger,
		now:       time.Now,
	}
	svc.dispatcher = &commands.Dispatcher{
		Cfg:      cfg,
		Roster:   r,
		Announce: svc.announceNow,
		OnJoin:   svc.onJoin,
		// MaxReplyContentBytes intentionally left at 0 (unlimited) — see
		// replyContentBudget docstring. Delivery.Send routes oversize
		// replies through Link automatically, so /users etc. return the
		// full list regardless of roster size.
		MaxReplyContentBytes: 0,
		OverflowLog:          logger.Printf,
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
	// RunLinkSweeper closes idle outbound links and emits KEEPALIVE on
	// active ones so the responder doesn't tear them down for inactivity.
	go s.transport.RunLinkSweeper(tCtx)
	// OutboundQueue.Run drains the persisted outbound message queue —
	// retries up to maxDeliveryAttempts with deliveryRetryWait backoff,
	// path-request defer for unknown recipients. Sequential by design
	// (half-duplex collision resilience).
	go s.outbound.Run(tCtx)

	s.logger.Printf("outbound queue depth   : %d", s.outbound.pendingCount())

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

// onJoin is the /join post-action hook — fires replay-on-join for the
// newly-joined user so they catch up on recent history.
func (s *Service) onJoin(senderHex string) {
	bytes, err := hex.DecodeString(senderHex)
	if err != nil || len(bytes) != 16 {
		return
	}
	if s.cfg.Replay.Count > 0 {
		go s.replayHistoryTo(bytes, s.now())
	}
}

// announceNow is the /announce hook — builds a fresh announce and
// broadcasts it on every interface immediately. Logs the action so an
// operator watching the log can correlate.
func (s *Service) announceNow() error {
	pkt, err := s.buildAnnounce()
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	s.logger.Printf("on-demand /announce")
	return s.transport.Broadcast(pkt)
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

// openLogWriter returns an io.Writer for the daemon logger. Stdout is
// always included so operators running fwdsvc in the foreground keep
// seeing output. If logPath is non-empty, the file is opened in append
// mode (mode 0600 — log lines may include user dest_hashes) and tee'd
// alongside stdout via io.MultiWriter; the file handle leaks
// intentionally (its lifetime is the process). On any open error the
// caller decides whether to fail startup.
func openLogWriter(logPath string) (io.Writer, error) {
	if logPath == "" {
		return os.Stdout, nil
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return io.MultiWriter(os.Stdout, f), nil
}

// stdLoggerAdapter bridges a *log.Logger into rns.Logger.
type stdLoggerAdapter struct{ l *log.Logger }

func (s stdLoggerAdapter) Printf(format string, args ...any) { s.l.Printf(format, args...) }

// Compile-time guard: announceTap implements rns.AnnounceHandler.
var _ rns.AnnounceHandler = (*announceTap)(nil)

// errSenderUnknown is surfaced from inbound when the LXMF source hasn't
// announced yet. We can't reply to them either, so the message is dropped.
var errSenderUnknown = errors.New("sender hasn't announced yet")
