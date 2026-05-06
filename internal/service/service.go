package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/svanichkin/go-lxmf/lxmf"
	"github.com/svanichkin/go-reticulum/rns"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/commands"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/history"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
)

// Service is the running forwarding daemon.
type Service struct {
	cfg         *config.Config
	identity    *rns.Identity
	router      *lxmf.LXMRouter
	destination *rns.Destination
	roster      *roster.Roster
	history     *history.Log
	dispatcher  *commands.Dispatcher

	logger *log.Logger
	now    func() time.Time
}

// New constructs the service. It does not start any goroutines or touch
// the network until Run is called.
func New(cfg *config.Config) (*Service, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Service.IdentityPath), 0o755); err != nil {
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

	return &Service{
		cfg:        cfg,
		roster:     r,
		history:    hist,
		dispatcher: &commands.Dispatcher{Cfg: cfg, Roster: r},
		logger:     log.New(os.Stdout, "fwdsvc ", log.LstdFlags),
		now:        time.Now,
	}, nil
}

// Run boots Reticulum, registers our LXMF identity, then blocks until ctx
// is cancelled. On shutdown it persists state and announces departure.
func (s *Service) Run(ctx context.Context) error {
	if err := s.startReticulum(); err != nil {
		return err
	}
	if err := s.loadOrCreateIdentity(); err != nil {
		return err
	}
	if err := s.startRouter(); err != nil {
		return err
	}

	s.logger.Printf("identity hash: %s", s.identity.HexHash)
	s.logger.Printf("display name : %s", s.cfg.Service.DisplayName)
	s.logger.Printf("roster size  : %d", len(s.roster.Hashes()))
	s.logger.Printf("history size : %d", s.history.Len())

	go s.router.JobLoop()

	if s.destination != nil {
		s.router.Announce(s.destination.Hash, nil)
	}

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

func (s *Service) startReticulum() error {
	cfgDir := s.cfg.Reticulum.ConfigPath
	_, err := rns.NewReticulum(&cfgDir, nil, nil, nil, false, nil)
	if err != nil {
		return fmt.Errorf("start reticulum: %w", err)
	}
	return nil
}

func (s *Service) loadOrCreateIdentity() error {
	path := s.cfg.Service.IdentityPath
	if _, err := os.Stat(path); err == nil {
		id, err := rns.IdentityFromFile(path)
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}
		s.identity = id
		return nil
	}

	id, err := rns.NewIdentity()
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	if err := id.Save(path); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}
	s.identity = id
	s.logger.Printf("created new identity at %s", path)
	return nil
}

func (s *Service) startRouter() error {
	storage := filepath.Dir(s.cfg.Service.IdentityPath)
	router, err := lxmf.NewLXMRouter(s.identity, storage)
	if err != nil {
		return fmt.Errorf("start lxmf router: %w", err)
	}
	router.RegisterDeliveryCallback(s.onLXMFReceived)
	displayName := s.cfg.Service.DisplayName
	dest := router.RegisterDeliveryIdentity(s.identity, &displayName, nil)

	rns.RegisterAnnounceHandler(lxmf.NewDeliveryAnnounceHandler(router))
	rns.RegisterAnnounceHandler(&announceTap{svc: s})

	s.router = router
	s.destination = dest
	return nil
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

// hexHash is a small helper to format a Reticulum identity hash byte slice.
func hexHash(b []byte) string { return hex.EncodeToString(b) }
