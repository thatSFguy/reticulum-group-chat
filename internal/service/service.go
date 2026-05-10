// Package service is the forwarding daemon's top layer: it wires our own
// rns + lxmf packages into a roster-aware group-chat relay with
// slash-command moderation and replay-on-join.
package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
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

	id, err := loadOrCreateIdentity(cfg.Service.IdentityB64, cfg.Service.IdentityPath, logger)
	if err != nil {
		return nil, err
	}

	transport := rns.NewTransport(stdLoggerAdapter{logger})
	// buildAnnounceWithContext is the same announce body as our periodic
	// announce, but we let the caller pick the context byte so the
	// Transport can mint path-response announces (context 0x0B) on
	// demand without duplicating the appData/identity wiring.
	buildAnnounceWithContext := func(ctx byte) (*rns.Packet, error) {
		appData, err := rns.EncodeLXMFAppData([]byte(cfg.Service.DisplayName), nil)
		if err != nil {
			return nil, err
		}
		return rns.BuildAnnounceWithContext(id, lxmf.FullName(), appData, nil, ctx)
	}
	delivery, err := lxmf.NewDelivery(transport, id, buildAnnounceWithContext)
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
		Cfg:                 cfg,
		Roster:              r,
		Announce:            svc.announceNow,
		PathLookup:          svc.pathLookup,
		OnJoin:              svc.onJoin,
		LookupAnnouncedName: svc.lookupAnnouncedName,
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

	// Persist the announce cache so a service restart can reach every
	// previously-known peer immediately, instead of waiting up to one
	// AnnounceInterval (10 min default) for them to re-announce. The
	// store is loaded eagerly here; the persist tap runs on every
	// inbound verified announce thereafter.
	announceStore := newAnnounceStore(announceStorePath(cfg.Service.StatePath))
	if entries, dropped, err := announceStore.load(svc.now()); err != nil {
		logger.Printf("announce cache load: %v (continuing with empty cache)", err)
	} else {
		for _, e := range entries {
			transport.Restore(e)
		}
		if len(entries) > 0 || dropped > 0 {
			logger.Printf("announce cache restored: %d entries (dropped %d stale > %s)",
				len(entries), dropped, announceStoreMaxAge)
		}
	}
	transport.RegisterAnnounceHandler(&announcePersistTap{
		transport: transport,
		store:     announceStore,
		logger:    logger,
	})

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

// lookupAnnouncedName returns the announced display name for a peer
// from their most recent verified announce, or "" if no announce has
// been heard or the announce carried no display name. Called by the
// commands dispatcher to default a fresh /join'er's nickname to their
// announced name. Decoding errors collapse to "" (the caller treats
// empty as "no default available").
func (s *Service) lookupAnnouncedName(hashBytes []byte) string {
	if len(hashBytes) != rns.IdentityHashLen {
		return ""
	}
	known := s.transport.Recall(hashBytes)
	if known == nil || len(known.AppData) == 0 {
		return ""
	}
	name, err := rns.DecodeLXMFAppDataDisplayName(known.AppData)
	if err != nil || len(name) == 0 {
		return ""
	}
	return string(name)
}

// pathLookup is the /path hook — translates the dispatcher's hex
// dest_hash into a snapshot of what the transport actually knows about
// reaching that destination: cached announce, hop count, multi-hop
// next-hop transport_id, and whether an Active Link is currently open.
// Returns PathInfo{Known:false} for any hex that fails to decode or for
// a destination we've never seen announced.
func (s *Service) pathLookup(destHashHex string) commands.PathInfo {
	destHash, err := hex.DecodeString(destHashHex)
	if err != nil || len(destHash) != 16 {
		return commands.PathInfo{}
	}
	known := s.transport.Recall(destHash)
	if known == nil {
		return commands.PathInfo{}
	}
	info := commands.PathInfo{
		Known:    true,
		LastSeen: known.LastSeen,
		Hops:     int(known.Hops),
	}
	if len(known.TransportID) == 16 {
		info.NextHopHex = hex.EncodeToString(known.TransportID)
	}
	if s.transport.LinkManager().ActiveTo(destHash) != nil {
		info.LinkActive = true
	}
	return info
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

// loadOrCreateIdentity resolves the service identity from one of three
// sources, in priority order:
//
//  1. service.identity_b64 in the config — base64-encoded backup of the
//     64-byte raw identity. When set, the on-disk file at identityPath
//     is ignored and not written to. Lets an operator keep the identity
//     in the same config file they back up before a reinstall.
//  2. The binary file at identityPath, if it exists.
//  3. Generate a fresh identity and save it to identityPath. Also
//     writes a sibling identity.b64.txt with the base64 form so the
//     operator can copy the value into service.identity_b64 to make
//     the config the single backup target. The b64 path is logged
//     prominently so the recommendation is visible on first run.
func loadOrCreateIdentity(b64 string, identityPath string, logger *log.Logger) (*rns.Identity, error) {
	if b64 = strings.TrimSpace(b64); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("service.identity_b64: not valid base64: %w", err)
		}
		id, err := rns.IdentityFromPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("service.identity_b64: %w", err)
		}
		logger.Printf("identity loaded from config (identity_b64); ignoring %s", identityPath)
		return id, nil
	}
	if _, err := os.Stat(identityPath); err == nil {
		return rns.IdentityFromFile(identityPath)
	}
	id, err := rns.NewIdentity()
	if err != nil {
		return nil, err
	}
	if err := id.Save(identityPath); err != nil {
		return nil, fmt.Errorf("save new identity: %w", err)
	}
	backupPath := identityPath + ".b64.txt"
	encoded := base64.StdEncoding.EncodeToString(id.PrivateKey())
	if err := writeIdentityBackup(backupPath, encoded); err != nil {
		// Backup file failed to write but the identity is safe on disk
		// at identityPath. Log loudly and continue — better to keep the
		// daemon running than to fail startup over a backup-file write.
		logger.Printf("WARNING: could not write identity backup to %s: %v", backupPath, err)
		logger.Printf("WARNING: copy the contents of %s manually to back up your identity", identityPath)
	} else {
		logger.Printf("created new identity at %s", identityPath)
		logger.Printf("BACKUP: identity also written to %s as base64", backupPath)
		logger.Printf("BACKUP: copy that value into your config under [service] identity_b64 = \"...\"")
		logger.Printf("BACKUP: so the identity survives losing the data dir at %s", filepath.Dir(identityPath))
	}
	return id, nil
}

// writeIdentityBackup writes the base64 form of the identity (with a
// trailing newline) to path with mode 0600. Atomic via tempfile rename
// in the same dir so a crash mid-write can't leave a partial file.
func writeIdentityBackup(path, b64 string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".identity-backup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.WriteString(b64 + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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
