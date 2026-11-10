package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
	"github.com/thatSFguy/reticulum-group-chat/internal/service"
	"github.com/thatSFguy/reticulum-group-chat/internal/version"
)

// Version is the human-readable release marker for this build. Sourced
// from internal/version so the /about command and other internals
// reference the same constant without import cycles.
const Version = version.Version

func main() {
	configPath := flag.String("config", "~/.fwdsvc/config.toml", "path to config TOML")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("fwdsvc %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	// These lines go to stderr, which systemd sends to the journal just
	// like stdout, so they need priorities too. Without one, journald
	// files them as info and LogLevelMax=warning would hide exactly the
	// lines that say why the service refused to start. The config error
	// is logged before log_level is known, so it is written
	// unconditionally.
	cfg, err := config.Load(*configPath)
	if err != nil {
		logging.New(os.Stderr, nil, rns.LogDebug).Errorf("config: %v", err)
		os.Exit(2)
	}
	logger := logging.New(os.Stderr, nil, cfg.Service.LogLevelValue)

	logger.Infof("fwdsvc %s starting (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
	for _, w := range cfg.Warnings {
		logger.Warnf("config warning: %s", w)
	}

	svc, err := service.New(cfg)
	if err != nil {
		logger.Errorf("init: %v", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := svc.Run(ctx); err != nil {
		logger.Errorf("run: %v", err)
		os.Exit(1)
	}
}
