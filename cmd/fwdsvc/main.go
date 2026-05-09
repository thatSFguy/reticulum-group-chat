package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/service"
)

// Version is the human-readable release marker for this build. Bumped
// per release; printed by --version and emitted in the startup log.
const Version = "1.2.3"

func main() {
	configPath := flag.String("config", "~/.fwdsvc/config.toml", "path to config TOML")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("fwdsvc %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	log.Printf("fwdsvc %s starting (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)

	svc, err := service.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := svc.Run(ctx); err != nil {
		log.Fatalf("run: %v", err)
	}
}
