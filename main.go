package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cidverse/ocisync/pkg/ocisync"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <config.yaml>\n", os.Args[0])
		os.Exit(2)
	}

	configPath := os.Args[1]
	cfg, err := ocisync.LoadConfig(configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	syncer, err := ocisync.NewSyncer(cfg, logger)
	if err != nil {
		logger.Error("failed to create sync instance", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	stats, err := syncer.Run(ctx)
	logger.Info("sync completed",
		"duration", time.Since(started).Round(time.Millisecond).String(),
		"scanned", stats.Scanned,
		"matched", stats.Matched,
		"copied", stats.Copied,
		"skipped", stats.Skipped,
		"failed", stats.Failed,
	)
	if err != nil {
		logger.Error("sync finished with errors", "error", err)
		stop()
		os.Exit(1)
	}
}
