package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/cidverse/ocisync/pkg/ocisync"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	var configPath = os.Args[1]
	cfg, err := ocisync.LoadConfig(configPath)
	if err != nil {
		slog.With("error", err).Error("failed to load config")
		os.Exit(1)
	}

	syncer, err := ocisync.NewSyncer(cfg, logger)
	if err != nil {
		slog.With("error", err).Error("failed to create sync instance")
		os.Exit(1)
	}

	started := time.Now()
	stats, err := syncer.Run(context.Background())
	if err != nil {
		slog.With("error", err).Error("failed to run sync")
		os.Exit(1)
	}

	slog.With("duration", time.Since(started).Round(time.Millisecond).String(),
		"scanned", stats.Scanned,
		"matched", stats.Matched,
		"copied", stats.Copied,
		"skipped", stats.Skipped,
		"failed", stats.Failed,
	).Info("sync completed")
}
