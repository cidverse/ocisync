package ocisync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

type SyncRunner struct {
	config           *Config
	logger           *slog.Logger
	registries       map[string]*registryClient
	helmRepositories map[string]*helmRepositoryClient
	checkers         []Evaluator
}

type SyncStats struct {
	Scanned int
	Matched int
	Copied  int
	Skipped int
	Failed  int
}

type SyncCandidate struct {
	ImageName        string
	SourceType       SourceType
	SourceRegistry   string
	TargetRegistry   string
	SourceRepository string
	TargetRepository string
	Tag              string
	SourceRef        string
	TargetRef        string
	Strategy         PushStrategy
}

func (c SyncCandidate) targetTag() string {
	if c.SourceType == SourceTypeHelmRepo {
		return helmChartRegistryTag(c.Tag)
	}
	return c.Tag
}

// artifactSource is implemented by all source registry clients (oci registries and helm repositories).
type artifactSource interface {
	ListTags(ctx context.Context, repository string) ([]string, error)
	Reference(repository, tag string) string
	CopyTo(ctx context.Context, target *registryClient, candidate SyncCandidate) error
}

func NewSyncer(cfg *Config, logger *slog.Logger) (*SyncRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}

	registries, err := newRegistryClients(cfg.Registries)
	if err != nil {
		return nil, fmt.Errorf("build registry clients: %w", err)
	}
	helmRepositories, err := newHelmRepositoryClients(cfg.Registries)
	if err != nil {
		return nil, fmt.Errorf("build helm repository clients: %w", err)
	}

	return &SyncRunner{
		config:           cfg,
		logger:           logger,
		registries:       registries,
		helmRepositories: helmRepositories,
		checkers:         nil,
	}, nil
}

// Run syncs all configured images. A failure of one image or tag does not stop the sync of the others; all errors are
// collected and returned together, and every failure is counted in SyncStats.Failed.
func (s *SyncRunner) Run(ctx context.Context) (*SyncStats, error) {
	stats := &SyncStats{}

	var errs []error
	for _, imageName := range sortedImageNames(s.config.Images) {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if err := s.syncRepository(ctx, imageName, s.config.Images[imageName], stats); err != nil {
			errs = append(errs, fmt.Errorf("images.%s: %w", imageName, err))
		}
	}

	return stats, errors.Join(errs...)
}

func (s *SyncRunner) syncRepository(ctx context.Context, imageName string, cfg ImageConfig, stats *SyncStats) error {
	source, target, err := s.clients(cfg)
	if err != nil {
		stats.Failed++
		return err
	}

	filter, err := newTagFilter(cfg)
	if err != nil {
		stats.Failed++
		return err
	}

	tags, err := source.ListTags(ctx, cfg.SourceRepository)
	if err != nil {
		stats.Failed++
		return fmt.Errorf("list source tags for %s from %s: %w", cfg.SourceRepository, cfg.SourceRegistry, err)
	}

	stats.Scanned += len(tags)
	matchedTags := filterTags(tags, filter)
	stats.Matched += len(matchedTags)

	s.logger.Info(
		"repository scan completed",
		"image", imageName,
		"sourceType", cfg.SourceType,
		"sourceRegistry", cfg.SourceRegistry,
		"targetRegistry", cfg.TargetRegistry,
		"sourceRepository", cfg.SourceRepository,
		"targetRepository", cfg.TargetRepository,
		"scanned", len(tags),
		"matched", len(matchedTags),
		"strategy", cfg.PushStrategy,
	)

	var errs []error
	for _, tag := range matchedTags {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}

		candidate := newCandidate(imageName, cfg, source, target, tag)
		copied, err := s.syncTag(ctx, source, target, candidate)
		switch {
		case err != nil:
			stats.Failed++
			s.logger.Error("failed to sync artifact", "image", imageName, "sourceRef", candidate.SourceRef, "targetRef", candidate.TargetRef, "error", err)
			errs = append(errs, err)
		case copied:
			stats.Copied++
		default:
			stats.Skipped++
		}
	}

	return errors.Join(errs...)
}

// clients returns the source and target clients for an image; config validation guarantees they exist.
func (s *SyncRunner) clients(cfg ImageConfig) (artifactSource, *registryClient, error) {
	target, ok := s.registries[cfg.TargetRegistry]
	if !ok {
		return nil, nil, fmt.Errorf("target registry %q is not an oci registry", cfg.TargetRegistry)
	}

	switch cfg.SourceType {
	case SourceTypeHelmRepo:
		if source, ok := s.helmRepositories[cfg.SourceRegistry]; ok {
			return source, target, nil
		}
	case SourceTypeOCI:
		if source, ok := s.registries[cfg.SourceRegistry]; ok {
			return source, target, nil
		}
	}
	return nil, nil, fmt.Errorf("source registry %q does not match source-type %q", cfg.SourceRegistry, cfg.SourceType)
}

func newCandidate(imageName string, cfg ImageConfig, source artifactSource, target *registryClient, tag string) SyncCandidate {
	candidate := SyncCandidate{
		ImageName:        imageName,
		SourceType:       cfg.SourceType,
		SourceRegistry:   cfg.SourceRegistry,
		TargetRegistry:   cfg.TargetRegistry,
		SourceRepository: cfg.SourceRepository,
		TargetRepository: cfg.TargetRepository,
		Tag:              tag,
		SourceRef:        source.Reference(cfg.SourceRepository, tag),
		Strategy:         cfg.PushStrategy,
	}
	candidate.TargetRef = target.Reference(cfg.TargetRepository, candidate.targetTag())
	return candidate
}

func (s *SyncRunner) syncTag(ctx context.Context, source artifactSource, target *registryClient, candidate SyncCandidate) (bool, error) {
	if candidate.Strategy == PushStrategyIfNotPresent {
		exists, err := target.TagExists(ctx, candidate.TargetRepository, candidate.targetTag())
		if err != nil {
			return false, fmt.Errorf("check target tag %s: %w", candidate.TargetRef, err)
		}
		if exists {
			s.logger.Info("skipping existing artifact", "image", candidate.ImageName, "targetRef", candidate.TargetRef)
			return false, nil
		}
	}

	for _, checker := range s.checkers {
		if err := checker.Check(ctx, candidate); err != nil {
			return false, fmt.Errorf("checker %s rejected %s: %w", checker.Name(), candidate.SourceRef, err)
		}
	}

	s.logger.Info(
		"copying artifact",
		"image", candidate.ImageName,
		"sourceRef", candidate.SourceRef,
		"targetRef", candidate.TargetRef,
	)
	if err := source.CopyTo(ctx, target, candidate); err != nil {
		return false, err
	}

	return true, nil
}
