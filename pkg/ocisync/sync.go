package ocisync

import (
	"context"
	"fmt"
	"log/slog"

	oras "oras.land/oras-go/v2"
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

func (s *SyncRunner) Run(ctx context.Context) (*SyncStats, error) {
	stats := &SyncStats{}

	for _, imageName := range sortedImageNames(s.config.Images) {
		if err := s.syncRepository(ctx, imageName, s.config.Images[imageName], stats); err != nil {
			return stats, err
		}
	}

	return stats, nil
}

func (s *SyncRunner) syncRepository(ctx context.Context, imageName string, cfg ImageConfig, stats *SyncStats) error {
	switch normalizeSourceType(cfg.SourceType) {
	case SourceTypeHelmRepo:
		return s.syncHelmRepository(ctx, imageName, cfg, stats)
	default:
		return s.syncOCIRepository(ctx, imageName, cfg, stats)
	}
}

func (s *SyncRunner) syncOCIRepository(ctx context.Context, imageName string, cfg ImageConfig, stats *SyncStats) error {
	filter, err := newTagFilter(cfg)
	if err != nil {
		return err
	}

	source := s.registries[cfg.SourceRegistry]
	target := s.registries[cfg.TargetRegistry]

	tags, err := source.ListTags(ctx, cfg.SourceRepository)
	if err != nil {
		return fmt.Errorf("list source tags for %s from %s: %w", cfg.SourceRepository, cfg.SourceRegistry, err)
	}

	stats.Scanned += len(tags)
	matchedTags := filterTags(tags, filter)
	stats.Matched += len(matchedTags)

	s.logger.Info(
		"repository scan completed",
		"image", imageName,
		"sourceType", normalizeSourceType(cfg.SourceType),
		"sourceRegistry", cfg.SourceRegistry,
		"targetRegistry", cfg.TargetRegistry,
		"sourceRepository", cfg.SourceRepository,
		"targetRepository", cfg.TargetRepository,
		"scanned", len(tags),
		"matched", len(matchedTags),
		"strategy", normalizePushStrategy(cfg.PushStrategy),
	)

	for _, tag := range matchedTags {
		candidate, err := s.newOCICandidate(imageName, cfg, tag)
		if err != nil {
			stats.Failed++
			return err
		}

		copied, err := s.syncTag(ctx, source, target, candidate)
		if err != nil {
			stats.Failed++
			return err
		}
		if copied {
			stats.Copied++
		} else {
			stats.Skipped++
		}
	}

	return nil
}

func (s *SyncRunner) syncHelmRepository(ctx context.Context, imageName string, cfg ImageConfig, stats *SyncStats) error {
	filter, err := newTagFilter(cfg)
	if err != nil {
		return err
	}

	source := s.helmRepositories[cfg.SourceRegistry]
	target := s.registries[cfg.TargetRegistry]

	versions, err := source.ListTags(ctx, cfg.SourceRepository)
	if err != nil {
		return fmt.Errorf("list helm chart versions for %s from %s: %w", cfg.SourceRepository, cfg.SourceRegistry, err)
	}

	stats.Scanned += len(versions)
	matchedVersions := filterTags(versions, filter)
	stats.Matched += len(matchedVersions)

	s.logger.Info(
		"repository scan completed",
		"image", imageName,
		"sourceType", normalizeSourceType(cfg.SourceType),
		"sourceRegistry", cfg.SourceRegistry,
		"targetRegistry", cfg.TargetRegistry,
		"sourceRepository", cfg.SourceRepository,
		"targetRepository", cfg.TargetRepository,
		"scanned", len(versions),
		"matched", len(matchedVersions),
		"strategy", normalizePushStrategy(cfg.PushStrategy),
	)

	for _, version := range matchedVersions {
		candidate, err := s.newHelmCandidate(imageName, cfg, version)
		if err != nil {
			stats.Failed++
			return err
		}

		copied, err := s.syncHelmTag(ctx, source, target, candidate)
		if err != nil {
			stats.Failed++
			return err
		}
		if copied {
			stats.Copied++
		} else {
			stats.Skipped++
		}
	}

	return nil
}

func (s *SyncRunner) newOCICandidate(imageName string, cfg ImageConfig, tag string) (SyncCandidate, error) {
	source := s.registries[cfg.SourceRegistry]
	target := s.registries[cfg.TargetRegistry]

	sourceRef, err := source.TagReference(cfg.SourceRepository, tag)
	if err != nil {
		return SyncCandidate{}, fmt.Errorf("build source ref for %s:%s: %w", cfg.SourceRepository, tag, err)
	}
	targetRef, err := target.TagReference(cfg.TargetRepository, tag)
	if err != nil {
		return SyncCandidate{}, fmt.Errorf("build target ref for %s:%s: %w", cfg.TargetRepository, tag, err)
	}

	return SyncCandidate{
		ImageName:        imageName,
		SourceType:       SourceTypeOCI,
		SourceRegistry:   cfg.SourceRegistry,
		TargetRegistry:   cfg.TargetRegistry,
		SourceRepository: cfg.SourceRepository,
		TargetRepository: cfg.TargetRepository,
		Tag:              tag,
		SourceRef:        sourceRef,
		TargetRef:        targetRef,
		Strategy:         normalizePushStrategy(cfg.PushStrategy),
	}, nil
}

func (s *SyncRunner) newHelmCandidate(imageName string, cfg ImageConfig, version string) (SyncCandidate, error) {
	target := s.registries[cfg.TargetRegistry]
	targetTag := helmChartRegistryTag(version)
	targetRef, err := target.TagReference(cfg.TargetRepository, targetTag)
	if err != nil {
		return SyncCandidate{}, fmt.Errorf("build target ref for %s:%s: %w", cfg.TargetRepository, targetTag, err)
	}

	return SyncCandidate{
		ImageName:        imageName,
		SourceType:       SourceTypeHelmRepo,
		SourceRegistry:   cfg.SourceRegistry,
		TargetRegistry:   cfg.TargetRegistry,
		SourceRepository: cfg.SourceRepository,
		TargetRepository: cfg.TargetRepository,
		Tag:              version,
		SourceRef:        fmt.Sprintf("%s/%s:%s", cfg.SourceRegistry, cfg.SourceRepository, version),
		TargetRef:        targetRef,
		Strategy:         normalizePushStrategy(cfg.PushStrategy),
	}, nil
}

func (s *SyncRunner) syncTag(ctx context.Context, source, target *registryClient, candidate SyncCandidate) (bool, error) {
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
	if err := s.copyReference(ctx, source, target, candidate); err != nil {
		return false, err
	}

	return true, nil
}

func (s *SyncRunner) syncHelmTag(ctx context.Context, source *helmRepositoryClient, target *registryClient, candidate SyncCandidate) (bool, error) {
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

	chartData, err := source.DownloadChart(ctx, candidate.SourceRepository, candidate.Tag)
	if err != nil {
		return false, fmt.Errorf("download chart %s version %s: %w", candidate.SourceRepository, candidate.Tag, err)
	}

	s.logger.Info(
		"copying artifact",
		"image", candidate.ImageName,
		"sourceRef", candidate.SourceRef,
		"targetRef", candidate.TargetRef,
	)
	if _, err := target.PushHelmChart(ctx, candidate.TargetRepository, chartData); err != nil {
		return false, fmt.Errorf("push helm chart %s -> %s: %w", candidate.SourceRef, candidate.TargetRef, err)
	}

	return true, nil
}

func (s *SyncRunner) copyReference(ctx context.Context, source, target *registryClient, candidate SyncCandidate) error {
	sourceRepo, err := source.ORASRepository(candidate.SourceRepository)
	if err != nil {
		return fmt.Errorf("build source repository for %s: %w", candidate.SourceRef, err)
	}
	targetRepo, err := target.ORASRepository(candidate.TargetRepository)
	if err != nil {
		return fmt.Errorf("build target repository for %s: %w", candidate.TargetRef, err)
	}

	if _, err := oras.Copy(ctx, sourceRepo, candidate.Tag, targetRepo, candidate.targetTag(), oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", candidate.SourceRef, candidate.TargetRef, err)
	}

	return nil
}
