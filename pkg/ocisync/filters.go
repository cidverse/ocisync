package ocisync

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

type tagFilter struct {
	regex              *regexp.Regexp
	constraint         *semver.Constraints
	includePrerelease  bool
	requiresSemverEval bool
}

func newTagFilter(cfg ImageConfig) (*tagFilter, error) {
	filter := &tagFilter{}

	if cfg.Regex != "" {
		re, err := regexp.Compile(cfg.Regex)
		if err != nil {
			return nil, fmt.Errorf("compile regex for %s: %w", cfg.SourceRepository, err)
		}
		filter.regex = re
	}

	if cfg.Semver != nil {
		filter.requiresSemverEval = true
		filter.includePrerelease = cfg.Semver.IncludePrerelease

		if cfg.Semver.Constraint != "" {
			constraint, err := semver.NewConstraint(cfg.Semver.Constraint)
			if err != nil {
				return nil, fmt.Errorf("parse semver constraint for %s: %w", cfg.SourceRepository, err)
			}
			filter.constraint = constraint
		}
	}

	return filter, nil
}

func (f *tagFilter) Match(tag string) bool {
	if f.regex != nil && !f.regex.MatchString(tag) {
		return false
	}

	if !f.requiresSemverEval {
		return true
	}

	version, ok := parseSemverTag(tag)
	if !ok {
		return false
	}
	if !f.includePrerelease && version.Prerelease() != "" {
		return false
	}
	if f.constraint != nil && !f.constraint.Check(version) {
		return false
	}

	return true
}

func filterTags(tags []string, filter *tagFilter) []string {
	if filter == nil {
		out := append([]string(nil), tags...)
		sort.Strings(out)
		return out
	}

	matched := make([]string, 0, len(tags))
	for _, tag := range tags {
		if filter.Match(tag) {
			matched = append(matched, tag)
		}
	}
	sort.Strings(matched)
	return matched
}

func parseSemverTag(tag string) (*semver.Version, bool) {
	version, err := semver.NewVersion(tag)
	if err == nil {
		return version, true
	}

	trimmed := strings.TrimPrefix(tag, "v")
	version, err = semver.NewVersion(trimmed)
	if err == nil {
		return version, true
	}

	return nil, false
}
