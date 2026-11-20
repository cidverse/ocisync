package ocisync

import (
	"slices"
	"testing"
)

func TestFilterTags(t *testing.T) {
	tags := []string{"latest", "v1.0.0", "1.5.0", "v1.6.0-rc.1", "v2.0.0", "1.7.0+build.1"}

	tests := []struct {
		name string
		cfg  ImageConfig
		want []string
	}{
		{
			name: "no filter matches everything",
			cfg:  ImageConfig{},
			want: []string{"1.5.0", "1.7.0+build.1", "latest", "v1.0.0", "v1.6.0-rc.1", "v2.0.0"},
		},
		{
			name: "regex only",
			cfg:  ImageConfig{Regex: `^v`},
			want: []string{"v1.0.0", "v1.6.0-rc.1", "v2.0.0"},
		},
		{
			name: "empty semver block drops non-semver and prereleases",
			cfg:  ImageConfig{Semver: &SemverFilter{}},
			want: []string{"1.5.0", "1.7.0+build.1", "v1.0.0", "v2.0.0"},
		},
		{
			name: "semver constraint",
			cfg:  ImageConfig{Semver: &SemverFilter{Constraint: ">= 1.5.0, < 2.0.0"}},
			want: []string{"1.5.0", "1.7.0+build.1"},
		},
		{
			name: "semver constraint with prereleases",
			cfg:  ImageConfig{Semver: &SemverFilter{Constraint: ">= 1.5.0-0", IncludePrerelease: true}},
			want: []string{"1.5.0", "1.7.0+build.1", "v1.6.0-rc.1", "v2.0.0"},
		},
		{
			name: "regex and semver combined",
			cfg:  ImageConfig{Regex: `^v`, Semver: &SemverFilter{Constraint: "< 2.0.0"}},
			want: []string{"v1.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := newTagFilter(tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := filterTags(tags, filter); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTagFilterInvalid(t *testing.T) {
	if _, err := newTagFilter(ImageConfig{Regex: "("}); err == nil {
		t.Error("expected regex error")
	}
	if _, err := newTagFilter(ImageConfig{Semver: &SemverFilter{Constraint: "not a constraint"}}); err == nil {
		t.Error("expected semver constraint error")
	}
}
