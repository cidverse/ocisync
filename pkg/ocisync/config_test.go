package ocisync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestConfig(t *testing.T, content string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ocisync.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadTestConfig(t, `
registries:
  src:
    registry: ghcr.io
  dst:
    registry: registry.example.com
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
`)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PushStrategy != PushStrategyIfNotPresent {
		t.Errorf("global push-strategy = %q", cfg.PushStrategy)
	}
	if cfg.Registries["src"].Type != RegistryTypeOCI {
		t.Errorf("registry type = %q", cfg.Registries["src"].Type)
	}
	image := cfg.Images["app"]
	if image.SourceType != SourceTypeOCI || image.PushStrategy != PushStrategyIfNotPresent || image.TargetRepository != "org/app" {
		t.Errorf("unexpected image defaults: %+v", image)
	}
}

func TestLoadConfigNormalizesEnumCase(t *testing.T) {
	cfg, err := loadTestConfig(t, `
push-strategy: always
registries:
  charts:
    type: Helm-Repo
    url: https://charts.example.com
  dst:
    type: OCI
    registry: registry.example.com
images:
  chart:
    source-type: HELM-REPO
    source-registry: charts
    target-registry: dst
    source-repository: mychart
    push-strategy: ifnotpresent
`)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PushStrategy != PushStrategyAlways {
		t.Errorf("global push-strategy = %q", cfg.PushStrategy)
	}
	if cfg.Registries["charts"].Type != RegistryTypeHelmRepo || cfg.Registries["dst"].Type != RegistryTypeOCI {
		t.Errorf("registry types not normalized: %+v", cfg.Registries)
	}
	image := cfg.Images["chart"]
	if image.SourceType != SourceTypeHelmRepo || image.PushStrategy != PushStrategyIfNotPresent {
		t.Errorf("image enums not normalized: %+v", image)
	}

	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // don't pick up the user's containers auth.json
	runner, err := NewSyncer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runner.clients(image); err != nil {
		t.Errorf("clients: %v", err)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "invalid registry type",
			config: `
registries:
  src: {type: docker, registry: ghcr.io}
images:
  app: {source-registry: src, target-registry: src, source-repository: org/app}
`,
			wantErr: "registries.src.type must be one of",
		},
		{
			name: "missing target registry",
			config: `
registries:
  src: {registry: ghcr.io}
images:
  app: {source-registry: src, source-repository: org/app}
`,
			wantErr: "images.app.target-registry is required",
		},
		{
			name: "helm repo as target",
			config: `
registries:
  src: {registry: ghcr.io}
  charts: {type: helm-repo, url: https://charts.example.com}
images:
  app: {source-registry: src, target-registry: charts, source-repository: org/app}
`,
			wantErr: "must reference an oci registry",
		},
		{
			name: "multiple credential sources",
			config: `
registries:
  src: {registry: ghcr.io, token: abc, token-env: TOKEN}
images:
  app: {source-registry: src, target-registry: src, source-repository: org/app}
`,
			wantErr: "must use only one of token, token-env, or token-command",
		},
		{
			name: "username without token",
			config: `
registries:
  src: {registry: ghcr.io, username: me}
images:
  app: {source-registry: src, target-registry: src, source-repository: org/app}
`,
			wantErr: "registries.src.username requires one of token",
		},
		{
			name: "invalid push strategy",
			config: `
registries:
  src: {registry: ghcr.io}
images:
  app: {source-registry: src, target-registry: src, source-repository: org/app, push-strategy: sometimes}
`,
			wantErr: "images.app.push-strategy must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadTestConfig(t, tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigTokenEnv(t *testing.T) {
	t.Setenv("OCISYNC_TEST_TOKEN", "  secret\n")
	cfg, err := loadTestConfig(t, `
registries:
  src: {registry: ghcr.io, token-env: OCISYNC_TEST_TOKEN}
images:
  app: {source-registry: src, target-registry: src, source-repository: org/app}
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Registries["src"].Token; got != "secret" {
		t.Errorf("token = %q", got)
	}
}
