package ocisync

import (
	"encoding/pem"
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

func writeTestCertificate(t *testing.T, dir, name string) {
	t.Helper()
	cert := newTestCACert(t, "Corp Root CA")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

const patchTestRegistries = `
registries:
  src:
    registry: ghcr.io
  dst:
    registry: registry.example.com
  charts:
    type: helm-repo
    url: https://charts.example.com
`

func TestLoadConfigPatches(t *testing.T) {
	dir := t.TempDir()
	writeTestCertificate(t, dir, "corp.pem")
	path := filepath.Join(dir, "ocisync.yaml")
	if err := os.WriteFile(path, []byte(patchTestRegistries+`
patches:
  corp-ca:
    ca-certificates:
      files: [corp.pem]
      on-missing-bundle: Create
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
    patches: [corp-ca]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ca := cfg.Patches["corp-ca"].CACertificates
	if ca.OnMissingBundle != MissingBundleCreate {
		t.Errorf("on-missing-bundle = %q", ca.OnMissingBundle)
	}
	if len(ca.certificates) != 1 || ca.certificates[0].Subject.CommonName != "Corp Root CA" {
		t.Errorf("certificates = %v", ca.certificates)
	}
}

func TestLoadConfigPatchErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "undefined patch",
			config: `
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
    patches: [missing]
`,
			wantErr: `images.app.patches[0] "missing" is not defined`,
		},
		{
			name: "helm source",
			config: `
patches:
  corp-ca:
    ca-certificates:
      files: [corp.pem]
images:
  chart:
    source-type: helm-repo
    source-registry: charts
    target-registry: dst
    source-repository: chart
    patches: [corp-ca]
`,
			wantErr: "images.chart.patches can only be used with source-type",
		},
		{
			name: "no files",
			config: `
patches:
  corp-ca:
    ca-certificates: {}
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
`,
			wantErr: "patches.corp-ca.ca-certificates.files must contain at least one file",
		},
		{
			name: "invalid on-missing-bundle",
			config: `
patches:
  corp-ca:
    ca-certificates:
      files: [corp.pem]
      on-missing-bundle: ignore
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
`,
			wantErr: "patches.corp-ca.ca-certificates.on-missing-bundle must be one of",
		},
		{
			name: "invalid java mode",
			config: `
patches:
  corp-ca:
    ca-certificates:
      files: [corp.pem]
      java: keystore
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
`,
			wantErr: "patches.corp-ca.ca-certificates.java must be one of",
		},
		{
			name: "missing file",
			config: `
patches:
  corp-ca:
    ca-certificates:
      files: [does-not-exist.pem]
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
`,
			wantErr: "patches.corp-ca.ca-certificates.files[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCertificate(t, dir, "corp.pem")
			path := filepath.Join(dir, "ocisync.yaml")
			if err := os.WriteFile(path, []byte(patchTestRegistries+tt.config), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigSystemBase(t *testing.T) {
	dir := t.TempDir()
	writeTestCertificate(t, dir, "corp.pem")
	writeTestCertificate(t, dir, "system.pem")
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "system.pem"))
	path := filepath.Join(dir, "ocisync.yaml")
	if err := os.WriteFile(path, []byte(patchTestRegistries+`
patches:
  corp-ca:
    ca-certificates:
      files: [corp.pem]
      base: System
images:
  app:
    source-registry: src
    target-registry: dst
    source-repository: org/app
    patches: [corp-ca]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ca := cfg.Patches["corp-ca"].CACertificates
	system, _ := os.ReadFile(filepath.Join(dir, "system.pem"))
	if ca.Base != CABundleBaseSystem || string(ca.systemBundle) != string(system) {
		t.Errorf("base = %q, system bundle loaded = %v", ca.Base, len(ca.systemBundle) > 0)
	}
}
