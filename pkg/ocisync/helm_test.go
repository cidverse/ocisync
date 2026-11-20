package ocisync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func buildChartArchive(t *testing.T, files map[string]string, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range order {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestIsTopLevelChartYAML(t *testing.T) {
	tests := map[string]bool{
		"mychart/Chart.yaml":                true,
		"./mychart/Chart.yaml":              true,
		"mychart/charts/sub/Chart.yaml":     false,
		"Chart.yaml":                        false,
		"mychart/values.yaml":               false,
		"mychart/templates/Chart.yaml.tmpl": false,
	}
	for name, want := range tests {
		if got := isTopLevelChartYAML(name); got != want {
			t.Errorf("isTopLevelChartYAML(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestExtractHelmChartMetadataIgnoresSubcharts(t *testing.T) {
	files := map[string]string{
		"mychart/charts/sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 0.1.0\n",
		"mychart/Chart.yaml": `apiVersion: v2
name: mychart
version: 1.2.3+build.4
appVersion: 1.10
kubeVersion: ">=1.25.0-0"
deprecated: false
type: application
annotations:
  example.com/revision: 42
dependencies:
  - name: sub
    version: 0.1.0
    import-values: [defaults]
`,
	}
	chart := buildChartArchive(t, files, []string{"mychart/charts/sub/Chart.yaml", "mychart/Chart.yaml"})

	meta, configData, err := extractHelmChartMetadata(chart)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "mychart" || meta.Version != "1.2.3+build.4" {
		t.Errorf("unexpected metadata: %+v", meta)
	}

	var config map[string]any
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"apiVersion", "appVersion", "type", "dependencies"} {
		if _, ok := config[key]; !ok {
			t.Errorf("config blob is missing %q: %s", key, configData)
		}
	}
	// helm decodes the config into string fields; unquoted numbers must stay strings with their original text
	if got := config["appVersion"]; got != "1.10" {
		t.Errorf("appVersion = %#v, want \"1.10\"", got)
	}
	if got := config["annotations"].(map[string]any)["example.com/revision"]; got != "42" {
		t.Errorf("annotation = %#v, want \"42\"", got)
	}
	if got := config["deprecated"]; got != false {
		t.Errorf("deprecated = %#v, want false", got)
	}

	if got := helmChartRegistryTag(meta.Version); got != "1.2.3_build.4" {
		t.Errorf("registry tag = %q", got)
	}
}

func TestHelmRepositoryAuthOnlySentToRepositoryOrigin(t *testing.T) {
	var foreignAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("chart"))
	}))
	defer foreign.Close()

	var repoAuth []string
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repoAuth = append(repoAuth, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/stable/index.yaml":
			_, _ = w.Write([]byte(`entries:
  local:
    - version: 1.0.0
      urls: [charts/local-1.0.0.tgz]
  remote:
    - version: 1.0.0
      urls: [` + foreign.URL + `/remote-1.0.0.tgz]
`))
		case "/stable/charts/local-1.0.0.tgz":
			_, _ = w.Write([]byte("chart"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer repo.Close()

	// no trailing slash: index.yaml must still be resolved below /stable/
	client, err := newHelmRepositoryClient("charts", RegistryConfig{Type: RegistryTypeHelmRepo, URL: repo.URL + "/stable", Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := client.DownloadChart(ctx, "local", "1.0.0"); err != nil {
		t.Fatalf("download local chart: %v", err)
	}
	if _, err := client.DownloadChart(ctx, "remote", "1.0.0"); err != nil {
		t.Fatalf("download remote chart: %v", err)
	}

	if len(repoAuth) != 2 {
		t.Fatalf("expected 2 requests to the repository, got %d", len(repoAuth))
	}
	for _, auth := range repoAuth {
		if auth != "Bearer secret" {
			t.Errorf("repository request auth = %q", auth)
		}
	}
	if foreignAuth != "" {
		t.Errorf("token leaked to foreign host: %q", foreignAuth)
	}
}

func TestHelmRepositoryListTagsSkipsRemoved(t *testing.T) {
	index, err := parseHelmIndex([]byte(`entries:
  app:
    - version: 1.0.0
    - version: 1.1.0
      removed: true
    - version: ""
`))
	if err != nil {
		t.Fatal(err)
	}
	client := &helmRepositoryClient{name: "charts", index: index}
	tags, err := client.ListTags(context.Background(), "app")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tags, ",") != "1.0.0" {
		t.Errorf("tags = %v", tags)
	}
}

func TestVerifyChartDigest(t *testing.T) {
	data := []byte("chart")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	for _, expected := range []string{"", digest, "sha256:" + digest, strings.ToUpper(digest)} {
		if err := verifyChartDigest(data, expected); err != nil {
			t.Errorf("verifyChartDigest(%q): %v", expected, err)
		}
	}
	if err := verifyChartDigest([]byte("tampered"), digest); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("expected digest mismatch, got %v", err)
	}
}

func TestHelmRepositoryDigestMismatchAndBasicAuth(t *testing.T) {
	sum := sha256.Sum256([]byte("chart"))
	goodDigest := hex.EncodeToString(sum[:])

	var user, pass string
	var basicOK bool
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, basicOK = r.BasicAuth()
		switch r.URL.Path {
		case "/index.yaml":
			_, _ = w.Write([]byte(`entries:
  good:
    - version: 1.0.0
      digest: ` + goodDigest + `
      urls: [good-1.0.0.tgz]
  bad:
    - version: 1.0.0
      digest: 0000000000000000000000000000000000000000000000000000000000000000
      urls: [bad-1.0.0.tgz]
`))
		default:
			_, _ = w.Write([]byte("chart"))
		}
	}))
	defer repo.Close()

	client, err := newHelmRepositoryClient("charts", RegistryConfig{Type: RegistryTypeHelmRepo, URL: repo.URL, Username: "user", Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := client.DownloadChart(ctx, "good", "1.0.0"); err != nil {
		t.Errorf("download good chart: %v", err)
	}
	if !basicOK || user != "user" || pass != "secret" {
		t.Errorf("expected basic auth user/secret, got ok=%v user=%q pass=%q", basicOK, user, pass)
	}
	if _, err := client.DownloadChart(ctx, "bad", "1.0.0"); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("expected digest mismatch, got %v", err)
	}
}
