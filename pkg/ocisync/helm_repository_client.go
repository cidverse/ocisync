package ocisync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type helmRepositoryClient struct {
	name     string
	baseURL  *url.URL
	username string
	token    string
	client   *http.Client
	index    *helmRepositoryIndex
}

type helmRepositoryIndex struct {
	Entries map[string][]helmRepositoryEntry `yaml:"entries"`
}

type helmRepositoryEntry struct {
	Version string   `yaml:"version"`
	URLs    []string `yaml:"urls"`
	Digest  string   `yaml:"digest"`
	Removed bool     `yaml:"removed"`
}

func newHelmRepositoryClients(configs map[string]RegistryConfig) (map[string]*helmRepositoryClient, error) {
	clients := make(map[string]*helmRepositoryClient, len(configs))
	for name, cfg := range configs {
		if cfg.Type != RegistryTypeHelmRepo {
			continue
		}
		client, err := newHelmRepositoryClient(name, cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		clients[name] = client
	}
	return clients, nil
}

func newHelmRepositoryClient(name string, cfg RegistryConfig) (*helmRepositoryClient, error) {
	baseURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse helm repository url %q: %w", cfg.URL, err)
	}
	// relative references (index.yaml, chart urls) must resolve below the repository path, not next to it
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
		if baseURL.RawPath != "" {
			baseURL.RawPath += "/"
		}
	}

	// http vs. https is determined by the repository url, so insecure only disables certificate verification here
	return &helmRepositoryClient{
		name:     name,
		baseURL:  baseURL,
		username: cfg.Username,
		token:    cfg.Token,
		client: &http.Client{
			Transport: newHTTPTransport(cfg.Insecure),
			Timeout:   helmRequestTimeout,
		},
	}, nil
}

func (r *helmRepositoryClient) ListTags(ctx context.Context, chartName string) ([]string, error) {
	index, err := r.loadIndex(ctx)
	if err != nil {
		return nil, err
	}

	entries, ok := index.Entries[chartName]
	if !ok {
		return nil, fmt.Errorf("chart %q not found in helm repository %q", chartName, r.name)
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Version) == "" || entry.Removed {
			continue
		}
		versions = append(versions, entry.Version)
	}
	sort.Strings(versions)
	return versions, nil
}

func (r *helmRepositoryClient) DownloadChart(ctx context.Context, chartName, version string) ([]byte, error) {
	index, err := r.loadIndex(ctx)
	if err != nil {
		return nil, err
	}

	entry, err := index.find(chartName, version)
	if err != nil {
		return nil, err
	}
	if len(entry.URLs) == 0 {
		return nil, fmt.Errorf("chart %s version %s has no download urls", chartName, version)
	}

	chartURL, err := r.resolveChartURL(entry.URLs[0])
	if err != nil {
		return nil, err
	}
	chartData, err := r.fetch(ctx, chartURL.String())
	if err != nil {
		return nil, err
	}
	if err := verifyChartDigest(chartData, entry.Digest); err != nil {
		return nil, fmt.Errorf("chart %s version %s from %s: %w", chartName, version, chartURL.String(), err)
	}
	return chartData, nil
}

// verifyChartDigest checks the chart archive against the sha256 digest from index.yaml. Old indexes may lack the
// digest, in which case there is nothing to verify against.
func verifyChartDigest(chartData []byte, expected string) error {
	expected = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(expected), "sha256:"))
	if expected == "" {
		return nil
	}
	sum := sha256.Sum256(chartData)
	if actual := hex.EncodeToString(sum[:]); actual != expected {
		return fmt.Errorf("digest mismatch: index.yaml has sha256:%s, downloaded archive has sha256:%s", expected, actual)
	}
	return nil
}

func (r *helmRepositoryClient) loadIndex(ctx context.Context) (*helmRepositoryIndex, error) {
	if r.index != nil {
		return r.index, nil
	}

	indexURL := r.baseURL.ResolveReference(&url.URL{Path: "index.yaml"})
	indexData, err := r.fetch(ctx, indexURL.String())
	if err != nil {
		return nil, fmt.Errorf("download index from %s: %w", indexURL.String(), err)
	}

	indexFile, err := parseHelmIndex(indexData)
	if err != nil {
		return nil, err
	}
	r.index = indexFile
	return indexFile, nil
}

func parseHelmIndex(data []byte) (*helmRepositoryIndex, error) {
	var indexFile helmRepositoryIndex
	if err := yaml.Unmarshal(data, &indexFile); err != nil {
		return nil, fmt.Errorf("parse helm index file: %w", err)
	}
	if len(indexFile.Entries) == 0 {
		return nil, fmt.Errorf("helm index file contains no chart entries")
	}
	return &indexFile, nil
}

func (i *helmRepositoryIndex) find(chartName, version string) (*helmRepositoryEntry, error) {
	entries, ok := i.Entries[chartName]
	if !ok {
		return nil, fmt.Errorf("chart %q not found in index", chartName)
	}
	for idx := range entries {
		entry := &entries[idx]
		if entry.Removed {
			continue
		}
		if entry.Version == version {
			return entry, nil
		}
	}
	return nil, fmt.Errorf("chart %s version %s not found in index", chartName, version)
}

func (r *helmRepositoryClient) resolveChartURL(rawURL string) (*url.URL, error) {
	chartURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse chart url %q: %w", rawURL, err)
	}
	return r.baseURL.ResolveReference(chartURL), nil
}

func (r *helmRepositoryClient) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// only send credentials to the repository itself, never to chart urls hosted elsewhere (e.g. release assets)
	if r.token != "" && sameOrigin(req.URL, r.baseURL) {
		if r.username != "" {
			req.SetBasicAuth(r.username, r.token)
		} else {
			req.Header.Set("Authorization", "Bearer "+r.token)
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Reference returns a human-readable reference for a chart version, used for logging.
func (r *helmRepositoryClient) Reference(chartName, version string) string {
	return fmt.Sprintf("%s/%s:%s", r.name, chartName, version)
}

// CopyTo downloads the chart version from the helm repository and pushes it as an OCI artifact to the target registry.
func (r *helmRepositoryClient) CopyTo(ctx context.Context, target *registryClient, candidate SyncCandidate) error {
	chartData, err := r.DownloadChart(ctx, candidate.SourceRepository, candidate.Tag)
	if err != nil {
		return fmt.Errorf("download chart %s version %s: %w", candidate.SourceRepository, candidate.Tag, err)
	}
	if err := target.PushHelmChart(ctx, candidate.TargetRepository, candidate.targetTag(), chartData); err != nil {
		return fmt.Errorf("push helm chart %s -> %s: %w", candidate.SourceRef, candidate.TargetRef, err)
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
