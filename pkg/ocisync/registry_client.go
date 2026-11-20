package ocisync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/errdef"
	orasremote "oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	orascredentials "oras.land/oras-go/v2/registry/remote/credentials"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"
)

const (
	helmConfigMediaType     = "application/vnd.cncf.helm.config.v1+json"
	helmChartLayerMediaType = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
)

type helmChartMetadata struct {
	Name        string                `yaml:"name" json:"name"`
	Version     string                `yaml:"version" json:"version"`
	Description string                `yaml:"description,omitempty" json:"description,omitempty"`
	Home        string                `yaml:"home,omitempty" json:"home,omitempty"`
	Sources     []string              `yaml:"sources,omitempty" json:"sources,omitempty"`
	Maintainers []helmChartMaintainer `yaml:"maintainers,omitempty" json:"maintainers,omitempty"`
	Annotations map[string]string     `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

type helmChartMaintainer struct {
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
}

type registryClient struct {
	registry   string
	insecure   bool
	credential orasauth.CredentialFunc
	httpClient *http.Client
	authCache  orasauth.Cache
}

func newRegistryClients(configs map[string]RegistryConfig) (map[string]*registryClient, error) {
	clients := make(map[string]*registryClient, len(configs))
	for name, cfg := range configs {
		if cfg.Type != RegistryTypeOCI {
			continue
		}
		client, err := newRegistryClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		clients[name] = client
	}
	return clients, nil
}

func newRegistryClient(cfg RegistryConfig) (*registryClient, error) {
	registry := strings.TrimSuffix(strings.TrimSpace(cfg.Registry), "/")
	if registry == "" {
		return nil, fmt.Errorf("registry is required")
	}

	credentialFunc, err := newCredentialFunc(cfg)
	if err != nil {
		return nil, err
	}

	return &registryClient{
		registry:   registry,
		insecure:   cfg.Insecure,
		credential: credentialFunc,
		// retries transient failures (429, 5xx, network errors) on top of a transport with timeouts
		httpClient: &http.Client{Transport: orasretry.NewTransport(newHTTPTransport(false))},
		// shared across all repositories of this registry, so tokens are reused instead of re-authenticating per call
		authCache: orasauth.NewCache(),
	}, nil
}

func newCredentialFunc(cfg RegistryConfig) (orasauth.CredentialFunc, error) {
	if cfg.Token != "" {
		// with a username the token is used as password (basic auth / token exchange, e.g. docker hub, harbor, ghcr
		// personal access tokens), without one it is sent as-is as bearer token to the registry.
		credential := orasauth.Credential{AccessToken: cfg.Token}
		if cfg.Username != "" {
			credential = orasauth.Credential{Username: cfg.Username, Password: cfg.Token}
		}
		return func(context.Context, string) (orasauth.Credential, error) {
			return credential, nil
		}, nil
	}

	containersCredential, err := newContainersAuthCredentialFunc()
	if err != nil {
		return nil, err
	}
	if containersCredential != nil {
		return containersCredential, nil
	}

	return func(context.Context, string) (orasauth.Credential, error) {
		return orasauth.EmptyCredential, nil
	}, nil
}

func newContainersAuthCredentialFunc() (orasauth.CredentialFunc, error) {
	configPath, ok := defaultContainersAuthFilePath()
	if !ok {
		return nil, nil
	}
	if _, err := os.Stat(configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat containers auth file %s: %w", configPath, err)
	}

	store, err := orascredentials.NewStore(configPath, orascredentials.StoreOptions{})
	if err != nil {
		return nil, fmt.Errorf("load containers auth file %s: %w", configPath, err)
	}
	return orascredentials.Credential(store), nil
}

func defaultContainersAuthFilePath() (string, bool) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome != "" {
		return filepath.Join(configHome, "containers", "auth.json"), true
	}

	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return "", false
	}
	return filepath.Join(homeDir, ".config", "containers", "auth.json"), true
}

func (r *registryClient) ListTags(ctx context.Context, repository string) ([]string, error) {
	repo, err := r.ORASRepository(repository)
	if err != nil {
		return nil, err
	}

	var tags []string
	if err := repo.Tags(ctx, "", func(batch []string) error {
		tags = append(tags, batch...)
		return nil
	}); err != nil {
		return nil, err
	}
	slices.Sort(tags)
	return tags, nil
}

func (r *registryClient) TagExists(ctx context.Context, repository, tag string) (bool, error) {
	repo, err := r.ORASRepository(repository)
	if err != nil {
		return false, err
	}

	_, err = repo.Resolve(ctx, tag)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errdef.ErrNotFound) {
		return false, nil
	}

	return false, err
}

// Reference returns the full reference (registry/repository:tag) of a tag.
func (r *registryClient) Reference(repository, tag string) string {
	return fmt.Sprintf("%s:%s", r.referencePath(repository), tag)
}

// CopyTo copies the candidate's tag, including all referenced manifests and blobs, to the target registry.
func (r *registryClient) CopyTo(ctx context.Context, target *registryClient, candidate SyncCandidate) error {
	sourceRepo, err := r.ORASRepository(candidate.SourceRepository)
	if err != nil {
		return fmt.Errorf("build source repository for %s: %w", candidate.SourceRef, err)
	}
	targetRepo, err := target.ORASRepository(candidate.TargetRepository)
	if err != nil {
		return fmt.Errorf("build target repository for %s: %w", candidate.TargetRef, err)
	}
	if candidate.patches != nil {
		if err := copyPatchedImage(ctx, sourceRepo, candidate.Tag, targetRepo, candidate.targetTag(), candidate.patches, candidate.SourceRef); err != nil {
			return fmt.Errorf("copy patched image %s -> %s: %w", candidate.SourceRef, candidate.TargetRef, err)
		}
		return nil
	}
	if _, err := oras.Copy(ctx, sourceRepo, candidate.Tag, targetRepo, candidate.targetTag(), oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", candidate.SourceRef, candidate.TargetRef, err)
	}
	return nil
}

// PatchFingerprint returns the patch fingerprint of repository:tag, or "" if the image was not patched by ocisync.
func (r *registryClient) PatchFingerprint(ctx context.Context, repository, tag string) (string, error) {
	repo, err := r.ORASRepository(repository)
	if err != nil {
		return "", err
	}
	return patchFingerprintOf(ctx, repo, tag)
}

func (r *registryClient) ORASRepository(repository string) (*orasremote.Repository, error) {
	if strings.TrimSpace(repository) == "" {
		return nil, fmt.Errorf("repository is required")
	}
	repo, err := orasremote.NewRepository(r.referencePath(repository))
	if err != nil {
		return nil, err
	}
	repo.PlainHTTP = r.insecure
	repo.Client = &orasauth.Client{
		Client:     r.httpClient,
		Cache:      r.authCache,
		Credential: r.credential,
	}
	return repo, nil
}

// PushHelmChart packages a chart archive as a Helm OCI artifact and pushes it to repository:tag.
func (r *registryClient) PushHelmChart(ctx context.Context, repository, tag string, chartData []byte) error {
	meta, configData, err := extractHelmChartMetadata(chartData)
	if err != nil {
		return err
	}
	if expected := helmChartRegistryTag(meta.Version); expected != tag {
		return fmt.Errorf("chart archive has version %q, which does not match tag %q from the repository index", meta.Version, tag)
	}

	targetRepo, err := r.ORASRepository(repository)
	if err != nil {
		return err
	}

	store := memory.New()
	chartDescriptor := content.NewDescriptorFromBytes(helmChartLayerMediaType, chartData)
	if err := store.Push(ctx, chartDescriptor, bytes.NewReader(chartData)); err != nil {
		return fmt.Errorf("push chart layer to memory store: %w", err)
	}

	configDescriptor := content.NewDescriptorFromBytes(helmConfigMediaType, configData)
	if err := store.Push(ctx, configDescriptor, bytes.NewReader(configData)); err != nil {
		return fmt.Errorf("push chart config to memory store: %w", err)
	}

	manifestDescriptor, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		Layers:              []ocispec.Descriptor{chartDescriptor},
		ConfigDescriptor:    &configDescriptor,
		ManifestAnnotations: generateHelmOCIAnnotations(meta),
	})
	if err != nil {
		return fmt.Errorf("pack helm chart manifest: %w", err)
	}
	if err := store.Tag(ctx, manifestDescriptor, tag); err != nil {
		return fmt.Errorf("tag helm chart manifest: %w", err)
	}

	if _, err := oras.Copy(ctx, store, tag, targetRepo, tag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("push helm chart to registry: %w", err)
	}

	return nil
}

// extractHelmChartMetadata reads the top-level Chart.yaml from a chart archive. It returns the parsed metadata (used for
// annotations) and the complete Chart.yaml as JSON, which is used as the OCI config blob, as done by helm push.
func extractHelmChartMetadata(chartData []byte) (*helmChartMetadata, []byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(chartData))
	if err != nil {
		return nil, nil, fmt.Errorf("open helm chart archive: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read helm chart archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || !isTopLevelChartYAML(header.Name) {
			continue
		}

		chartYAML, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, nil, fmt.Errorf("read Chart.yaml from archive: %w", err)
		}

		var meta helmChartMetadata
		if err := yaml.Unmarshal(chartYAML, &meta); err != nil {
			return nil, nil, fmt.Errorf("parse Chart.yaml: %w", err)
		}
		if strings.TrimSpace(meta.Name) == "" || strings.TrimSpace(meta.Version) == "" {
			return nil, nil, fmt.Errorf("chart metadata must contain name and version")
		}

		var root yaml.Node
		if err := yaml.Unmarshal(chartYAML, &root); err != nil {
			return nil, nil, fmt.Errorf("parse Chart.yaml: %w", err)
		}
		raw, err := yamlNodeToJSONValue(&root)
		if err != nil {
			return nil, nil, fmt.Errorf("parse Chart.yaml: %w", err)
		}
		configData, err := json.Marshal(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal chart metadata: %w", err)
		}

		return &meta, configData, nil
	}

	return nil, nil, fmt.Errorf("Chart.yaml not found in helm chart archive")
}

// yamlNodeToJSONValue converts a yaml node into a value for json encoding. Numeric scalars are kept as strings with their
// original text: helm decodes the config blob into chart.Metadata, which has no numeric fields, and unquoted values such
// as "appVersion: 1.10" must neither become a json number (breaks helm pull) nor lose their formatting (1.10 -> 1.1).
func yamlNodeToJSONValue(node *yaml.Node) (any, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return yamlNodeToJSONValue(node.Content[0])
	case yaml.AliasNode:
		return yamlNodeToJSONValue(node.Alias)
	case yaml.MappingNode:
		out := make(map[string]any, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			value, err := yamlNodeToJSONValue(node.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[node.Content[i].Value] = value
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, item := range node.Content {
			value, err := yamlNodeToJSONValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool":
			var b bool
			if err := node.Decode(&b); err != nil {
				return nil, err
			}
			return b, nil
		default:
			return node.Value, nil
		}
	default:
		return nil, fmt.Errorf("unsupported yaml node kind %d", node.Kind)
	}
}

// isTopLevelChartYAML reports whether a tar entry is <chart>/Chart.yaml, excluding subcharts (<chart>/charts/<sub>/Chart.yaml).
func isTopLevelChartYAML(name string) bool {
	dir, file := path.Split(strings.TrimPrefix(name, "./"))
	return file == "Chart.yaml" && dir != "" && strings.Count(dir, "/") == 1
}

func helmChartRegistryTag(version string) string {
	return strings.ReplaceAll(version, "+", "_")
}

func generateHelmOCIAnnotations(meta *helmChartMetadata) map[string]string {
	annotations := map[string]string{
		ocispec.AnnotationCreated: time.Now().UTC().Format(time.RFC3339),
	}
	addOCIAnnotation(annotations, ocispec.AnnotationDescription, meta.Description)
	addOCIAnnotation(annotations, ocispec.AnnotationTitle, meta.Name)
	addOCIAnnotation(annotations, ocispec.AnnotationVersion, meta.Version)
	addOCIAnnotation(annotations, ocispec.AnnotationURL, meta.Home)
	if len(meta.Sources) > 0 {
		addOCIAnnotation(annotations, ocispec.AnnotationSource, meta.Sources[0])
	}
	if len(meta.Maintainers) > 0 {
		maintainers := make([]string, 0, len(meta.Maintainers))
		for _, maintainer := range meta.Maintainers {
			part := strings.TrimSpace(maintainer.Name)
			if maintainer.Email != "" {
				if part == "" {
					part = maintainer.Email
				} else {
					part = fmt.Sprintf("%s (%s)", part, maintainer.Email)
				}
			}
			if part != "" {
				maintainers = append(maintainers, part)
			}
		}
		addOCIAnnotation(annotations, ocispec.AnnotationAuthors, strings.Join(maintainers, ", "))
	}
	for key, value := range meta.Annotations {
		if _, exists := annotations[key]; exists {
			continue
		}
		addOCIAnnotation(annotations, key, value)
	}
	return annotations
}

func addOCIAnnotation(annotations map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		annotations[key] = value
	}
}

func (r *registryClient) referencePath(repository string) string {
	return fmt.Sprintf("%s/%s", r.registry, strings.TrimPrefix(repository, "/"))
}
