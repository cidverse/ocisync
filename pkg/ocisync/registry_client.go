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
	"os"
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
	}, nil
}

func newCredentialFunc(cfg RegistryConfig) (orasauth.CredentialFunc, error) {
	if cfg.Token != "" {
		return func(context.Context, string) (orasauth.Credential, error) {
			return orasauth.Credential{AccessToken: cfg.Token}, nil
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

func (r *registryClient) TagReference(repository, tag string) (string, error) {
	if strings.TrimSpace(tag) == "" {
		return "", fmt.Errorf("tag is required")
	}
	return fmt.Sprintf("%s:%s", r.referencePath(repository), tag), nil
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
		Client:     orasretry.DefaultClient,
		Cache:      orasauth.NewCache(),
		Credential: r.credential,
	}
	return repo, nil
}

func (r *registryClient) PushHelmChart(ctx context.Context, repository string, chartData []byte) (string, error) {
	meta, err := extractHelmChartMetadata(chartData)
	if err != nil {
		return "", err
	}

	tag := helmChartRegistryTag(meta.Version)
	targetRepo, err := r.ORASRepository(repository)
	if err != nil {
		return "", err
	}

	store := memory.New()
	chartDescriptor := content.NewDescriptorFromBytes(helmChartLayerMediaType, chartData)
	if err := store.Push(ctx, chartDescriptor, bytes.NewReader(chartData)); err != nil {
		return "", fmt.Errorf("push chart layer to memory store: %w", err)
	}

	configData, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("marshal chart metadata: %w", err)
	}
	configDescriptor := content.NewDescriptorFromBytes(helmConfigMediaType, configData)
	if err := store.Push(ctx, configDescriptor, bytes.NewReader(configData)); err != nil {
		return "", fmt.Errorf("push chart config to memory store: %w", err)
	}

	manifestDescriptor, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		Layers:              []ocispec.Descriptor{chartDescriptor},
		ConfigDescriptor:    &configDescriptor,
		ManifestAnnotations: generateHelmOCIAnnotations(meta),
	})
	if err != nil {
		return "", fmt.Errorf("pack helm chart manifest: %w", err)
	}
	if err := store.Tag(ctx, manifestDescriptor, tag); err != nil {
		return "", fmt.Errorf("tag helm chart manifest: %w", err)
	}

	if _, err := oras.Copy(ctx, store, tag, targetRepo, tag, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("push helm chart to registry: %w", err)
	}

	return tag, nil
}

func extractHelmChartMetadata(chartData []byte) (*helmChartMetadata, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(chartData))
	if err != nil {
		return nil, fmt.Errorf("open helm chart archive: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read helm chart archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(header.Name, "/Chart.yaml") {
			continue
		}

		chartYAML, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, fmt.Errorf("read Chart.yaml from archive: %w", err)
		}

		var meta helmChartMetadata
		if err := yaml.Unmarshal(chartYAML, &meta); err != nil {
			return nil, fmt.Errorf("parse Chart.yaml: %w", err)
		}
		if strings.TrimSpace(meta.Name) == "" || strings.TrimSpace(meta.Version) == "" {
			return nil, fmt.Errorf("chart metadata must contain name and version")
		}
		return &meta, nil
	}

	return nil, fmt.Errorf("Chart.yaml not found in helm chart archive")
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
