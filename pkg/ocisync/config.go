package ocisync

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Registries   map[string]RegistryConfig `yaml:"registries"`
	Images       map[string]ImageConfig    `yaml:"images"`
	PushStrategy PushStrategy              `yaml:"push-strategy"`
}

type RegistryType string

type RegistryConfig struct {
	Type         RegistryType `yaml:"type"`
	Registry     string       `yaml:"registry"`
	URL          string       `yaml:"url"`
	Token        string       `yaml:"token"`
	TokenEnv     string       `yaml:"token-env"`
	TokenCommand string       `yaml:"token-command"`
	Insecure     bool         `yaml:"insecure"`
}

type SourceType string

type ImageConfig struct {
	SourceType       SourceType    `yaml:"source-type"`
	SourceRegistry   string        `yaml:"source-registry"`
	TargetRegistry   string        `yaml:"target-registry"`
	SourceRepository string        `yaml:"source-repository"`
	TargetRepository string        `yaml:"target-repository"`
	Regex            string        `yaml:"regex"`
	Semver           *SemverFilter `yaml:"semver"`
	PushStrategy     PushStrategy  `yaml:"push-strategy"`
}

type SemverFilter struct {
	Constraint        string `yaml:"constraint"`
	IncludePrerelease bool   `yaml:"include-prerelease"`
}

type PushStrategy string

const (
	RegistryTypeOCI      RegistryType = "oci"
	RegistryTypeHelmRepo RegistryType = "helm-repo"

	SourceTypeOCI      SourceType = "oci"
	SourceTypeHelmRepo SourceType = "helm-repo"

	PushStrategyIfNotPresent PushStrategy = "IfNotPresent"
	PushStrategyAlways       PushStrategy = "Always"
)

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	applyDefaults(&cfg)
	if err = resolveSecrets(&cfg); err != nil {
		return nil, err
	}
	if err = validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.PushStrategy == "" {
		cfg.PushStrategy = PushStrategyIfNotPresent
	}

	for name, registry := range cfg.Registries {
		if registry.Type == "" {
			registry.Type = RegistryTypeOCI
		}
		cfg.Registries[name] = registry
	}

	for name, image := range cfg.Images {
		if image.SourceType == "" {
			image.SourceType = SourceTypeOCI
		}
		if image.PushStrategy == "" {
			image.PushStrategy = cfg.PushStrategy
		}
		if image.SourceRepository == "" {
			image.SourceRepository = image.TargetRepository
		}
		if image.TargetRepository == "" {
			image.TargetRepository = image.SourceRepository
		}
		cfg.Images[name] = image
	}
}

func sortedImageNames(images map[string]ImageConfig) []string {
	names := make([]string, 0, len(images))
	for name := range images {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func resolveSecrets(cfg *Config) error {
	for name, registry := range cfg.Registries {
		resolved, err := resolveRegistrySecrets(registry, "registries."+name)
		if err != nil {
			return err
		}
		cfg.Registries[name] = resolved
	}
	return nil
}

func resolveRegistrySecrets(registry RegistryConfig, field string) (RegistryConfig, error) {
	if err := validateCredentialSources(registry, field); err != nil {
		return RegistryConfig{}, err
	}

	switch {
	case registry.Token != "":
		return registry, nil
	case registry.TokenEnv != "":
		value, ok := os.LookupEnv(registry.TokenEnv)
		if !ok {
			return RegistryConfig{}, fmt.Errorf("%s token-env %q is not set", field, registry.TokenEnv)
		}
		registry.Token = strings.TrimSpace(value)
		registry.TokenEnv = ""
	case registry.TokenCommand != "":
		value, err := readTokenFromCommand(registry.TokenCommand)
		if err != nil {
			return RegistryConfig{}, fmt.Errorf("%s token-command %q: %w", field, registry.TokenCommand, err)
		}
		registry.Token = value
		registry.TokenCommand = ""
	}

	return registry, nil
}

func validateCredentialSources(registry RegistryConfig, field string) error {
	sources := 0
	if registry.Token != "" {
		sources++
	}
	if registry.TokenEnv != "" {
		sources++
	}
	if registry.TokenCommand != "" {
		sources++
	}
	if sources > 1 {
		return fmt.Errorf("%s must use only one of token, token-env, or token-command", field)
	}
	return nil
}

func readTokenFromCommand(command string) (string, error) {
	output, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}

	return "", fmt.Errorf("empty secret output")
}

func validateConfig(cfg *Config) error {
	if len(cfg.Registries) == 0 {
		return fmt.Errorf("registries must contain at least one registry")
	}
	if len(cfg.Images) == 0 {
		return fmt.Errorf("images must contain at least one repository")
	}
	if err := validatePushStrategy(cfg.PushStrategy, "push-strategy"); err != nil {
		return err
	}

	for name, registry := range cfg.Registries {
		if err := validateRegistryConfig(registry, "registries."+name); err != nil {
			return err
		}
	}

	for name, image := range cfg.Images {
		prefix := fmt.Sprintf("images.%s", name)
		if err := validateSourceType(image.SourceType, prefix+".source-type"); err != nil {
			return err
		}
		if strings.TrimSpace(image.SourceRepository) == "" {
			return fmt.Errorf("%s.source-repository is required", prefix)
		}
		if image.SourceRegistry == "" {
			return fmt.Errorf("%s.source-registry is required when multiple registries are configured", prefix)
		}
		if image.TargetRegistry == "" {
			return fmt.Errorf("%s.target-registry is required when multiple registries are configured", prefix)
		}
		if _, ok := cfg.Registries[image.SourceRegistry]; !ok {
			return fmt.Errorf("%s.source-registry %q is not defined", prefix, image.SourceRegistry)
		}
		if _, ok := cfg.Registries[image.TargetRegistry]; !ok {
			return fmt.Errorf("%s.target-registry %q is not defined", prefix, image.TargetRegistry)
		}
		if cfg.Registries[image.TargetRegistry].Type != RegistryTypeOCI {
			return fmt.Errorf("%s.target-registry %q must reference an oci registry", prefix, image.TargetRegistry)
		}
		sourceRegistry := cfg.Registries[image.SourceRegistry]
		switch normalizeSourceType(image.SourceType) {
		case SourceTypeOCI:
			if sourceRegistry.Type != RegistryTypeOCI {
				return fmt.Errorf("%s.source-registry %q must reference an oci registry for source-type %q", prefix, image.SourceRegistry, SourceTypeOCI)
			}
		case SourceTypeHelmRepo:
			if sourceRegistry.Type != RegistryTypeHelmRepo {
				return fmt.Errorf("%s.source-registry %q must reference a helm-repo registry for source-type %q", prefix, image.SourceRegistry, SourceTypeHelmRepo)
			}
		}
		if err := validatePushStrategy(image.PushStrategy, prefix+".push-strategy"); err != nil {
			return err
		}
	}

	return nil
}

func validateRegistryConfig(registry RegistryConfig, field string) error {
	if err := validateRegistryType(registry.Type, field+".type"); err != nil {
		return err
	}
	switch normalizeRegistryType(registry.Type) {
	case RegistryTypeOCI:
		if strings.TrimSpace(registry.Registry) == "" {
			return fmt.Errorf("%s.registry is required for type %q", field, RegistryTypeOCI)
		}
	case RegistryTypeHelmRepo:
		if strings.TrimSpace(registry.URL) == "" {
			return fmt.Errorf("%s.url is required for type %q", field, RegistryTypeHelmRepo)
		}
	}
	if err := validateCredentialSources(registry, field); err != nil {
		return err
	}
	return nil
}

func validateRegistryType(registryType RegistryType, field string) error {
	switch normalizeRegistryType(registryType) {
	case RegistryTypeOCI, RegistryTypeHelmRepo:
		return nil
	default:
		return fmt.Errorf("%s must be one of %q or %q", field, RegistryTypeOCI, RegistryTypeHelmRepo)
	}
}

func normalizeRegistryType(registryType RegistryType) RegistryType {
	switch strings.ToLower(string(registryType)) {
	case "", string(RegistryTypeOCI):
		return RegistryTypeOCI
	case string(RegistryTypeHelmRepo):
		return RegistryTypeHelmRepo
	default:
		return ""
	}
}

func validateSourceType(sourceType SourceType, field string) error {
	switch normalizeSourceType(sourceType) {
	case SourceTypeOCI, SourceTypeHelmRepo:
		return nil
	default:
		return fmt.Errorf("%s must be one of %q or %q", field, SourceTypeOCI, SourceTypeHelmRepo)
	}
}

func normalizeSourceType(sourceType SourceType) SourceType {
	switch strings.ToLower(string(sourceType)) {
	case "", string(SourceTypeOCI):
		return SourceTypeOCI
	case string(SourceTypeHelmRepo):
		return SourceTypeHelmRepo
	default:
		return ""
	}
}

func validatePushStrategy(strategy PushStrategy, field string) error {
	switch normalizePushStrategy(strategy) {
	case PushStrategyIfNotPresent, PushStrategyAlways:
		return nil
	default:
		return fmt.Errorf("%s must be one of %q or %q", field, PushStrategyIfNotPresent, PushStrategyAlways)
	}
}

func normalizePushStrategy(strategy PushStrategy) PushStrategy {
	switch strings.ToLower(string(strategy)) {
	case "", strings.ToLower(string(PushStrategyIfNotPresent)):
		return PushStrategyIfNotPresent
	case strings.ToLower(string(PushStrategyAlways)):
		return PushStrategyAlways
	default:
		return ""
	}
}
