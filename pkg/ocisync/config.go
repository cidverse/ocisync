package ocisync

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Registries   map[string]RegistryConfig `yaml:"registries"`
	Images       map[string]ImageConfig    `yaml:"images"`
	Patches      map[string]PatchConfig    `yaml:"patches"`
	PushStrategy PushStrategy              `yaml:"push-strategy"`
}

type RegistryType string

type RegistryConfig struct {
	Type         RegistryType `yaml:"type"`
	Registry     string       `yaml:"registry"`
	URL          string       `yaml:"url"`
	Username     string       `yaml:"username"`
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
	Patches          []string      `yaml:"patches"`
}

// PatchConfig defines a modification applied to container images before they are pushed to the target.
type PatchConfig struct {
	CACertificates *CACertificatesPatchConfig `yaml:"ca-certificates"`
}

// CACertificatesPatchConfig adds CA certificates to the system trust stores of an image.
type CACertificatesPatchConfig struct {
	// Files are PEM files with one or more certificates, relative to the config file.
	Files []string `yaml:"files"`
	// Env sets CA env vars (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, AWS_CA_BUNDLE, PIP_CERT, NODE_EXTRA_CA_CERTS, ...) unless the image already sets them.
	Env             bool                `yaml:"env"`
	OnMissingBundle MissingBundleAction `yaml:"on-missing-bundle"`
	// Base selects the bundle the certificates are added to: the bundle of the image (default) or the CA bundle of
	// the system running ocisync, which then replaces the bundles of the image.
	Base CABundleBase `yaml:"base"`
	// Java selects how Java truststores are handled: replace the truststores in the image (default), write a separate
	// truststore and select it with JAVA_TOOL_OPTIONS, or leave them alone.
	Java JavaTruststoreMode `yaml:"java"`

	certificates []*x509.Certificate // loaded from Files by LoadConfig
	systemBundle []byte              // loaded by LoadConfig for base "system"
}

type MissingBundleAction string

type CABundleBase string

type JavaTruststoreMode string

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

	MissingBundleFail   MissingBundleAction = "fail"
	MissingBundleSkip   MissingBundleAction = "skip"
	MissingBundleCreate MissingBundleAction = "create"

	CABundleBaseImage  CABundleBase = "image"
	CABundleBaseSystem CABundleBase = "system"

	JavaTruststoreReplace JavaTruststoreMode = "replace"
	JavaTruststoreEnv     JavaTruststoreMode = "env"
	JavaTruststoreNone    JavaTruststoreMode = "none"
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
	if err = loadPatchFiles(&cfg, filepath.Dir(path)); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	// enum values are matched case-insensitively; normalize valid values to their canonical form so the rest of the
	// code can compare against the constants directly. invalid values are kept as-is so validation can report them.
	cfg.PushStrategy = canonical(cfg.PushStrategy, normalizePushStrategy)

	for name, registry := range cfg.Registries {
		registry.Type = canonical(registry.Type, normalizeRegistryType)
		cfg.Registries[name] = registry
	}

	for name, image := range cfg.Images {
		image.SourceType = canonical(image.SourceType, normalizeSourceType)
		if image.PushStrategy == "" {
			image.PushStrategy = cfg.PushStrategy
		} else {
			image.PushStrategy = canonical(image.PushStrategy, normalizePushStrategy)
		}
		if image.SourceRepository == "" {
			image.SourceRepository = image.TargetRepository
		}
		if image.TargetRepository == "" {
			image.TargetRepository = image.SourceRepository
		}
		cfg.Images[name] = image
	}

	for name, patch := range cfg.Patches {
		if patch.CACertificates != nil {
			patch.CACertificates.OnMissingBundle = canonical(patch.CACertificates.OnMissingBundle, normalizeMissingBundleAction)
			patch.CACertificates.Base = canonical(patch.CACertificates.Base, normalizeCABundleBase)
			patch.CACertificates.Java = canonical(patch.CACertificates.Java, normalizeJavaTruststoreMode)
		}
		cfg.Patches[name] = patch
	}
}

// canonical returns the normalized form of value, or value unchanged if it is not a recognized value.
func canonical[T ~string](value T, normalize func(T) T) T {
	if normalized := normalize(value); normalized != "" {
		return normalized
	}
	return value
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
			return fmt.Errorf("%s.source-registry is required", prefix)
		}
		if image.TargetRegistry == "" {
			return fmt.Errorf("%s.target-registry is required", prefix)
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
		switch image.SourceType {
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
		seen := map[string]bool{}
		for i, patchName := range image.Patches {
			field := fmt.Sprintf("%s.patches[%d]", prefix, i)
			if _, ok := cfg.Patches[patchName]; !ok {
				return fmt.Errorf("%s %q is not defined", field, patchName)
			}
			if seen[patchName] {
				return fmt.Errorf("%s %q is listed more than once", field, patchName)
			}
			seen[patchName] = true
		}
		if len(image.Patches) > 0 && image.SourceType != SourceTypeOCI {
			return fmt.Errorf("%s.patches can only be used with source-type %q", prefix, SourceTypeOCI)
		}
	}

	for name, patch := range cfg.Patches {
		if err := validatePatchConfig(patch, "patches."+name); err != nil {
			return err
		}
	}

	return nil
}

func validatePatchConfig(patch PatchConfig, field string) error {
	if patch.CACertificates == nil {
		return fmt.Errorf("%s must define a patch type (ca-certificates)", field)
	}
	ca := patch.CACertificates
	if len(ca.Files) == 0 {
		return fmt.Errorf("%s.ca-certificates.files must contain at least one file", field)
	}
	for i, file := range ca.Files {
		if strings.TrimSpace(file) == "" {
			return fmt.Errorf("%s.ca-certificates.files[%d] must not be empty", field, i)
		}
	}
	if err := validateMissingBundleAction(ca.OnMissingBundle, field+".ca-certificates.on-missing-bundle"); err != nil {
		return err
	}
	if err := validateCABundleBase(ca.Base, field+".ca-certificates.base"); err != nil {
		return err
	}
	return validateJavaTruststoreMode(ca.Java, field+".ca-certificates.java")
}

// loadPatchFiles reads the files referenced by patches; relative paths are resolved against baseDir.
func loadPatchFiles(cfg *Config, baseDir string) error {
	for name, patch := range cfg.Patches {
		if patch.CACertificates == nil {
			continue
		}
		var certs []*x509.Certificate
		for i, file := range patch.CACertificates.Files {
			field := fmt.Sprintf("patches.%s.ca-certificates.files[%d]", name, i)
			filePath := file
			if !filepath.IsAbs(filePath) {
				filePath = filepath.Join(baseDir, filePath)
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
			parsed, err := parseCertificatesPEM(data)
			if err != nil {
				return fmt.Errorf("%s %s: %w", field, file, err)
			}
			certs = append(certs, parsed...)
		}
		patch.CACertificates.certificates = certs

		if patch.CACertificates.Base == CABundleBaseSystem {
			bundle, err := readSystemCABundle()
			if err != nil {
				return fmt.Errorf("patches.%s.ca-certificates.base %q: %w", name, CABundleBaseSystem, err)
			}
			patch.CACertificates.systemBundle = bundle
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
	if registry.Username != "" && registry.Token == "" {
		return fmt.Errorf("%s.username requires one of token, token-env, or token-command", field)
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

func validateMissingBundleAction(action MissingBundleAction, field string) error {
	if normalizeMissingBundleAction(action) == "" {
		return fmt.Errorf("%s must be one of %q, %q or %q", field, MissingBundleFail, MissingBundleSkip, MissingBundleCreate)
	}
	return nil
}

func normalizeMissingBundleAction(action MissingBundleAction) MissingBundleAction {
	switch strings.ToLower(string(action)) {
	case "", string(MissingBundleFail):
		return MissingBundleFail
	case string(MissingBundleSkip):
		return MissingBundleSkip
	case string(MissingBundleCreate):
		return MissingBundleCreate
	default:
		return ""
	}
}

func validateCABundleBase(base CABundleBase, field string) error {
	if normalizeCABundleBase(base) == "" {
		return fmt.Errorf("%s must be one of %q or %q", field, CABundleBaseImage, CABundleBaseSystem)
	}
	return nil
}

func normalizeCABundleBase(base CABundleBase) CABundleBase {
	switch strings.ToLower(string(base)) {
	case "", string(CABundleBaseImage):
		return CABundleBaseImage
	case string(CABundleBaseSystem):
		return CABundleBaseSystem
	default:
		return ""
	}
}

// readSystemCABundle reads the CA bundle of the system running ocisync: $SSL_CERT_FILE if set, otherwise the first
// well-known bundle location that exists. Symlinks are followed on the host.
func readSystemCABundle() ([]byte, error) {
	candidates := caBundlePaths
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		candidates = []string{file}
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		if !x509.NewCertPool().AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("system CA bundle %s contains no certificates", candidate)
		}
		return data, nil
	}
	return nil, fmt.Errorf("no system CA bundle found (checked %s)", strings.Join(candidates, ", "))
}

func validateJavaTruststoreMode(mode JavaTruststoreMode, field string) error {
	if normalizeJavaTruststoreMode(mode) == "" {
		return fmt.Errorf("%s must be one of %q, %q or %q", field, JavaTruststoreReplace, JavaTruststoreEnv, JavaTruststoreNone)
	}
	return nil
}

func normalizeJavaTruststoreMode(mode JavaTruststoreMode) JavaTruststoreMode {
	switch strings.ToLower(string(mode)) {
	case "", string(JavaTruststoreReplace):
		return JavaTruststoreReplace
	case string(JavaTruststoreEnv):
		return JavaTruststoreEnv
	case string(JavaTruststoreNone):
		return JavaTruststoreNone
	default:
		return ""
	}
}
