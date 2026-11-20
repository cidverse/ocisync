package ocisync

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opencontainers/go-digest"
)

// caBundlePaths are the well-known locations of the system CA bundle (PEM) across distributions. Every bundle found
// in an image gets the certificates appended. Many of them are symlinks to each other; symlinks are resolved and every
// file is patched only once.
var caBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",                      // Debian, Ubuntu, Alpine, Gentoo, Wolfi/Chainguard, distroless, BusyBox
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",       // RHEL, CentOS, Fedora, UBI, Rocky, Alma, Amazon Linux, Oracle Linux
	"/etc/pki/tls/certs/ca-bundle.crt",                        // RHEL/Fedora legacy path, Photon OS, Amazon Linux 2, Mariner/Azure Linux
	"/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", // RHEL/Fedora OpenSSL trusted certificate bundle
	"/etc/pki/tls/certs/ca-bundle.trust.crt",                  // RHEL/Fedora legacy path of the trusted bundle
	"/var/lib/ca-certificates/ca-bundle.pem",                  // openSUSE, SLES, SLE BCI
	"/etc/ssl/ca-bundle.pem",                                  // openSUSE, SLES (symlink to the one above)
	"/etc/ca-certificates/extracted/tls-ca-bundle.pem",        // Arch Linux
	"/etc/ssl/cert.pem",                                       // Alpine, Arch, Void (OpenSSL/LibreSSL default CA file)
	"/usr/lib/ssl/cert.pem",                                   // Debian/Ubuntu OpenSSL default CA file (OPENSSLDIR)
	"/etc/ssl/certs/ca-bundle.crt",                            // older Fedora/RHEL, some minimal images
	"/etc/pki/tls/cacert.pem",                                 // OpenELEC, older Mandriva/Mageia
}

// caBundleEnvVars point to CA bundles; if an image sets them, the referenced files are patched as well.
var caBundleEnvVars = []string{
	"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO",
	"AWS_CA_BUNDLE", "PIP_CERT", "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", "HEX_CACERTS_PATH", "DENO_CERT",
}

// caBundleEnvDefaults are set to the patched bundle with env: true, for tools that use their own CA store by default.
// Variables the image already sets are not changed.
var caBundleEnvDefaults = []string{
	"SSL_CERT_FILE",                      // OpenSSL, Go, .NET, Ruby, httpx
	"REQUESTS_CA_BUNDLE",                 // python requests (certifi), Azure CLI, Conda
	"AWS_CA_BUNDLE",                      // AWS CLI, boto3/botocore (certifi)
	"PIP_CERT",                           // pip (vendored certifi)
	"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", // Google Cloud SDK
	"HEX_CACERTS_PATH",                   // Hex (Elixir)
}

// caAnchorDirs are the directories read by the distribution tooling (update-ca-certificates, update-ca-trust, trust)
// to regenerate the bundles. The certificates are placed there too, so they survive a regeneration in derived images.
// Files are only written to directories that exist in the image.
var caAnchorDirs = []string{
	"/usr/local/share/ca-certificates",          // Debian, Ubuntu, Alpine (update-ca-certificates, requires .crt)
	"/etc/pki/ca-trust/source/anchors",          // RHEL, CentOS, Fedora, UBI, Amazon Linux (update-ca-trust)
	"/etc/pki/trust/anchors",                    // openSUSE, SLES (update-ca-certificates)
	"/etc/ca-certificates/trust-source/anchors", // Arch Linux (update-ca-trust / trust extract-compat)
}

// defaultCABundlePath is created when the image has no bundle and on-missing-bundle is "create".
const defaultCABundlePath = "/etc/ssl/certs/ca-certificates.crt"

// caExtraCertsDir holds a bundle with only the added certificates, used for NODE_EXTRA_CA_CERTS.
const caExtraCertsDir = "/etc/ssl/certs"

var unsafeFileNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type caCertificate struct {
	subject string
	pem     []byte
}

// caCertificatesPatch adds CA certificates to the trust stores of an image.
type caCertificatesPatch struct {
	name      string
	certs     []caCertificate
	env       bool
	onMissing MissingBundleAction
	java      JavaTruststoreMode
	// systemBundle replaces the content of the image bundles if set (base "system")
	systemBundle []byte
	keepPaths    map[string]bool
	keepNames    map[string]bool
}

func newCACertificatesPatch(name string, cfg *CACertificatesPatchConfig) *caCertificatesPatch {
	certs := make([]caCertificate, 0, len(cfg.certificates))
	for _, cert := range cfg.certificates {
		certs = append(certs, caCertificate{
			subject: strings.NewReplacer("\n", " ", "\r", " ").Replace(cert.Subject.String()),
			pem:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		})
	}

	keepPaths := map[string]bool{}
	keepNames := map[string]bool{}
	for _, p := range caBundlePaths {
		keepPaths[cleanFSPath(p)] = true
		keepNames[path.Base(p)] = true
	}

	return &caCertificatesPatch{
		name:         name,
		certs:        certs,
		env:          cfg.Env,
		onMissing:    cfg.OnMissingBundle,
		java:         cfg.Java,
		systemBundle: cfg.systemBundle,
		keepPaths:    keepPaths,
		keepNames:    keepNames,
	}
}

func (p *caCertificatesPatch) systemBundleDigest() string {
	if p.systemBundle == nil {
		return ""
	}
	return digest.FromBytes(p.systemBundle).String()
}

func (p *caCertificatesPatch) Name() string {
	return p.name
}

func (p *caCertificatesPatch) Fingerprint() any {
	certs := make([]string, 0, len(p.certs))
	for _, cert := range p.certs {
		certs = append(certs, string(cert.pem))
	}
	return struct {
		Type      string   `json:"type"`
		Certs     []string `json:"certs"`
		Env       bool     `json:"env"`
		OnMissing string   `json:"onMissing"`
		Java      string   `json:"java"`
		// the system bundle is part of the output, a change on the host re-syncs the images
		SystemBundle string `json:"systemBundle,omitempty"`
	}{Type: "ca-certificates", Certs: certs, Env: p.env, OnMissing: string(p.onMissing), Java: string(p.java), SystemBundle: p.systemBundleDigest()}
}

// KeepFile keeps the bundles in memory during the scan. Bundles at other locations (symlink targets, env vars) are
// read from their layer afterwards.
func (p *caCertificatesPatch) KeepFile(name string) bool {
	return p.keepPaths[name] || (p.keepNames[path.Base(name)] && strings.HasPrefix(name, "etc/"))
}

func (p *caCertificatesPatch) Apply(ctx context.Context, fsys *imageFS, cfg *imageConfigFile) error {
	candidates := append([]string{}, caBundlePaths...)
	for _, key := range caBundleEnvVars {
		if value, ok := cfg.Env(key); ok && path.IsAbs(value) {
			candidates = append(candidates, value)
		}
	}

	primary := ""
	createdBundle := false
	patched := map[string]bool{}
	for _, candidate := range candidates {
		resolved, node, err := fsys.resolve(candidate)
		if err != nil {
			return err
		}
		if node == nil || !node.isRegular() {
			continue
		}
		if primary == "" {
			primary = candidate
		}
		if patched[resolved] {
			continue
		}
		patched[resolved] = true

		if p.systemBundle != nil {
			// base "system": the image bundle is replaced, its content is not needed
			updated, _ := p.appendCertificates(p.systemBundle)
			fsys.WriteFile(resolved, updated, node.mode, node.uid, node.gid)
			continue
		}

		data, err := fsys.ReadFile(ctx, resolved)
		if err != nil {
			return fmt.Errorf("read CA bundle %s: %w", candidate, err)
		}
		if updated, changed := p.appendCertificates(data); changed {
			fsys.WriteFile(resolved, updated, node.mode, node.uid, node.gid)
		}
	}

	if primary == "" {
		switch p.onMissing {
		case MissingBundleSkip:
			return nil
		case MissingBundleCreate:
			updated, _ := p.appendCertificates(p.systemBundle)
			if err := writeFileIfChanged(ctx, fsys, defaultCABundlePath, updated); err != nil {
				return err
			}
			primary = defaultCABundlePath
			createdBundle = true
		default:
			return fmt.Errorf("no CA bundle found in the image (checked %s); set on-missing-bundle to skip or create", strings.Join(caBundlePaths, ", "))
		}
	}

	if err := p.writeAnchors(ctx, fsys); err != nil {
		return err
	}

	if p.env {
		if err := p.setEnv(ctx, fsys, cfg, primary); err != nil {
			return err
		}
	}

	// a created bundle without system base only holds the configured certificates; a java truststore built from it
	// would drop all public roots of the JDK
	if !createdBundle || p.systemBundle != nil {
		resolved, _, err := fsys.resolve(primary)
		if err != nil {
			return err
		}
		bundle, err := fsys.ReadFile(ctx, resolved)
		if err != nil {
			return fmt.Errorf("read patched CA bundle %s: %w", primary, err)
		}
		if err := p.applyJava(ctx, fsys, cfg, bundle); err != nil {
			return err
		}
	}
	return nil
}

// appendCertificates appends all certificates that are not yet part of the bundle.
func (p *caCertificatesPatch) appendCertificates(bundle []byte) ([]byte, bool) {
	out := append([]byte{}, bundle...)
	changed := false
	for _, cert := range p.certs {
		if bytes.Contains(bundle, cert.pem) {
			continue
		}
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, fmt.Sprintf("# %s (added by ocisync patch %s)\n", cert.subject, p.name)...)
		out = append(out, cert.pem...)
		changed = true
	}
	return out, changed
}

// writeAnchors places each certificate in the source directories of the distribution trust tooling.
func (p *caCertificatesPatch) writeAnchors(ctx context.Context, fsys *imageFS) error {
	for _, dir := range caAnchorDirs {
		resolvedDir, node, err := fsys.resolve(dir)
		if err != nil {
			return err
		}
		if node == nil || !node.isDir() {
			continue
		}
		for i, cert := range p.certs {
			if err := writeFileIfChanged(ctx, fsys, path.Join(resolvedDir, p.certFileName(i)), cert.pem); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *caCertificatesPatch) setEnv(ctx context.Context, fsys *imageFS, cfg *imageConfigFile, primary string) error {
	for _, key := range caBundleEnvDefaults {
		if _, ok := cfg.Env(key); !ok {
			cfg.SetEnv(key, primary)
		}
	}

	// deno uses the bundled mozilla roots by default; "system" makes it read the patched system store
	if _, ok := cfg.Env("DENO_TLS_CA_STORE"); !ok {
		cfg.SetEnv("DENO_TLS_CA_STORE", "system")
	}

	// node.js ships its own CA store and only reads additional certificates from NODE_EXTRA_CA_CERTS; if the image
	// already sets it, the referenced file was patched above
	if _, ok := cfg.Env("NODE_EXTRA_CA_CERTS"); !ok {
		var extra []byte
		for _, cert := range p.certs {
			extra = append(extra, cert.pem...)
		}
		extraPath := path.Join(caExtraCertsDir, "ocisync-"+p.safeName()+".pem")
		if err := writeFileIfChanged(ctx, fsys, extraPath, extra); err != nil {
			return err
		}
		cfg.SetEnv("NODE_EXTRA_CA_CERTS", extraPath)
	}
	return nil
}

func (p *caCertificatesPatch) safeName() string {
	name := strings.Trim(unsafeFileNameChars.ReplaceAllString(p.name, "-"), "-.")
	if name == "" {
		return "ca"
	}
	return name
}

func (p *caCertificatesPatch) certFileName(index int) string {
	if len(p.certs) == 1 {
		return fmt.Sprintf("ocisync-%s.crt", p.safeName())
	}
	return fmt.Sprintf("ocisync-%s-%d.crt", p.safeName(), index+1)
}

// writeFileIfChanged writes a file (following symlinks) with mode 0644 unless it already has the given content.
func writeFileIfChanged(ctx context.Context, fsys *imageFS, name string, data []byte) error {
	resolved, node, err := fsys.resolve(name)
	if err != nil {
		return err
	}
	if resolved == "" || (node != nil && !node.isRegular()) {
		return fmt.Errorf("cannot write %s: path is not a regular file", name)
	}
	if node != nil {
		existing, err := fsys.ReadFile(ctx, resolved)
		if err == nil && bytes.Equal(existing, data) {
			return nil
		}
	}
	fsys.WriteFile(resolved, data, 0o644, 0, 0)
	return nil
}

// parseCertificatesPEM parses all certificates of a PEM file. Other PEM blocks (e.g. private keys) are rejected.
func parseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q, only CERTIFICATE blocks are allowed", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM encoded certificates found")
	}
	return certs, nil
}
