package ocisync

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
)

type testTarEntry struct {
	name     string
	typ      byte
	content  string
	linkname string
}

func buildTestTar(t *testing.T, entries ...testTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typ, Mode: 0o644, Linkname: entry.linkname, ModTime: time.Unix(0, 0)}
		switch entry.typ {
		case tar.TypeDir:
			header.Mode = 0o755
		case tar.TypeReg:
			header.Size = int64(len(entry.content))
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(entry.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarDir(name string) testTarEntry { return testTarEntry{name: name, typ: tar.TypeDir} }
func tarFile(name, content string) testTarEntry {
	return testTarEntry{name: name, typ: tar.TypeReg, content: content}
}
func tarSymlink(name, target string) testTarEntry {
	return testTarEntry{name: name, typ: tar.TypeSymlink, linkname: target}
}

func readTarFiles(t *testing.T, data []byte) map[string]testTarEntry {
	t.Helper()
	tarStream, closeFn, err := openLayer(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	files := map[string]testTarEntry{}
	tr := tar.NewReader(tarStream)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		files[strings.TrimSuffix(header.Name, "/")] = testTarEntry{name: header.Name, typ: header.Typeflag, content: string(body), linkname: header.Linkname}
	}
	return files
}

func newTestCACert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newTestPatchSet(t *testing.T, cfg *CACertificatesPatchConfig) *imagePatchSet {
	t.Helper()
	if cfg.OnMissingBundle == "" {
		cfg.OnMissingBundle = MissingBundleFail
	}
	if cfg.Java == "" {
		cfg.Java = JavaTruststoreReplace
	}
	set, err := newImagePatchSet([]imagePatch{newCACertificatesPatch("corp-ca", cfg)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func pushTestBlob(t *testing.T, store oras.Target, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	desc := content.NewDescriptorFromBytes(mediaType, data)
	exists, err := store.Exists(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err := store.Push(context.Background(), desc, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	return desc
}

// pushTestImage pushes a single-platform image with gzip compressed layers and returns its manifest descriptor.
func pushTestImage(t *testing.T, store oras.Target, layers ...[]byte) ocispec.Descriptor {
	t.Helper()
	return pushTestImageWithEnv(t, store, nil, layers...)
}

func pushTestImageWithEnv(t *testing.T, store oras.Target, env []string, layers ...[]byte) ocispec.Descriptor {
	t.Helper()
	var layerDescs []ocispec.Descriptor
	var diffIDs []string
	var history []map[string]any
	for _, layer := range layers {
		compressed, err := gzipBytes(layer)
		if err != nil {
			t.Fatal(err)
		}
		layerDescs = append(layerDescs, pushTestBlob(t, store, ocispec.MediaTypeImageLayerGzip, compressed))
		diffIDs = append(diffIDs, digest.FromBytes(layer).String())
		history = append(history, map[string]any{"created_by": "test"})
	}
	configData, err := json.Marshal(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config":       map[string]any{"Env": append([]string{"PATH=/usr/bin"}, env...)},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": diffIDs},
		"history":      history,
	})
	if err != nil {
		t.Fatal(err)
	}
	configDesc := pushTestBlob(t, store, ocispec.MediaTypeImageConfig, configData)
	manifestData, err := json.Marshal(ocispec.Manifest{
		Versioned: specsVersioned(),
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    layerDescs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pushTestBlob(t, store, ocispec.MediaTypeImageManifest, manifestData)
}

func fetchJSON(t *testing.T, store oras.ReadOnlyTarget, desc ocispec.Descriptor, v any) {
	t.Helper()
	data, err := content.FetchAll(context.Background(), store, desc)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func TestCopyPatchedImageDebian(t *testing.T) {
	ctx := context.Background()
	src, dst := memory.New(), memory.New()
	cert := newTestCACert(t, "Corp Root CA")

	base := buildTestTar(t,
		tarDir("etc/"), tarDir("etc/ssl/"), tarDir("etc/ssl/certs/"),
		tarFile("etc/ssl/certs/ca-certificates.crt", "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n"),
		tarSymlink("etc/ssl/cert.pem", "certs/ca-certificates.crt"),
		tarDir("usr/"), tarDir("usr/local/"), tarDir("usr/local/share/"), tarDir("usr/local/share/ca-certificates/"),
		tarDir("usr/lib/"), tarDir("usr/lib/ssl/"),
		tarSymlink("usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"),
	)
	app := buildTestTar(t, tarFile("app/run.sh", "#!/bin/sh\n"))
	manifestDesc := pushTestImage(t, src, base, app)
	if err := src.Tag(ctx, manifestDesc, "1.0"); err != nil {
		t.Fatal(err)
	}

	set := newTestPatchSet(t, &CACertificatesPatchConfig{Env: true, certificates: []*x509.Certificate{cert}})
	if err := copyPatchedImage(ctx, src, "1.0", dst, "1.0", set, "example.com/app:1.0"); err != nil {
		t.Fatal(err)
	}

	patchedDesc, err := dst.Resolve(ctx, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	var manifest ocispec.Manifest
	fetchJSON(t, dst, patchedDesc, &manifest)
	if len(manifest.Layers) != 3 {
		t.Fatalf("layers = %d, want 3", len(manifest.Layers))
	}
	if manifest.Annotations[ocispec.AnnotationBaseImageDigest] != manifestDesc.Digest.String() {
		t.Errorf("base digest annotation = %q", manifest.Annotations[ocispec.AnnotationBaseImageDigest])
	}
	for _, layer := range manifest.Layers[:2] {
		if exists, _ := dst.Exists(ctx, layer); !exists {
			t.Errorf("source layer %s was not copied", layer.Digest)
		}
	}

	layerData, err := content.FetchAll(ctx, dst, manifest.Layers[2])
	if err != nil {
		t.Fatal(err)
	}
	files := readTarFiles(t, layerData)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	bundle, ok := files["etc/ssl/certs/ca-certificates.crt"]
	if !ok {
		t.Fatalf("bundle not patched, layer files: %v", files)
	}
	if !strings.HasPrefix(bundle.content, "-----BEGIN CERTIFICATE-----\nPUBLIC") || !strings.Contains(bundle.content, certPEM) {
		t.Errorf("unexpected bundle content:\n%s", bundle.content)
	}
	if _, ok := files["etc/ssl/cert.pem"]; ok {
		t.Error("symlink etc/ssl/cert.pem must not be replaced")
	}
	if anchor := files["usr/local/share/ca-certificates/ocisync-corp-ca.crt"]; anchor.content != certPEM {
		t.Errorf("anchor = %q", anchor.content)
	}
	if extra := files["etc/ssl/certs/ocisync-corp-ca.pem"]; extra.content != certPEM {
		t.Errorf("extra certs file = %q", extra.content)
	}
	if _, ok := files["etc/pki/ca-trust/source/anchors/ocisync-corp-ca.crt"]; ok {
		t.Error("anchors must only be written to existing directories")
	}

	var cfg map[string]any
	fetchJSON(t, dst, manifest.Config, &cfg)
	rootfs := cfg["rootfs"].(map[string]any)
	diffIDs := rootfs["diff_ids"].([]any)
	if len(diffIDs) != 3 || diffIDs[2] != digest.FromBytes(mustGunzip(t, layerData)).String() {
		t.Errorf("diff_ids = %v", diffIDs)
	}
	if history := cfg["history"].([]any); len(history) != 3 {
		t.Errorf("history entries = %d", len(history))
	}
	runtime := cfg["config"].(map[string]any)
	env := runtime["Env"].([]any)
	bundlePath := "/etc/ssl/certs/ca-certificates.crt"
	wantEnv := []any{
		"PATH=/usr/bin",
		"SSL_CERT_FILE=" + bundlePath,
		"REQUESTS_CA_BUNDLE=" + bundlePath,
		"AWS_CA_BUNDLE=" + bundlePath,
		"PIP_CERT=" + bundlePath,
		"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=" + bundlePath,
		"HEX_CACERTS_PATH=" + bundlePath,
		"DENO_TLS_CA_STORE=system",
		"NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ocisync-corp-ca.pem",
	}
	if len(env) != len(wantEnv) {
		t.Fatalf("env = %v", env)
	}
	for i := range wantEnv {
		if env[i] != wantEnv[i] {
			t.Errorf("env[%d] = %v, want %v", i, env[i], wantEnv[i])
		}
	}

	fingerprint, err := patchFingerprintOf(ctx, dst, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != set.fingerprint {
		t.Errorf("fingerprint = %q, want %q", fingerprint, set.fingerprint)
	}

	// patching is deterministic, a second run produces the same image
	dst2 := memory.New()
	if err := copyPatchedImage(ctx, src, "1.0", dst2, "1.0", set, "example.com/app:1.0"); err != nil {
		t.Fatal(err)
	}
	again, err := dst2.Resolve(ctx, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != patchedDesc.Digest {
		t.Errorf("second run digest %s != %s", again.Digest, patchedDesc.Digest)
	}
}

func TestCopyPatchedImageRHELIndex(t *testing.T) {
	ctx := context.Background()
	src, dst := memory.New(), memory.New()
	cert := newTestCACert(t, "Corp Root CA")

	// RHEL layout: /etc/ssl/certs is a directory symlink and the legacy bundle a symlink to the extracted bundle
	base := buildTestTar(t,
		tarDir("etc/"), tarDir("etc/pki/"), tarDir("etc/pki/tls/"), tarDir("etc/pki/tls/certs/"),
		tarDir("etc/pki/ca-trust/"), tarDir("etc/pki/ca-trust/extracted/"), tarDir("etc/pki/ca-trust/extracted/pem/"),
		tarDir("etc/pki/ca-trust/extracted/openssl/"),
		tarDir("etc/pki/ca-trust/source/"), tarDir("etc/pki/ca-trust/source/anchors/"),
		tarFile("etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "# public\n"),
		tarFile("etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", "# trusted\n"),
		tarSymlink("etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
		tarSymlink("etc/pki/tls/certs/ca-bundle.trust.crt", "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt"),
		tarDir("etc/ssl/"),
		tarSymlink("etc/ssl/certs", "/etc/pki/tls/certs"),
	)
	amd64 := pushTestImage(t, src, base)
	attestation := pushTestBlob(t, src, ocispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2}`))
	attestation.Annotations = map[string]string{"vnd.docker.reference.type": "attestation-manifest"}
	attestation.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}
	amd64.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	indexData, err := json.Marshal(ocispec.Index{
		Versioned: specsVersioned(),
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{amd64, attestation},
	})
	if err != nil {
		t.Fatal(err)
	}
	indexDesc := pushTestBlob(t, src, ocispec.MediaTypeImageIndex, indexData)
	if err := src.Tag(ctx, indexDesc, "9"); err != nil {
		t.Fatal(err)
	}

	set := newTestPatchSet(t, &CACertificatesPatchConfig{certificates: []*x509.Certificate{cert}})
	if err := copyPatchedImage(ctx, src, "9", dst, "9", set, "example.com/ubi:9"); err != nil {
		t.Fatal(err)
	}

	patchedIndexDesc, err := dst.Resolve(ctx, "9")
	if err != nil {
		t.Fatal(err)
	}
	var index ocispec.Index
	fetchJSON(t, dst, patchedIndexDesc, &index)
	if len(index.Manifests) != 1 {
		t.Fatalf("index manifests = %d, want 1 (attestation dropped)", len(index.Manifests))
	}
	if index.Manifests[0].Platform == nil || index.Manifests[0].Platform.Architecture != "amd64" {
		t.Errorf("platform not kept: %+v", index.Manifests[0].Platform)
	}
	if len(index.Manifests[0].Data) != 0 {
		t.Error("index entries must not embed manifest data")
	}

	var manifest ocispec.Manifest
	fetchJSON(t, dst, index.Manifests[0], &manifest)
	layerData, err := content.FetchAll(ctx, dst, manifest.Layers[len(manifest.Layers)-1])
	if err != nil {
		t.Fatal(err)
	}
	files := readTarFiles(t, layerData)
	for _, name := range []string{
		"etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt",
		"etc/pki/ca-trust/source/anchors/ocisync-corp-ca.crt",
	} {
		if _, ok := files[name]; !ok {
			t.Errorf("%s not written, layer files: %v", name, files)
		}
	}
	for _, name := range []string{"etc/pki/tls/certs/ca-bundle.crt", "etc/ssl/certs/ca-bundle.crt", "etc/ssl/certs"} {
		if _, ok := files[name]; ok {
			t.Errorf("%s must not be written (symlink)", name)
		}
	}

	fingerprint, err := patchFingerprintOf(ctx, dst, "9")
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != set.fingerprint {
		t.Errorf("fingerprint = %q, want %q", fingerprint, set.fingerprint)
	}
}

func TestCopyPatchedImageMissingBundle(t *testing.T) {
	ctx := context.Background()
	cert := newTestCACert(t, "Corp Root CA")

	tests := []struct {
		action      MissingBundleAction
		wantErr     bool
		wantLayers  int
		wantCreated bool
	}{
		{action: MissingBundleFail, wantErr: true},
		{action: MissingBundleSkip, wantLayers: 1},
		{action: MissingBundleCreate, wantLayers: 2, wantCreated: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			src, dst := memory.New(), memory.New()
			desc := pushTestImage(t, src, buildTestTar(t, tarFile("app", "binary")))
			if err := src.Tag(ctx, desc, "1"); err != nil {
				t.Fatal(err)
			}
			set := newTestPatchSet(t, &CACertificatesPatchConfig{OnMissingBundle: tt.action, certificates: []*x509.Certificate{cert}})
			err := copyPatchedImage(ctx, src, "1", dst, "1", set, "example.com/static:1")
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "no CA bundle found") {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			patched, err := dst.Resolve(ctx, "1")
			if err != nil {
				t.Fatal(err)
			}
			var manifest ocispec.Manifest
			fetchJSON(t, dst, patched, &manifest)
			if len(manifest.Layers) != tt.wantLayers {
				t.Fatalf("layers = %d, want %d", len(manifest.Layers), tt.wantLayers)
			}
			if tt.wantCreated {
				layerData, err := content.FetchAll(ctx, dst, manifest.Layers[1])
				if err != nil {
					t.Fatal(err)
				}
				files := readTarFiles(t, layerData)
				for _, name := range []string{"etc", "etc/ssl", "etc/ssl/certs", "etc/ssl/certs/ca-certificates.crt"} {
					if _, ok := files[name]; !ok {
						t.Errorf("%s not created, layer files: %v", name, files)
					}
				}
			}
			fingerprint, err := patchFingerprintOf(ctx, dst, "1")
			if err != nil {
				t.Fatal(err)
			}
			if fingerprint != set.fingerprint {
				t.Errorf("fingerprint = %q", fingerprint)
			}
		})
	}
}

func TestImageFSWhiteoutsAndSymlinks(t *testing.T) {
	fsys := newImageFS(nil, func(string) bool { return true })
	layers := [][]byte{
		buildTestTar(t,
			tarDir("etc/"), tarDir("etc/ssl/"), tarDir("etc/ssl/certs/"),
			tarFile("etc/ssl/certs/ca-certificates.crt", "old"),
			tarDir("opt/"), tarFile("opt/a", "a"), tarFile("opt/b", "b"),
			tarFile("removed", "x"),
		),
		buildTestTar(t,
			tarFile(".wh.removed", ""),
			tarFile("opt/.wh..wh..opq", ""),
			tarFile("opt/c", "c"),
			tarFile("etc/ssl/certs/ca-certificates.crt", "new"),
			tarSymlink("etc/alt", "ssl/certs"),
			tarSymlink("loop", "loop"),
		),
	}
	for i, layer := range layers {
		if err := fsys.addLayer(i, bytes.NewReader(layer)); err != nil {
			t.Fatal(err)
		}
	}

	if fsys.lookup("removed") != nil {
		t.Error("whiteout did not remove file")
	}
	if fsys.lookup("opt/a") != nil || fsys.lookup("opt/b") != nil || fsys.lookup("opt/c") == nil {
		t.Error("opaque whiteout not applied correctly")
	}
	resolved, node, err := fsys.resolve("/etc/alt/ca-certificates.crt")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "etc/ssl/certs/ca-certificates.crt" || node == nil || string(node.content) != "new" {
		t.Errorf("resolve = %q, %+v", resolved, node)
	}
	if _, _, err := fsys.resolve("/loop/x"); err == nil {
		t.Error("expected symlink loop error")
	}
	resolved, node, err = fsys.resolve("/etc/alt/missing/file")
	if err != nil || node != nil || resolved != "etc/ssl/certs/missing/file" {
		t.Errorf("resolve missing = %q, %v, %v", resolved, node, err)
	}
}

func TestImageFSReadFileFromLayer(t *testing.T) {
	layer := buildTestTar(t,
		tarFile("data/original", "content"),
		testTarEntry{name: "data/link", typ: tar.TypeLink, linkname: "data/original"},
	)
	fetch := func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}
	fsys := newImageFS(fetch, nil) // keeps no content during the scan
	fsys.layers = []ocispec.Descriptor{{}}
	if err := fsys.addLayer(0, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"data/original", "data/link"} {
		data, err := fsys.ReadFile(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "content" {
			t.Errorf("%s = %q", name, data)
		}
	}
}

func TestAppendCertificatesIsIdempotent(t *testing.T) {
	cert := newTestCACert(t, "Corp Root CA")
	patch := newCACertificatesPatch("corp", &CACertificatesPatchConfig{certificates: []*x509.Certificate{cert}})

	once, changed := patch.appendCertificates([]byte("existing"))
	if !changed || !strings.HasPrefix(string(once), "existing\n# CN=Corp Root CA") {
		t.Fatalf("first append = %q", once)
	}
	twice, changed := patch.appendCertificates(once)
	if changed || !bytes.Equal(once, twice) {
		t.Error("certificate appended twice")
	}
}

func TestParseCertificatesPEMRejectsKeys(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})
	if _, err := parseCertificatesPEM(data); err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("err = %v", err)
	}
	if _, err := parseCertificatesPEM([]byte("nothing")); err == nil {
		t.Error("expected error for file without certificates")
	}
}

func mustGunzip(t *testing.T, data []byte) []byte {
	t.Helper()
	r, closeFn, err := openLayer(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func specsVersioned() specs.Versioned {
	return specs.Versioned{SchemaVersion: 2}
}

func TestCopyPatchedImageSystemBase(t *testing.T) {
	ctx := context.Background()
	src, dst := memory.New(), memory.New()
	cert := newTestCACert(t, "Corp Root CA")

	base := buildTestTar(t,
		tarDir("etc/"), tarDir("etc/ssl/"), tarDir("etc/ssl/certs/"),
		tarFile("etc/ssl/certs/ca-certificates.crt", "# image bundle\n"),
	)
	desc := pushTestImage(t, src, base)
	if err := src.Tag(ctx, desc, "1"); err != nil {
		t.Fatal(err)
	}

	systemBundle := []byte("# system bundle\n")
	imageSet := newTestPatchSet(t, &CACertificatesPatchConfig{certificates: []*x509.Certificate{cert}})
	set := newTestPatchSet(t, &CACertificatesPatchConfig{certificates: []*x509.Certificate{cert}, systemBundle: systemBundle})
	if set.fingerprint == imageSet.fingerprint {
		t.Error("base system must change the fingerprint")
	}
	if err := copyPatchedImage(ctx, src, "1", dst, "1", set, "example.com/app:1"); err != nil {
		t.Fatal(err)
	}

	patched, err := dst.Resolve(ctx, "1")
	if err != nil {
		t.Fatal(err)
	}
	var manifest ocispec.Manifest
	fetchJSON(t, dst, patched, &manifest)
	layerData, err := content.FetchAll(ctx, dst, manifest.Layers[len(manifest.Layers)-1])
	if err != nil {
		t.Fatal(err)
	}
	bundle := readTarFiles(t, layerData)["etc/ssl/certs/ca-certificates.crt"].content
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	if !strings.HasPrefix(bundle, "# system bundle\n") || strings.Contains(bundle, "image bundle") || !strings.Contains(bundle, certPEM) {
		t.Errorf("unexpected bundle content:\n%s", bundle)
	}
}

// jksEntryCount checks the JKS header and integrity digest and returns the number of entries.
func jksEntryCount(t *testing.T, data []byte, password string) int {
	t.Helper()
	if len(data) < 32 || binary.BigEndian.Uint32(data) != jksMagic || binary.BigEndian.Uint32(data[4:]) != jksVersion {
		t.Fatalf("not a JKS truststore: %q", data[:min(len(data), 16)])
	}
	body, sum := data[:len(data)-sha1.Size], data[len(data)-sha1.Size:]
	digest := sha1.New()
	for _, c := range password {
		digest.Write([]byte{byte(c >> 8), byte(c)})
	}
	digest.Write([]byte("Mighty Aphrodite"))
	digest.Write(body)
	if !bytes.Equal(digest.Sum(nil), sum) {
		t.Fatal("JKS integrity digest mismatch")
	}
	return int(binary.BigEndian.Uint32(data[8:]))
}

func pushJavaTestImage(t *testing.T, store oras.Target, env []string) ocispec.Descriptor {
	t.Helper()
	publicCA := newTestCACert(t, "Public Root CA")
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: publicCA.Raw}))
	base := buildTestTar(t,
		tarDir("etc/"), tarDir("etc/ssl/"), tarDir("etc/ssl/certs/"), tarDir("etc/ssl/certs/java/"),
		tarFile("etc/ssl/certs/ca-certificates.crt", publicPEM),
		tarFile("etc/ssl/certs/java/cacerts", "distro-jks"),
		// distro JDK linking to the distro truststore
		tarDir("usr/"), tarDir("usr/lib/"), tarDir("usr/lib/jvm/"), tarDir("usr/lib/jvm/java-21/"),
		tarDir("usr/lib/jvm/java-21/lib/"), tarDir("usr/lib/jvm/java-21/lib/security/"),
		tarSymlink("usr/lib/jvm/java-21/lib/security/cacerts", "/etc/ssl/certs/java/cacerts"),
		// JDK with its own truststore (e.g. eclipse-temurin)
		tarDir("opt/"), tarDir("opt/java/"), tarDir("opt/java/openjdk/"), tarDir("opt/java/openjdk/lib/"),
		tarDir("opt/java/openjdk/lib/security/"),
		tarFile("opt/java/openjdk/lib/security/cacerts", "jdk-pkcs12"),
	)
	desc := pushTestImageWithEnv(t, store, env, base)
	return desc
}

func TestCopyPatchedImageJava(t *testing.T) {
	ctx := context.Background()
	cert := newTestCACert(t, "Corp Root CA")

	tests := []struct {
		name        string
		mode        JavaTruststoreMode
		env         []string
		wantStores  []string
		wantOptions string
		password    string
	}{
		{
			name:       "replace",
			mode:       JavaTruststoreReplace,
			wantStores: []string{"etc/ssl/certs/java/cacerts", "opt/java/openjdk/lib/security/cacerts"},
			password:   "changeit",
		},
		{
			name:        "env",
			mode:        JavaTruststoreEnv,
			env:         []string{"JAVA_TOOL_OPTIONS=-Xmx1g"},
			wantStores:  []string{"etc/ssl/certs/java/ocisync-corp-ca.jks"},
			wantOptions: "-Xmx1g -Djavax.net.ssl.trustStore=/etc/ssl/certs/java/ocisync-corp-ca.jks -Djavax.net.ssl.trustStoreType=JKS -Djavax.net.ssl.trustStorePassword=changeit",
			password:    "changeit",
		},
		{
			name:        "env with truststore configured by the image",
			mode:        JavaTruststoreEnv,
			env:         []string{"JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/opt/java/openjdk/lib/security/cacerts -Djavax.net.ssl.trustStorePassword=secret"},
			wantStores:  []string{"opt/java/openjdk/lib/security/cacerts"},
			wantOptions: "-Djavax.net.ssl.trustStore=/opt/java/openjdk/lib/security/cacerts -Djavax.net.ssl.trustStorePassword=secret",
			password:    "secret",
		},
		{
			name: "none",
			mode: JavaTruststoreNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := memory.New(), memory.New()
			desc := pushJavaTestImage(t, src, tt.env)
			if err := src.Tag(ctx, desc, "21"); err != nil {
				t.Fatal(err)
			}
			set := newTestPatchSet(t, &CACertificatesPatchConfig{Java: tt.mode, certificates: []*x509.Certificate{cert}})
			if err := copyPatchedImage(ctx, src, "21", dst, "21", set, "example.com/java:21"); err != nil {
				t.Fatal(err)
			}

			patched, err := dst.Resolve(ctx, "21")
			if err != nil {
				t.Fatal(err)
			}
			var manifest ocispec.Manifest
			fetchJSON(t, dst, patched, &manifest)
			layerData, err := content.FetchAll(ctx, dst, manifest.Layers[len(manifest.Layers)-1])
			if err != nil {
				t.Fatal(err)
			}
			files := readTarFiles(t, layerData)

			var stores []string
			for name, entry := range files {
				if strings.HasPrefix(entry.content, "\xfe\xed\xfe\xed") {
					stores = append(stores, name)
					// public root from the image bundle plus the corp CA
					if n := jksEntryCount(t, []byte(entry.content), tt.password); n != 2 {
						t.Errorf("%s has %d entries, want 2", name, n)
					}
				}
			}
			slices.Sort(stores)
			if !slices.Equal(stores, tt.wantStores) {
				t.Errorf("truststores = %v, want %v", stores, tt.wantStores)
			}
			if _, ok := files["usr/lib/jvm/java-21/lib/security/cacerts"]; ok {
				t.Error("symlinked JDK truststore must not be replaced")
			}

			var cfg map[string]any
			fetchJSON(t, dst, manifest.Config, &cfg)
			options := ""
			for _, entry := range cfg["config"].(map[string]any)["Env"].([]any) {
				if value, ok := strings.CutPrefix(entry.(string), "JAVA_TOOL_OPTIONS="); ok {
					options = value
				}
			}
			if options != tt.wantOptions {
				t.Errorf("JAVA_TOOL_OPTIONS = %q, want %q", options, tt.wantOptions)
			}
		})
	}
}
