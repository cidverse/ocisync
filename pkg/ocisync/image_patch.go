package ocisync

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
)

const (
	dockerManifestMediaType     = "application/vnd.docker.distribution.manifest.v2+json"
	dockerManifestListMediaType = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerConfigMediaType       = "application/vnd.docker.container.image.v1+json"
	dockerLayerGzipMediaType    = "application/vnd.docker.image.rootfs.diff.tar.gzip"

	// patchFingerprintLabel is set on the config of every patched image. It identifies the applied patches, so that
	// IfNotPresent re-syncs a tag once the patch configuration (e.g. the certificates) changes.
	patchFingerprintLabel = "io.cidverse.ocisync.patch.fingerprint"
	patchNamesLabel       = "io.cidverse.ocisync.patch.names"

	// patchFormatVersion is part of the fingerprint; bump it when the patch output changes, to re-patch existing images.
	patchFormatVersion = 1
)

// errNotPatchable is returned for manifests that are not linux container images; inside an index they are copied as-is.
var errNotPatchable = errors.New("not a patchable linux container image")

// imagePatch modifies the filesystem and config of a container image.
type imagePatch interface {
	Name() string
	// Fingerprint returns a value that changes whenever the output of the patch would change.
	Fingerprint() any
	// Apply writes the changed files into fsys and updates the image config.
	Apply(ctx context.Context, fsys *imageFS, cfg *imageConfigFile) error
	// KeepFile reports whether the content of a file should be kept in memory during the layer scan.
	KeepFile(name string) bool
}

// imagePatchSet is the ordered list of patches configured for an image.
type imagePatchSet struct {
	patches     []imagePatch
	fingerprint string
	logger      *slog.Logger
}

func newImagePatchSet(patches []imagePatch, logger *slog.Logger) (*imagePatchSet, error) {
	if len(patches) == 0 {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	type fingerprintEntry struct {
		Name  string `json:"name"`
		Patch any    `json:"patch"`
	}
	entries := make([]fingerprintEntry, 0, len(patches))
	for _, patch := range patches {
		entries = append(entries, fingerprintEntry{Name: patch.Name(), Patch: patch.Fingerprint()})
	}
	data, err := json.Marshal(struct {
		Version int                `json:"version"`
		Patches []fingerprintEntry `json:"patches"`
	}{Version: patchFormatVersion, Patches: entries})
	if err != nil {
		return nil, fmt.Errorf("compute patch fingerprint: %w", err)
	}
	sum := sha256.Sum256(data)

	return &imagePatchSet{
		patches:     patches,
		fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		logger:      logger,
	}, nil
}

func (s *imagePatchSet) names() string {
	if s == nil {
		return ""
	}
	names := make([]string, 0, len(s.patches))
	for _, patch := range s.patches {
		names = append(names, patch.Name())
	}
	return strings.Join(names, ",")
}

func (s *imagePatchSet) keepFile(name string) bool {
	for _, patch := range s.patches {
		if patch.KeepFile(name) {
			return true
		}
	}
	return false
}

// imagePatcher copies an image from src to dst while applying the patches to every linux image manifest.
type imagePatcher struct {
	src       oras.ReadOnlyTarget
	dst       oras.Target
	set       *imagePatchSet
	sourceRef string
}

// copyPatchedImage copies srcRef from src to dst as dstTag, applying the patch set to the image (all platforms of an
// index). Unchanged blobs are streamed to the target while they are scanned, so every layer is downloaded only once.
func copyPatchedImage(ctx context.Context, src oras.ReadOnlyTarget, srcRef string, dst oras.Target, dstTag string, set *imagePatchSet, sourceRef string) error {
	root, err := src.Resolve(ctx, srcRef)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", sourceRef, err)
	}

	p := &imagePatcher{src: src, dst: dst, set: set, sourceRef: sourceRef}
	var patched ocispec.Descriptor
	switch root.MediaType {
	case ocispec.MediaTypeImageIndex, dockerManifestListMediaType:
		patched, err = p.patchIndex(ctx, root)
	case ocispec.MediaTypeImageManifest, dockerManifestMediaType:
		patched, err = p.patchManifest(ctx, root)
	default:
		err = fmt.Errorf("unsupported media type %q", root.MediaType)
	}
	if errors.Is(err, errNotPatchable) {
		return fmt.Errorf("%s: patches can only be applied to linux container images: %w", sourceRef, err)
	}
	if err != nil {
		return err
	}

	return p.pushManifest(ctx, patched, dstTag)
}

func (p *imagePatcher) patchIndex(ctx context.Context, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
	data, err := content.FetchAll(ctx, p.src, desc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetch index %s: %w", desc.Digest, err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse index %s: %w", desc.Digest, err)
	}

	manifests := make([]ocispec.Descriptor, 0, len(index.Manifests))
	patchedAny := false
	for _, child := range index.Manifests {
		if isAttestationManifest(child) {
			// attestations (provenance, sbom) reference the digest of the original image and would no longer match
			p.set.logger.Debug("dropping attestation manifest from patched index", "sourceRef", p.sourceRef, "digest", child.Digest)
			continue
		}

		if isImageManifestMediaType(child.MediaType) && (child.Platform == nil || child.Platform.OS == "" || child.Platform.OS == "linux") {
			patched, err := p.patchManifest(ctx, child)
			if err == nil {
				if err := p.pushManifest(ctx, patched, ""); err != nil {
					return ocispec.Descriptor{}, err
				}
				patched.Data = nil
				patched.Platform = child.Platform
				patched.Annotations = child.Annotations
				patched.ArtifactType = child.ArtifactType
				manifests = append(manifests, patched)
				patchedAny = true
				continue
			}
			if !errors.Is(err, errNotPatchable) {
				return ocispec.Descriptor{}, fmt.Errorf("platform %s: %w", platformString(child.Platform), err)
			}
		}

		p.set.logger.Info("copying index entry without patching", "sourceRef", p.sourceRef, "digest", child.Digest, "platform", platformString(child.Platform))
		if err := oras.CopyGraph(ctx, p.src, p.dst, child, oras.DefaultCopyGraphOptions); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("copy index entry %s: %w", child.Digest, err)
		}
		manifests = append(manifests, child)
	}
	if !patchedAny {
		return ocispec.Descriptor{}, fmt.Errorf("index %s: %w", desc.Digest, errNotPatchable)
	}

	index.Manifests = manifests
	if desc.MediaType == ocispec.MediaTypeImageIndex {
		index.Annotations = withBaseAnnotations(index.Annotations, desc.Digest, p.sourceRef)
	}
	return marshalManifest(desc.MediaType, index)
}

func (p *imagePatcher) patchManifest(ctx context.Context, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
	data, err := content.FetchAll(ctx, p.src, desc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetch manifest %s: %w", desc.Digest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse manifest %s: %w", desc.Digest, err)
	}
	if manifest.MediaType == "" {
		manifest.MediaType = desc.MediaType
	}
	if manifest.Config.MediaType != ocispec.MediaTypeImageConfig && manifest.Config.MediaType != dockerConfigMediaType {
		return ocispec.Descriptor{}, fmt.Errorf("manifest %s has config media type %q: %w", desc.Digest, manifest.Config.MediaType, errNotPatchable)
	}

	configData, err := content.FetchAll(ctx, p.src, manifest.Config)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetch image config %s: %w", manifest.Config.Digest, err)
	}
	cfg, err := parseImageConfig(configData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse image config %s: %w", manifest.Config.Digest, err)
	}
	if osName := cfg.OS(); osName != "" && osName != "linux" {
		return ocispec.Descriptor{}, fmt.Errorf("image os %q: %w", osName, errNotPatchable)
	}
	for _, layer := range manifest.Layers {
		if len(layer.URLs) > 0 {
			return ocispec.Descriptor{}, fmt.Errorf("layer %s is a foreign layer: %w", layer.Digest, errNotPatchable)
		}
	}

	fsys := newImageFS(p.src.Fetch, p.set.keepFile)
	fsys.layers = manifest.Layers
	for i, layer := range manifest.Layers {
		if err := p.scanAndCopyLayer(ctx, fsys, i, layer); err != nil {
			return ocispec.Descriptor{}, err
		}
	}

	for _, patch := range p.set.patches {
		if err := patch.Apply(ctx, fsys, cfg); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("patch %s: %w", patch.Name(), err)
		}
	}

	createdBy := "ocisync patch: " + p.set.names()
	if fsys.changed() {
		layerTar, err := fsys.buildLayer()
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("build patch layer: %w", err)
		}
		layerData, err := gzipBytes(layerTar)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("compress patch layer: %w", err)
		}
		layerMediaType := ocispec.MediaTypeImageLayerGzip
		if manifest.MediaType == dockerManifestMediaType {
			layerMediaType = dockerLayerGzipMediaType
		}
		layerDesc := content.NewDescriptorFromBytes(layerMediaType, layerData)
		if err := p.pushBlob(ctx, layerDesc, layerData); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("push patch layer: %w", err)
		}
		manifest.Layers = append(manifest.Layers, layerDesc)
		if err := cfg.AppendLayer(digest.FromBytes(layerTar), createdBy); err != nil {
			return ocispec.Descriptor{}, err
		}
	} else {
		cfg.AppendEmptyHistory(createdBy)
	}
	cfg.SetLabel(patchFingerprintLabel, p.set.fingerprint)
	cfg.SetLabel(patchNamesLabel, p.set.names())

	newConfig, err := cfg.Marshal()
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal image config: %w", err)
	}
	configDesc := content.NewDescriptorFromBytes(manifest.Config.MediaType, newConfig)
	if err := p.pushBlob(ctx, configDesc, newConfig); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push image config: %w", err)
	}
	manifest.Config = configDesc

	if manifest.MediaType == ocispec.MediaTypeImageManifest {
		manifest.Annotations = withBaseAnnotations(manifest.Annotations, desc.Digest, p.sourceRef)
	}
	return marshalManifest(manifest.MediaType, manifest)
}

// scanAndCopyLayer adds a source layer to the filesystem view. If the target does not have the blob yet, it is pushed
// from the same stream, so the layer is only downloaded once.
func (p *imagePatcher) scanAndCopyLayer(ctx context.Context, fsys *imageFS, index int, layer ocispec.Descriptor) error {
	exists, err := p.dst.Exists(ctx, layer)
	if err != nil {
		return fmt.Errorf("check layer %s in target: %w", layer.Digest, err)
	}

	rc, err := p.src.Fetch(ctx, layer)
	if err != nil {
		return fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
	}
	defer rc.Close()

	if exists {
		if err := fsys.addLayer(index, rc); err != nil {
			return fmt.Errorf("scan layer %s: %w", layer.Digest, err)
		}
		return nil
	}

	pr, pw := io.Pipe()
	pushDone := make(chan error, 1)
	go func() {
		err := p.dst.Push(ctx, layer, pr)
		if errors.Is(err, errdef.ErrAlreadyExists) {
			err = nil
		}
		// unblock the writer if the push ended early
		_ = pr.CloseWithError(errors.Join(err, io.ErrClosedPipe))
		pushDone <- err
	}()

	tee := io.TeeReader(rc, pw)
	scanErr := fsys.addLayer(index, tee)
	if scanErr == nil {
		// the tar reader stops at the end-of-archive marker, push the remaining bytes (padding) as well
		_, scanErr = io.Copy(io.Discard, tee)
	}
	_ = pw.CloseWithError(scanErr)
	pushErr := <-pushDone

	if scanErr != nil || pushErr != nil {
		return fmt.Errorf("scan and copy layer %s: %w", layer.Digest, errors.Join(scanErr, pushErr))
	}
	return nil
}

func (p *imagePatcher) pushBlob(ctx context.Context, desc ocispec.Descriptor, data []byte) error {
	exists, err := p.dst.Exists(ctx, desc)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := p.dst.Push(ctx, desc, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return err
	}
	return nil
}

// pushManifest pushes a manifest or index produced by marshalManifest and tags it if tag is set.
func (p *imagePatcher) pushManifest(ctx context.Context, desc ocispec.Descriptor, tag string) error {
	data := desc.Data
	desc.Data = nil
	if tag == "" {
		if err := p.pushBlob(ctx, desc, data); err != nil {
			return fmt.Errorf("push manifest %s: %w", desc.Digest, err)
		}
		return nil
	}

	if pusher, ok := p.dst.(registry.ReferencePusher); ok {
		if err := pusher.PushReference(ctx, desc, bytes.NewReader(data), tag); err != nil {
			return fmt.Errorf("push manifest %s as %s: %w", desc.Digest, tag, err)
		}
		return nil
	}
	if err := p.pushBlob(ctx, desc, data); err != nil {
		return fmt.Errorf("push manifest %s: %w", desc.Digest, err)
	}
	if err := p.dst.Tag(ctx, desc, tag); err != nil {
		return fmt.Errorf("tag manifest %s as %s: %w", desc.Digest, tag, err)
	}
	return nil
}

// marshalManifest encodes a manifest or index. The returned descriptor carries the encoded content in Data.
func marshalManifest(mediaType string, manifest any) (ocispec.Descriptor, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	desc := content.NewDescriptorFromBytes(mediaType, data)
	desc.Data = data
	return desc, nil
}

func withBaseAnnotations(annotations map[string]string, base digest.Digest, baseName string) map[string]string {
	out := make(map[string]string, len(annotations)+2)
	for k, v := range annotations {
		out[k] = v
	}
	out[ocispec.AnnotationBaseImageDigest] = base.String()
	out[ocispec.AnnotationBaseImageName] = baseName
	return out
}

func isImageManifestMediaType(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageManifest || mediaType == dockerManifestMediaType
}

func isAttestationManifest(desc ocispec.Descriptor) bool {
	return desc.Annotations["vnd.docker.reference.type"] == "attestation-manifest"
}

func platformString(platform *ocispec.Platform) string {
	if platform == nil {
		return "unknown"
	}
	s := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		s += "/" + platform.Variant
	}
	return s
}

func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf) // no name and no mtime in the header, the output is deterministic
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// imageConfigFile is an image config (OCI or Docker) that keeps all unknown fields when modified.
type imageConfigFile struct {
	raw map[string]any
}

func parseImageConfig(data []byte) (*imageConfigFile, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	if raw == nil {
		raw = map[string]any{}
	}
	return &imageConfigFile{raw: raw}, nil
}

func (c *imageConfigFile) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(c.raw); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func (c *imageConfigFile) OS() string {
	osName, _ := c.raw["os"].(string)
	return osName
}

func (c *imageConfigFile) runtimeConfig() map[string]any {
	runtime, ok := c.raw["config"].(map[string]any)
	if !ok {
		runtime = map[string]any{}
		c.raw["config"] = runtime
	}
	return runtime
}

// Env returns the value of an environment variable of the image config.
func (c *imageConfigFile) Env(key string) (string, bool) {
	env, _ := c.runtimeConfig()["Env"].([]any)
	for _, entry := range env {
		if s, ok := entry.(string); ok {
			if k, v, found := strings.Cut(s, "="); found && k == key {
				return v, true
			}
		}
	}
	return "", false
}

// SetEnv sets an environment variable, replacing an existing value.
func (c *imageConfigFile) SetEnv(key, value string) {
	runtime := c.runtimeConfig()
	env, _ := runtime["Env"].([]any)
	entry := key + "=" + value
	for i, existing := range env {
		if s, ok := existing.(string); ok && strings.HasPrefix(s, key+"=") {
			env[i] = entry
			runtime["Env"] = env
			return
		}
	}
	runtime["Env"] = append(env, entry)
}

func (c *imageConfigFile) SetLabel(key, value string) {
	runtime := c.runtimeConfig()
	labels, ok := runtime["Labels"].(map[string]any)
	if !ok {
		labels = map[string]any{}
		runtime["Labels"] = labels
	}
	labels[key] = value
}

// Label returns a label of the image config.
func (c *imageConfigFile) Label(key string) string {
	labels, _ := c.runtimeConfig()["Labels"].(map[string]any)
	value, _ := labels[key].(string)
	return value
}

// AppendLayer registers a new top layer by its uncompressed digest and adds a matching history entry.
func (c *imageConfigFile) AppendLayer(diffID digest.Digest, createdBy string) error {
	rootfs, ok := c.raw["rootfs"].(map[string]any)
	if !ok {
		return fmt.Errorf("image config has no rootfs")
	}
	diffIDs, _ := rootfs["diff_ids"].([]any)
	rootfs["diff_ids"] = append(diffIDs, diffID.String())
	c.appendHistory(map[string]any{"created_by": createdBy, "comment": "added by ocisync"})
	return nil
}

// AppendEmptyHistory records a config-only change in the history.
func (c *imageConfigFile) AppendEmptyHistory(createdBy string) {
	c.appendHistory(map[string]any{"created_by": createdBy, "comment": "added by ocisync", "empty_layer": true})
}

func (c *imageConfigFile) appendHistory(entry map[string]any) {
	// history is optional; only extend it when present, as its non-empty entries must match the layers
	history, ok := c.raw["history"].([]any)
	if !ok {
		return
	}
	c.raw["history"] = append(history, entry)
}

// patchFingerprintOf returns the patch fingerprint label of an image in target, or "" if the image is not patched.
// For an index, the first image manifest is inspected: all platforms are patched with the same patch set.
func patchFingerprintOf(ctx context.Context, target oras.ReadOnlyTarget, tag string) (string, error) {
	desc, err := target.Resolve(ctx, tag)
	if err != nil {
		return "", err
	}

	if desc.MediaType == ocispec.MediaTypeImageIndex || desc.MediaType == dockerManifestListMediaType {
		data, err := content.FetchAll(ctx, target, desc)
		if err != nil {
			return "", err
		}
		var index ocispec.Index
		if err := json.Unmarshal(data, &index); err != nil {
			return "", err
		}
		found := false
		for _, child := range index.Manifests {
			if isImageManifestMediaType(child.MediaType) && !isAttestationManifest(child) &&
				(child.Platform == nil || child.Platform.OS == "" || child.Platform.OS == "linux") {
				desc, found = child, true
				break
			}
		}
		if !found {
			return "", nil
		}
	}
	if !isImageManifestMediaType(desc.MediaType) {
		return "", nil
	}

	data, err := content.FetchAll(ctx, target, desc)
	if err != nil {
		return "", err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", err
	}
	configData, err := content.FetchAll(ctx, target, manifest.Config)
	if err != nil {
		return "", err
	}
	cfg, err := parseImageConfig(configData)
	if err != nil {
		return "", err
	}
	return cfg.Label(patchFingerprintLabel), nil
}
