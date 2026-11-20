package ocisync

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"

	// maxKeptFileSize limits the size of files whose content is kept in memory during the layer scan.
	maxKeptFileSize = 32 << 20
	// maxSymlinkHops limits symlink resolution, like the kernel's ELOOP limit.
	maxSymlinkHops = 40
)

// layerModTime is used for all entries of generated layers so that the same patch produces the same layer digest.
var layerModTime = time.Unix(0, 0).UTC()

var errLayerZstd = errors.New("zstd compressed layers are not supported for patching")

// fsNode is the merged state of a single path of an image filesystem.
type fsNode struct {
	typ      byte // tar type flag; tar.TypeReg for regular files and hardlinks
	linkname string
	hardlink bool // regular file that was a hardlink to linkname in its layer
	mode     int64
	uid, gid int
	layer    int // index of the layer that provided this entry, -1 for implicit directories and written files
	content  []byte
	kept     bool // content holds the file content
}

func (n *fsNode) isDir() bool {
	return n.typ == tar.TypeDir
}

func (n *fsNode) isRegular() bool {
	return n.typ == tar.TypeReg
}

// imageFS is a read-only, merged view of the layers of an image with a write overlay. Only metadata is kept for all
// entries; content is kept for files selected by keep and read lazily from the layer for all others.
type imageFS struct {
	nodes   map[string]*fsNode
	overlay map[string]*fsNode
	layers  []ocispec.Descriptor
	fetch   func(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error)
	keep    func(name string) bool
}

func newImageFS(fetch func(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error), keep func(name string) bool) *imageFS {
	if keep == nil {
		keep = func(string) bool { return false }
	}
	return &imageFS{
		nodes:   map[string]*fsNode{"": {typ: tar.TypeDir, mode: 0o755, layer: -1}},
		overlay: map[string]*fsNode{},
		fetch:   fetch,
		keep:    keep,
	}
}

// cleanFSPath returns the path relative to the image root without leading slash; "" is the root.
func cleanFSPath(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// openLayer returns a reader for the uncompressed tar stream of a layer, detecting the compression by its magic bytes.
func openLayer(r io.Reader) (io.Reader, func() error, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, err
	}
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		return gz, gz.Close, nil
	case len(magic) == 4 && bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return nil, nil, errLayerZstd
	default:
		return br, func() error { return nil }, nil
	}
}

// addLayer merges the next layer (in order, bottom to top) into the filesystem view. r is the layer blob as stored in
// the registry (compressed or not). The caller must make sure the remaining content of r is consumed if needed.
func (f *imageFS) addLayer(layerIndex int, r io.Reader) error {
	tarStream, closeFn, err := openLayer(r)
	if err != nil {
		return err
	}
	defer closeFn()

	type layerEntry struct {
		name string
		node *fsNode
	}
	var (
		entries   []layerEntry
		current   = map[string]*fsNode{}
		whiteouts []string
		opaques   []string
	)

	tr := tar.NewReader(tarStream)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read layer %d: %w", layerIndex, err)
		}

		name := cleanFSPath(header.Name)
		if name == "" {
			continue
		}
		dir, base := path.Dir(name), path.Base(name)
		if dir == "." {
			dir = ""
		}
		if base == whiteoutOpaque {
			opaques = append(opaques, dir)
			continue
		}
		if strings.HasPrefix(base, whiteoutPrefix) {
			whiteouts = append(whiteouts, cleanFSPath(path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))))
			continue
		}

		node := &fsNode{typ: header.Typeflag, mode: header.Mode, uid: header.Uid, gid: header.Gid, layer: layerIndex}
		switch header.Typeflag {
		case tar.TypeReg:
			if f.keep(name) && header.Size <= maxKeptFileSize {
				data, err := io.ReadAll(tr)
				if err != nil {
					return fmt.Errorf("read %s from layer %d: %w", name, layerIndex, err)
				}
				node.content, node.kept = data, true
			}
		case tar.TypeLink:
			node.typ = tar.TypeReg
			node.hardlink = true
			node.linkname = cleanFSPath(header.Linkname)
			target := current[node.linkname]
			if target == nil {
				target = f.nodes[node.linkname]
			}
			if target != nil && target.kept {
				node.content, node.kept = target.content, true
			}
		case tar.TypeSymlink:
			node.linkname = header.Linkname
		}

		current[name] = node
		entries = append(entries, layerEntry{name: name, node: node})
	}

	// whiteouts only hide entries of lower layers, so they are applied before the entries of this layer
	for _, dir := range opaques {
		f.removeChildren(dir)
	}
	for _, name := range whiteouts {
		f.removeTree(name)
	}
	for _, entry := range entries {
		if previous, ok := f.nodes[entry.name]; ok && previous.isDir() && !entry.node.isDir() {
			// a file or symlink replacing a directory hides everything below it
			f.removeChildren(entry.name)
		}
		f.nodes[entry.name] = entry.node
		f.addImplicitParents(entry.name)
	}

	return nil
}

func (f *imageFS) addImplicitParents(name string) {
	for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if _, ok := f.nodes[dir]; ok {
			return
		}
		f.nodes[dir] = &fsNode{typ: tar.TypeDir, mode: 0o755, layer: -1}
	}
}

func (f *imageFS) removeTree(name string) {
	delete(f.nodes, name)
	f.removeChildren(name)
}

func (f *imageFS) removeChildren(dir string) {
	prefix := dir + "/"
	if dir == "" {
		prefix = ""
	}
	for name := range f.nodes {
		if name != "" && name != dir && strings.HasPrefix(name, prefix) {
			delete(f.nodes, name)
		}
	}
}

func (f *imageFS) lookup(name string) *fsNode {
	if node, ok := f.overlay[name]; ok {
		return node
	}
	return f.nodes[name]
}

// resolve follows all symlinks of p within the image root. It returns the resolved path and its node; the node is nil
// if the path does not exist, in which case the missing components are appended to the resolved existing prefix.
func (f *imageFS) resolve(p string) (string, *fsNode, error) {
	parts := splitFSPath(cleanFSPath(p))
	resolved := ""
	hops := 0
	for i := 0; i < len(parts); i++ {
		next := cleanFSPath(path.Join(resolved, parts[i]))
		node := f.lookup(next)
		if node == nil {
			return cleanFSPath(path.Join(append([]string{resolved}, parts[i:]...)...)), nil, nil
		}
		if node.typ == tar.TypeSymlink {
			hops++
			if hops > maxSymlinkHops {
				return "", nil, fmt.Errorf("resolve %s: too many levels of symbolic links", p)
			}
			base := resolved
			if path.IsAbs(node.linkname) {
				base = ""
			}
			parts = append(splitFSPath(cleanFSPath(path.Join(base, node.linkname))), parts[i+1:]...)
			resolved = ""
			i = -1
			continue
		}
		if !node.isDir() && i < len(parts)-1 {
			// a non-directory in the middle of the path
			return "", nil, nil
		}
		resolved = next
	}
	return resolved, f.lookup(resolved), nil
}

func splitFSPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// ReadFile returns the content of the regular file at the resolved path name.
func (f *imageFS) ReadFile(ctx context.Context, name string) ([]byte, error) {
	node := f.lookup(name)
	if node == nil || !node.isRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if node.kept {
		return node.content, nil
	}
	if node.layer < 0 || node.layer >= len(f.layers) {
		return nil, fmt.Errorf("%s: unknown source layer", name)
	}

	wanted := name
	if node.hardlink {
		wanted = node.linkname
	}
	data, err := f.readFromLayer(ctx, node.layer, wanted)
	if err != nil {
		return nil, err
	}
	node.content, node.kept = data, true
	return data, nil
}

// readFromLayer reads a single file from a layer, following hardlinks within the layer.
func (f *imageFS) readFromLayer(ctx context.Context, layerIndex int, name string) ([]byte, error) {
	rc, err := f.fetch(ctx, f.layers[layerIndex])
	if err != nil {
		return nil, fmt.Errorf("fetch layer %s: %w", f.layers[layerIndex].Digest, err)
	}
	defer rc.Close()

	tarStream, closeFn, err := openLayer(rc)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	contents := map[string][]byte{}
	tr := tar.NewReader(tarStream)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read layer %d: %w", layerIndex, err)
		}
		entryName := cleanFSPath(header.Name)
		switch header.Typeflag {
		case tar.TypeReg:
			if header.Size > maxKeptFileSize {
				if entryName == name {
					return nil, fmt.Errorf("%s is too large (%d bytes)", name, header.Size)
				}
				continue
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			if entryName == name {
				return data, nil
			}
			// hardlinks always point to earlier entries of the same layer, keep small files around for them
			contents[entryName] = data
		case tar.TypeLink:
			if entryName == name {
				if data, ok := contents[cleanFSPath(header.Linkname)]; ok {
					return data, nil
				}
				return nil, fmt.Errorf("%s: hardlink target %s not found in layer", name, header.Linkname)
			}
		}
	}
	return nil, fmt.Errorf("%s not found in layer %d", name, layerIndex)
}

// find returns the sorted paths of all entries of the image (excluding written files) that match.
func (f *imageFS) find(match func(name string) bool) []string {
	var names []string
	for name := range f.nodes {
		if name != "" && match(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// WriteFile adds or replaces a regular file at the resolved path name in the overlay.
func (f *imageFS) WriteFile(name string, data []byte, mode int64, uid, gid int) {
	f.overlay[cleanFSPath(name)] = &fsNode{typ: tar.TypeReg, mode: mode, uid: uid, gid: gid, layer: -1, content: data, kept: true}
}

// changed reports whether files were written to the overlay.
func (f *imageFS) changed() bool {
	return len(f.overlay) > 0
}

// buildLayer returns an uncompressed tar with all written files plus the parent directories missing in the image.
// The output is deterministic for the same input.
func (f *imageFS) buildLayer() ([]byte, error) {
	names := make([]string, 0, len(f.overlay))
	for name := range f.overlay {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	createdDirs := map[string]bool{}
	for _, name := range names {
		var missing []string
		for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if node := f.nodes[dir]; (node != nil && node.isDir()) || createdDirs[dir] {
				break
			}
			missing = append(missing, dir)
		}
		for i := len(missing) - 1; i >= 0; i-- {
			createdDirs[missing[i]] = true
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     missing[i] + "/",
				Mode:     0o755,
				ModTime:  layerModTime,
			}); err != nil {
				return nil, err
			}
		}

		node := f.overlay[name]
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     node.mode,
			Uid:      node.uid,
			Gid:      node.gid,
			Size:     int64(len(node.content)),
			ModTime:  layerModTime,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(node.content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
