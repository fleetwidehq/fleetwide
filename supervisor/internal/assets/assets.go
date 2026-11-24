// Package assets delivers files next to a release: model weights, prompt
// bundles, configs, static content. Each asset is fetched from an OCI
// registry, an object URL or a git host, verified against its pinned digest,
// unpacked into <unpack_to>/<name>/.versions/<key> and made live by an atomic
// symlink switch of <unpack_to>/<name>/current. Older versions stay for
// rollback (keep-last-2) and the layer cache keeps blobs so a re-sync after a
// restart costs nothing.
package assets

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/fsinfo"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/klauspost/compress/zstd"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/progress"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

// Options for Sync.
type Options struct {
	Cache    *layercache.Cache
	Log      func(string, ...any)
	HTTP     *http.Client
	Progress progress.Reporter // optional: reports bytes while an asset downloads
}

// Result is the outcome for one asset.
type Result struct {
	Name    string
	From    string // deliverable key the asset came from
	Digest  string
	Path    string // <unpack_to>/<name>/current
	Changed bool   // a new version went live
	Staged  bool   // a new version is unpacked and ready to switch (Stage only)
	Err     error
}

// Sync brings every asset to its pinned version. Assets already live are
// skipped without network access. It returns one Result per asset and an
// error when any asset failed (the others are still applied).
func Sync(ctx context.Context, list []v1.Asset, o Options) ([]Result, error) {
	o = o.withDefaults()
	var out []Result
	var firstErr error
	for _, a := range list {
		r := stageOne(ctx, a, o)
		if r.Err == nil {
			r = activateOne(a, o)
		}
		if r.Err != nil && firstErr == nil {
			firstErr = fmt.Errorf("asset %s: %w", a.Name, r.Err)
		}
		out = append(out, r)
	}
	return out, firstErr
}

// Stage fetches and unpacks every asset's pinned version next to the live
// one without switching anything. Safe to call repeatedly; already staged or
// live versions cost nothing.
func Stage(ctx context.Context, list []v1.Asset, o Options) ([]Result, error) {
	o = o.withDefaults()
	var out []Result
	var firstErr error
	for _, a := range list {
		r := stageOne(ctx, a, o)
		if r.Err != nil && firstErr == nil {
			firstErr = fmt.Errorf("asset %s: %w", a.Name, r.Err)
		}
		out = append(out, r)
	}
	return out, firstErr
}

// Activate switches each asset's `current` to its (staged) pinned version.
func Activate(list []v1.Asset, o Options) []Result {
	o = o.withDefaults()
	var out []Result
	for _, a := range list {
		out = append(out, activateOne(a, o))
	}
	return out
}

func (o Options) withDefaults() Options {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 0}
	}
	return o
}

// Key is the version directory name for an asset's pinned content.
func Key(a v1.Asset) string {
	d := strings.TrimPrefix(a.Digest, "sha256:")
	if len(d) > 16 {
		d = d[:16]
	}
	return d
}

// Current returns the digest key currently live for an asset ("" when none).
func Current(a v1.Asset) string {
	link, err := os.Readlink(filepath.Join(a.UnpackTo, a.Name, "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

// stageOne makes sure the pinned version is unpacked under .versions/<key>.
func stageOne(ctx context.Context, a v1.Asset, o Options) Result {
	base := filepath.Join(a.UnpackTo, a.Name)
	res := Result{Name: a.Name, From: a.From, Digest: a.Digest, Path: filepath.Join(base, "current")}
	key := Key(a)
	if key == "" {
		res.Err = errors.New("no digest pinned")
		return res
	}
	if Current(a) == key {
		return res // already live
	}
	versions := filepath.Join(base, ".versions")
	final := filepath.Join(versions, key)
	if _, err := os.Stat(final); err == nil {
		res.Staged = true
		return res
	}
	if err := os.MkdirAll(versions, 0o755); err != nil {
		res.Err = err
		return res
	}
	staging, err := os.MkdirTemp(versions, ".staging-"+key+"-")
	if err != nil {
		res.Err = err
		return res
	}
	start := time.Now()
	if a.Size > 0 {
		if err := checkSpace(versions, a.Size*2); err != nil {
			os.RemoveAll(staging)
			res.Err = err
			return res
		}
	}
	var ferr error
	if o.Progress != nil {
		o.Progress.Begin("asset", a.Name, a.Size)
	}
	switch a.Source {
	case "oci":
		ferr = fetchOCI(ctx, a, staging, o)
	case "object":
		ferr = fetchObject(ctx, a, staging, o)
	case "git":
		ferr = fetchGit(ctx, a, staging, o)
	default:
		ferr = fmt.Errorf("unknown source %q", a.Source)
	}
	if o.Progress != nil {
		o.Progress.End()
	}
	if ferr != nil {
		os.RemoveAll(staging)
		res.Err = ferr
		return res
	}
	if err := os.Chmod(staging, 0o755); err == nil {
		if err := os.Rename(staging, final); err != nil {
			os.RemoveAll(staging)
			if _, e2 := os.Stat(final); e2 != nil { // lost a race: fine when final exists
				res.Err = err
				return res
			}
		}
	}
	o.Log("asset %s: %s fetched and unpacked in %s", a.Name, shortDigest(a.Digest), time.Since(start).Round(time.Millisecond))
	res.Staged = true
	return res
}

// activateOne switches `current` to the pinned version (staged beforehand).
func activateOne(a v1.Asset, o Options) Result {
	base := filepath.Join(a.UnpackTo, a.Name)
	res := Result{Name: a.Name, From: a.From, Digest: a.Digest, Path: filepath.Join(base, "current")}
	key := Key(a)
	if key == "" {
		res.Err = errors.New("no digest pinned")
		return res
	}
	if Current(a) == key {
		return res
	}
	versions := filepath.Join(base, ".versions")
	if _, err := os.Stat(filepath.Join(versions, key)); err != nil {
		res.Err = fmt.Errorf("version %s is not staged", key)
		return res
	}
	tmp := filepath.Join(base, ".current.tmp")
	os.Remove(tmp)
	if err := os.Symlink(filepath.Join(".versions", key), tmp); err != nil {
		res.Err = err
		return res
	}
	if err := os.Rename(tmp, res.Path); err != nil {
		os.Remove(tmp)
		res.Err = err
		return res
	}
	res.Changed = true
	prune(versions, key, 2, o)
	return res
}

// prune keeps the live version plus the `keep` most recent others.
func prune(versions, live string, keep int, o Options) {
	ents, err := os.ReadDir(versions)
	if err != nil {
		return
	}
	type ent struct {
		name string
		mod  time.Time
	}
	var others []ent
	for _, e := range ents {
		if e.Name() == live || !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".staging-") {
			os.RemoveAll(filepath.Join(versions, e.Name()))
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		others = append(others, ent{e.Name(), info.ModTime()})
	}
	sort.Slice(others, func(i, j int) bool { return others[i].mod.After(others[j].mod) })
	for i := keep; i < len(others); i++ {
		os.RemoveAll(filepath.Join(versions, others[i].name))
		o.Log("asset: pruned old version %s", others[i].name)
	}
}

func checkSpace(dir string, need int64) error {
	avail, _, ok := fsinfo.Free(dir)
	if !ok {
		return nil
	}
	free := int64(avail)
	if free < need {
		return fmt.Errorf("not enough disk space under %s: need %d MB, %d MB free", dir, need>>20, free>>20)
	}
	return nil
}

// ---- sources ----

// fetchOCI pulls every layer of an OCI artifact: tar layers are extracted,
// anything else (GGUF weights, safetensors, plain files) is written as a
// file named by its title annotation or its media type.
func fetchOCI(ctx context.Context, a v1.Asset, dst string, o Options) error {
	var nopts []name.Option
	if a.Insecure {
		nopts = append(nopts, name.Insecure)
	}
	ref, err := name.ParseReference(a.Ref, nopts...)
	if err != nil {
		return err
	}
	if !strings.Contains(a.Ref, "@sha256:") {
		ref, err = name.ParseReference(ref.Context().String()+"@"+a.Digest, nopts...)
		if err != nil {
			return err
		}
	}
	var auth *registry.Auth
	if a.Auth != nil && a.Auth.Secret != "" {
		auth = &registry.Auth{Registry: a.Auth.Registry, Username: a.Auth.Username, Secret: a.Auth.Secret, Type: a.Auth.Type, SessionToken: a.Auth.SessionToken, RoleARN: a.Auth.RoleARN, Region: a.Auth.Region}
	}
	ropts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(registry.Keychain(auth))}
	if a.SkipVerify {
		ropts = append(ropts, remote.WithTransport(registry.SkipVerifyTransport()))
	}
	desc, err := remote.Get(ref, ropts...)
	if err != nil {
		if strings.Contains(err.Error(), "MANIFEST_UNKNOWN") || strings.Contains(err.Error(), "404") {
			return fmt.Errorf("digest mismatch: the registry has no manifest %s for %s (the pinned digest does not match what is published)", shortDigest(a.Digest), a.Ref)
		}
		return fmt.Errorf("fetch %s: %w", a.Ref, err)
	}
	if desc.Digest.String() != a.Digest {
		return fmt.Errorf("digest mismatch: registry has %s, channel pins %s", desc.Digest, a.Digest)
	}
	img, err := artifactImage(desc)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	m, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for i, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return err
		}
		mt := ""
		var ann map[string]string
		if i < len(m.Layers) {
			mt, ann = string(m.Layers[i].MediaType), m.Layers[i].Annotations
		}
		if o.Cache != nil && !o.Cache.Has(d.String()) {
			rc, err := l.Compressed()
			if err != nil {
				return err
			}
			_, err = o.Cache.Put(d.String(), progress.Wrap(rc, o.Progress))
			rc.Close()
			if err != nil {
				return fmt.Errorf("layer %s: %w", d, err)
			}
		}
		var r io.ReadCloser
		if o.Cache != nil {
			f, err := o.Cache.Open(d.String())
			if err != nil {
				return err
			}
			r = f
		} else {
			rc, err := l.Compressed()
			if err != nil {
				return err
			}
			r = rc
		}
		err = func() error {
			defer r.Close()
			if strings.Contains(mt, "tar") {
				return extractLayer(r, mt, dst)
			}
			fname := ann["org.opencontainers.image.title"]
			if fname == "" {
				fname = fmt.Sprintf("layer-%d%s", i, extFor(mt))
			}
			return writeFile(dst, path.Base(fname), r)
		}()
		if err != nil {
			return fmt.Errorf("layer %s: %w", d, err)
		}
	}
	return nil
}

// artifactImage picks the manifest to deliver. An index (multi-arch image or
// buildx output with attestation manifests) yields the child for the host
// platform, else the first child that is not an attestation.
func artifactImage(desc *remote.Descriptor) (ggcrv1.Image, error) {
	if !desc.MediaType.IsIndex() {
		return desc.Image()
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	host := registry.HostPlatform()
	var first *ggcrv1.Hash
	for _, m := range im.Manifests {
		if m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		if m.Platform != nil && m.Platform.OS == host.OS && m.Platform.Architecture == host.Arch {
			h := m.Digest
			return idx.Image(h)
		}
		if first == nil {
			h := m.Digest
			first = &h
		}
	}
	if first == nil {
		return nil, errors.New("index has no deliverable manifest")
	}
	return idx.Image(*first)
}

// extractLayer decompresses an image layer by media type (falling back to
// sniffing the bytes) and extracts the tar inside.
func extractLayer(r io.Reader, mt, dst string) error {
	switch {
	case strings.Contains(mt, "zstd"):
		zr, err := zstd.NewReader(r)
		if err != nil {
			return err
		}
		defer zr.Close()
		return extractTar(zr, dst, 0)
	case strings.Contains(mt, "gzip"):
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		return extractTar(gz, dst, 0)
	}
	br := newPeekReader(r)
	head, _ := br.Peek(4)
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		return extractTar(gz, dst, 0)
	case len(head) >= 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		zr, err := zstd.NewReader(br)
		if err != nil {
			return err
		}
		defer zr.Close()
		return extractTar(zr, dst, 0)
	}
	return extractTar(br, dst, 0)
}

func extFor(mt string) string {
	switch {
	case strings.Contains(mt, "gguf"):
		return ".gguf"
	case strings.Contains(mt, "safetensors"):
		return ".safetensors"
	case strings.Contains(mt, "json"):
		return ".json"
	case strings.Contains(mt, "zip"):
		return ".zip"
	}
	return ".bin"
}

// readCloser pairs a wrapped reader with the original closer.
type readCloser struct {
	io.Reader
	io.Closer
}

// fetchObject downloads one file over HTTP(S), verifies its sha256 and unpacks
// it by content (gzip/tar/zip) or stores it as a single file.
func fetchObject(ctx context.Context, a v1.Asset, dst string, o Options) error {
	u, err := url.Parse(a.Ref)
	if err != nil {
		return err
	}
	var body io.ReadCloser
	if o.Cache != nil && o.Cache.Has(a.Digest) {
		f, err := o.Cache.Open(a.Digest)
		if err != nil {
			return err
		}
		body = f
	} else {
		rc, err := httpGet(ctx, o.HTTP, a.Ref, a.Auth)
		if err != nil {
			return err
		}
		if o.Cache != nil {
			_, err = o.Cache.Put(a.Digest, progress.Wrap(rc, o.Progress))
			rc.Close()
			if err != nil {
				return err
			}
			f, err := o.Cache.Open(a.Digest)
			if err != nil {
				return err
			}
			body = f
		} else {
			body = readCloser{progress.Wrap(rc, o.Progress), rc}
		}
	}
	defer body.Close()
	return unpackByContent(body, dst, path.Base(u.Path), 0)
}

// fetchGit downloads a commit archive from the hosting service (GitHub,
// GitLab, Gitea/Codeberg, Bitbucket) and strips the top-level directory.
func fetchGit(ctx context.Context, a v1.Asset, dst string, o Options) error {
	u, err := url.Parse(a.Ref)
	if err != nil {
		return err
	}
	commit := a.Digest
	var archive string
	switch {
	case u.Host == "github.com":
		archive = a.Ref + "/archive/" + commit + ".tar.gz"
	case strings.Contains(u.Host, "gitlab"):
		archive = a.Ref + "/-/archive/" + commit + "/archive.tar.gz"
	case u.Host == "bitbucket.org":
		archive = a.Ref + "/get/" + commit + ".tar.gz"
	default: // gitea, codeberg, forgejo
		archive = a.Ref + "/archive/" + commit + ".tar.gz"
	}
	rc, err := httpGet(ctx, o.HTTP, archive, a.Auth)
	if err != nil {
		return fmt.Errorf("git archive %s: %w", archive, err)
	}
	defer rc.Close()
	// the archive bytes are not content-addressed; integrity comes from TLS
	// and the pinned commit in the path. Record what we got for the log.
	h := sha256.New()
	if err := unpackByContent(io.TeeReader(rc, h), dst, "archive.tar.gz", 1); err != nil {
		return err
	}
	o.Log("asset %s: git %s@%s (archive sha256 %s)", a.Name, a.Ref, commit[:12], hex.EncodeToString(h.Sum(nil))[:12])
	return nil
}

func httpGet(ctx context.Context, hc *http.Client, rawURL string, auth *v1.RegistryAuth) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	if auth != nil && auth.Secret != "" {
		switch strings.ToLower(auth.Username) {
		case "", "token", "bearer", "oauth2":
			req.Header.Set("Authorization", "Bearer "+auth.Secret)
		default:
			req.SetBasicAuth(auth.Username, auth.Secret)
		}
	}
	req.Header.Set("User-Agent", "fleetwide-supervisor")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return resp.Body, nil
}

// ---- unpacking ----

// unpackByContent sniffs gzip / tar / zip; anything else is a single file.
func unpackByContent(r io.Reader, dst, filename string, strip int) error {
	br := newPeekReader(r)
	head, _ := br.Peek(512)
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		return extractTar(gz, dst, strip)
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return extractTar(br, dst, strip)
	case len(head) >= 4 && string(head[:4]) == "PK\x03\x04":
		return extractZip(br, dst, strip)
	}
	if filename == "" || filename == "/" || filename == "." {
		filename = "asset.bin"
	}
	return writeFile(dst, filename, br)
}

func writeFile(dst, name string, r io.Reader) error {
	full, err := securejoin.SecureJoin(dst, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func stripPath(p string, strip int) (string, bool) {
	p = path.Clean("/" + p)
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if strip > 0 {
		if len(parts) <= strip {
			return "", false
		}
		parts = parts[strip:]
	}
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	return path.Join(parts...), true
}

func extractTar(r io.Reader, dst string, strip int) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel, ok := stripPath(h.Name, strip)
		if !ok {
			continue
		}
		full, err := securejoin.SecureJoin(dst, rel)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(full, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(h.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode|0o400)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			// only links that stay inside the asset
			if strings.HasPrefix(h.Linkname, "/") || strings.Contains(h.Linkname, "..") {
				continue
			}
			os.MkdirAll(filepath.Dir(full), 0o755)
			os.Remove(full)
			if err := os.Symlink(h.Linkname, full); err != nil {
				return err
			}
		}
	}
}

func extractZip(r io.Reader, dst string, strip int) error {
	b, err := io.ReadAll(r) // zip needs random access; assets in zip form are small bundles
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		rel, ok := stripPath(f.Name, strip)
		if !ok {
			continue
		}
		full, err := securejoin.SecureJoin(dst, rel)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
			os.MkdirAll(full, 0o755)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		out, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// peekReader lets us sniff the first bytes and still stream the whole body.
type peekReader struct {
	r   io.Reader
	buf []byte
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) Peek(n int) ([]byte, error) {
	if len(p.buf) >= n {
		return p.buf[:n], nil
	}
	more := make([]byte, n-len(p.buf))
	k, err := io.ReadFull(p.r, more)
	p.buf = append(p.buf, more[:k]...)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return p.buf, err
	}
	return p.buf, nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}
