package fleet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/embedded"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/manifest"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/rootfs"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/supervise"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/unpack"
)

// RedeployError says a release cannot be applied to this container in place:
// it changes the image outside the sync paths, or was embedded with other
// sync paths, or is not an embedded image at all. The container needs a new
// image.
type RedeployError struct{ Reason string }

func (e *RedeployError) Error() string { return "redeploy required: " + e.Reason }

// embeddedSelfCheck reports the sync and asset paths and the state dir this
// process cannot write, with the fix: the container must run as the uid the
// image was embedded for, or with gid 0.
func (c *Controller) embeddedSelfCheck() {
	emb := c.emb
	var bad []string
	for _, p := range append(append([]string{c.cfg.StateDir}, emb.SyncPaths...), emb.AssetPaths...) {
		if unix.Access(p, unix.W_OK|unix.X_OK) != nil {
			bad = append(bad, p)
		}
	}
	who := fmt.Sprintf("uid %d gid %d", os.Getuid(), os.Getgid())
	if len(bad) == 0 {
		c.log("embedded runtime: running as %s; sync paths %s writable", who, strings.Join(emb.SyncPaths, ", "))
		return
	}
	want := emb.User
	if want == "" {
		want = "0:0"
	}
	msg := fmt.Sprintf("embedded runtime: running as %s but cannot write %s; run the container as uid %s or with gid 0 (the image was embedded for %s)", who, strings.Join(bad, ", "), strings.Split(want, ":")[0], want)
	c.log("warning: %s", msg)
	c.mu.Lock()
	c.lastErr = msg
	c.mu.Unlock()
}

// startInPlace starts the process a release shipped, with its files already
// on disk: the embedded image's own process at first start, or a synced
// release's on resume. Nothing is pulled or written.
func (c *Controller) startInPlace(rel *release, rt imagecfg.Runtime, why string) {
	c.mu.Lock()
	c.current = rel
	c.mu.Unlock()
	man := c.embeddedManifest(rel)
	c.sup.SetInfo(map[string]any{
		"release":      map[string]any{"id": rel.ReleaseID, "reference": rel.Image, "digest": rel.Digest, "platform": rel.Platform, "embedded": true},
		"supervisor":   c.cfg.SupervisorVer,
		"installation": c.installationID(),
	})
	c.sup.SetExtraEnv(rel.Env, false)
	c.log("starting %s (%s) in place: %s", rel.ReleaseID, shortDigest(rel.Digest), why)
	if err := c.sup.Deploy(rt, man, nil); err != nil {
		c.log("start failed: %v", err)
		c.mu.Lock()
		c.lastErr = err.Error()
		c.mu.Unlock()
		c.setPhase("failed")
		return
	}
	c.setPhase("running")
	c.event("embedded_start", fmt.Sprintf("running %s (%s) %s", rel.ReleaseID, shortDigest(rel.Digest), why), rel.ReleaseID)
}

// embeddedRelease is the record for the image's own embedded release.
func (c *Controller) embeddedRelease(id string) *release {
	emb := c.emb
	p := emb.Process
	return &release{ReleaseID: id, Image: emb.Image, Digest: emb.Digest, IndexDigest: emb.IndexDigest, Platform: c.cfg.Platform.String(), Process: &p, PathsFile: filepath.Join(c.cfg.StateDir, "paths", "embedded.txt")}
}

func (c *Controller) embeddedManifest(rel *release) *manifest.Manifest {
	if rel.Manifest != "" {
		if man, err := manifest.Parse([]byte(rel.Manifest), "console"); err == nil {
			return man
		}
	}
	man, err := manifest.Load("/", "")
	if err != nil {
		man = manifest.Defaults()
	}
	c.mu.Lock()
	h := c.health
	c.mu.Unlock()
	if h != nil {
		man.Health = mergeHealth(man.Health, h)
	}
	return man
}

// awaitLatestOrFallback runs on each heartbeat while a `--start latest`
// container has nothing running: past the deadline it either starts the
// embedded app (fallback) or stays down (strict) for the orchestrator.
func (c *Controller) awaitLatestOrFallback() {
	c.mu.Lock()
	deadline, cur := c.awaitLatest, c.current
	c.mu.Unlock()
	if deadline.IsZero() || cur != nil || time.Now().Before(deadline) {
		return
	}
	c.mu.Lock()
	c.awaitLatest = time.Time{}
	c.mu.Unlock()
	if c.emb.StartFallback == "strict" {
		c.log("no release assigned within %ds and --start latest is strict: nothing runs until the console answers", c.emb.StartTimeoutS)
		c.event("start_waiting", fmt.Sprintf("no release assigned within %ds; strict start: nothing running", c.emb.StartTimeoutS), "")
		c.setPhase("failed")
		return
	}
	c.event("start_fallback", fmt.Sprintf("no release assigned within %ds; starting the embedded app", c.emb.StartTimeoutS), "")
	c.startInPlace(c.embeddedRelease("embedded"), c.emb.Process, "the console did not assign a release in time")
}

// markRedeploy records that rel cannot be applied here and tells the console,
// once. The release is not marked failed and is not retried.
func (c *Controller) markRedeploy(id, reason string) {
	c.mu.Lock()
	if c.redeploy == nil {
		c.redeploy = map[string]string{}
	}
	_, known := c.redeploy[id]
	c.redeploy[id] = reason
	c.mu.Unlock()
	c.saveState()
	if !known {
		c.log("release %s needs a redeploy: %s", id, reason)
		c.event("redeploy_required", reason, id)
	}
}

// localIndex is the index of the image this container was built from, read
// once from the metadata `embed` wrote into it.
func (c *Controller) localIndex() (*embedded.Index, error) {
	c.mu.Lock()
	idx := c.localIdx
	c.mu.Unlock()
	if idx != nil {
		return idx, nil
	}
	f, err := os.Open(embedded.IndexFile)
	if err != nil {
		return nil, fmt.Errorf("this image has no index (%v); re-embed it", err)
	}
	defer f.Close()
	idx, sha, err := embedded.Read(f)
	if err != nil {
		return nil, fmt.Errorf("local index: %w", err)
	}
	if c.emb.IndexSHA256 != "" && sha != c.emb.IndexSHA256 {
		return nil, fmt.Errorf("local index does not match embedded.json (%s vs %s)", sha, c.emb.IndexSHA256)
	}
	c.mu.Lock()
	c.localIdx = idx
	c.mu.Unlock()
	return idx, nil
}

// syncPathsNow is the app's current sync path list: the console's, else the
// image's.
func (c *Controller) syncPathsNow() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.syncPaths) > 0 {
		return c.syncPaths
	}
	return c.emb.SyncPaths
}

// deployEmbedded brings rel onto an embedded-runtime container. In order:
// resolve; refuse anything that is not an embedded image; read its metadata
// layer (~1 MB) and compare its index with this image's — a difference
// outside the sync paths is a base change and a *RedeployError before any
// bulk pull; then pull only the layers that touch the sync paths, stage their
// merged view, check every destination is writable as this user, and in the
// supervisor gap commit the staged tree and remove what the sync paths held
// that the release does not. The app restarts on the release's own process
// definition.
func (c *Controller) deployEmbedded(ctx context.Context, rel *release, cleanup bool) (deployReport, error) {
	var rep deployReport
	emb := c.emb
	ref, err := registry.PinByDigest(rel.Image, rel.Digest, rel.Insecure)
	if err != nil {
		return rep, err
	}
	plat := c.cfg.Platform // this container's own: the release pins an index, not an architecture
	img, err := registry.Resolve(ctx, ref, plat, registry.Options{Insecure: rel.Insecure, SkipVerify: rel.SkipVerify, Auth: rel.Auth})
	if err != nil {
		return rep, fmt.Errorf("resolve: %w", err)
	}
	if !img.Matches(rel.Digest) {
		return rep, fmt.Errorf("digest mismatch: console said %s, registry served %s for %s", rel.Digest, img.Digest, plat)
	}
	if img.Label(embedded.LabelRuntime) != embedded.RuntimeEmbedded {
		return rep, &RedeployError{Reason: fmt.Sprintf("release %s is not an embedded image; publish the image `fleetwide embed` produced", rel.ReleaseID)}
	}
	c.mu.Lock()
	cur := c.current
	c.mu.Unlock()
	curCustomer := emb.Digest
	if cur != nil && cur.Customer != "" {
		curCustomer = cur.Customer
	}
	// Fast path: the same customer image as what is on disk — nothing to
	// sync, adopt the release id.
	if d := img.Label(embedded.LabelAppDigest); d != "" && d == curCustomer {
		rel.Customer = d
		rel.Layers = nil
		p := emb.Process
		if cur != nil && cur.Process != nil {
			p = *cur.Process
		}
		rel.Process = &p
		c.log("%s is the customer image already on disk (%s): adopting without a sync", rel.ReleaseID, shortDigest(d))
		if !c.sup.AppRunning() {
			c.startInPlace(rel, p, "adopted the assigned release")
		} else {
			c.mu.Lock()
			c.current = rel
			c.mu.Unlock()
		}
		return rep, nil
	}
	meta, ok := img.MetaLayer(embedded.LabelMetaLayer)
	if !ok {
		return rep, &RedeployError{Reason: fmt.Sprintf("release %s has no metadata layer; re-embed it with a current fleetwide CLI", rel.ReleaseID)}
	}

	// The metadata layer alone: the release's embedded.json and index.
	opts := c.fetchOptions(rel.Insecure, rel.SkipVerify, rel.Auth, rel.Digest)
	opts.PullOnly = []string{meta.Digest}
	opts.Chown = os.Geteuid() == 0
	f, err := rootfs.Fetch(ctx, ref, opts)
	if err != nil {
		return rep, fmt.Errorf("fetch metadata: %w", err)
	}
	rep.PullMS = f.PullMS
	blob, err := c.cfg.Cache.Open(meta.Digest)
	if err != nil {
		return rep, err
	}
	tr, _, err := unpack.Decompress(blob)
	if err != nil {
		blob.Close()
		return rep, err
	}
	rinfo, ridx, rsha, err := embedded.ReadMeta(tr)
	tr.Close()
	blob.Close()
	if err != nil {
		return rep, fmt.Errorf("release metadata: %w", err)
	}
	if want := img.Label(embedded.LabelIndexSHA); want != "" && want != rsha {
		return rep, fmt.Errorf("release index sha256 %s does not match its label %s", rsha, want)
	}
	sync := c.syncPathsNow()
	if !sameStrings(rinfo.SyncPaths, cleanSorted(sync)) {
		return rep, &RedeployError{Reason: fmt.Sprintf("release %s was embedded with sync paths %s but the app now declares %s; re-embed it", rel.ReleaseID, strings.Join(rinfo.SyncPaths, ","), strings.Join(sync, ","))}
	}
	local, err := c.localIndex()
	if err != nil {
		return rep, err
	}
	inside := append(append([]string{}, sync...), emb.AssetPaths...)
	inside = append(inside, c.assetDirsSnapshot()...)
	t0 := time.Now()
	if ch := embedded.Diff(local, ridx, inside); len(ch) > 0 {
		return rep, &RedeployError{Reason: fmt.Sprintf("release %s changes the image outside the sync paths — %s — so this container needs a new embedded image", rel.ReleaseID, embedded.Summary(ch, 3))}
	}
	c.log("release %s: base identical to this image (%d paths compared in %dms); syncing %s from %d layer(s)", rel.ReleaseID, len(ridx.Entries), time.Since(t0).Milliseconds(), strings.Join(sync, ", "), len(rinfo.SyncLayers))

	// The sync-path layers, and nothing else.
	opts.PullOnly = rinfo.SyncLayers
	f, err = rootfs.Fetch(ctx, ref, opts)
	if err != nil {
		return rep, fmt.Errorf("fetch sync layers: %w", err)
	}
	rep.PullMS += f.PullMS
	rel.Layers = append(append([]string{}, rinfo.SyncLayers...), meta.Digest)
	rel.IndexDigest = img.IndexDigest
	rel.Customer = rinfo.Digest
	p := rinfo.Process
	rel.Process = &p

	// Stage the merged view of the sync paths.
	staging := filepath.Join(embedded.StagingDir, rel.ReleaseID)
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return rep, fmt.Errorf("staging dir: %w", err)
	}
	defer os.RemoveAll(staging)
	t1 := time.Now()
	view, err := f.SyncView(rinfo.SyncLayers, sync, staging)
	if err != nil {
		return rep, fmt.Errorf("stage: %w", err)
	}
	rep.StageMS, rep.Staged = time.Since(t1).Milliseconds(), true
	protected, err := rootfs.ProtectedPaths("/", append([]string{c.cfg.Cache.Dir(), c.cfg.StateDir, embedded.Dir}, c.assetDirsSnapshot()...)...)
	if err != nil {
		return rep, err
	}
	// Could this user write every destination? Decided before the stop.
	if err := f.SyncPreflight(rinfo.SyncLayers, sync, "/", protected); err != nil {
		var pe *unpack.PreflightError
		if errors.As(err, &pe) {
			return rep, &RedeployError{Reason: fmt.Sprintf("release %s writes %s, which this user cannot: %s; embed the image again with the current sync paths, or run as %s", rel.ReleaseID, pe.Path, pe.Reason, emb.User)}
		}
		return rep, err
	}
	c.log("staged %s: %d files, %d dirs under %s in %dms", rel.ReleaseID, view.Stats.Files, view.Stats.Dirs, strings.Join(sync, ", "), view.UnpackMS)

	c.mu.Lock()
	old := c.current
	c.mu.Unlock()
	c.sup.SetInfo(map[string]any{
		"release":      map[string]any{"id": rel.ReleaseID, "reference": rel.Image, "digest": rel.Digest, "platform": plat.String(), "embedded": true},
		"supervisor":   c.cfg.SupervisorVer,
		"installation": c.installationID(),
	})
	c.sup.SetExtraEnv(rel.Env, false)
	sw, err := c.sup.DeployWith(func() (supervise.Prepared, error) {
		cres, err := rootfs.Commit(staging, "/", rootfs.CommitOptions{Protected: protected, Chown: os.Geteuid() == 0, Log: c.log, Warn: func(f string, a ...any) { c.log("warn: "+f, a...) }})
		if err != nil {
			return supervise.Prepared{}, fmt.Errorf("commit: %w", err)
		}
		if err := writePaths(rel.PathsFile, cres.Paths); err != nil {
			return supervise.Prepared{}, err
		}
		if cleanup {
			removed := c.removeSyncResidue(sync, cres.Paths, protected)
			c.log("sync residue: removed %d entries under %s not in %s", removed, strings.Join(sync, ", "), rel.ReleaseID)
		}
		return supervise.Prepared{Runtime: p, Manifest: c.embeddedManifest(rel)}, nil
	})
	rep.Swap = sw
	if err != nil {
		return rep, err
	}
	_ = old
	c.log("swap %s: %s", rel.ReleaseID, rep)
	return rep, nil
}

// removeSyncResidue removes what is on disk under the sync paths and not in
// keep — the previous release's files, and anything the app wrote there (the
// sync paths are code and configuration, not data). Deepest first, so
// emptied directories go too; the sync path roots themselves stay.
func (c *Controller) removeSyncResidue(sync, keep, protected []string) int {
	keepSet := make(map[string]struct{}, len(keep))
	for _, p := range keep {
		keepSet[p] = struct{}{}
		// every ancestor of a kept path is kept
		for d := filepath.Dir(p); d != "/" && d != "."; d = filepath.Dir(d) {
			keepSet[d] = struct{}{}
		}
	}
	var victims []string
	for _, root := range sync {
		root = filepath.Clean(root)
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || p == root {
				return nil
			}
			if _, ok := keepSet[p]; ok {
				return nil
			}
			for _, pr := range protected {
				if p == pr || strings.HasPrefix(p, pr+"/") {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			victims = append(victims, p)
			if d.IsDir() {
				return filepath.SkipDir // its contents go with it
			}
			return nil
		})
	}
	sort.Slice(victims, func(i, j int) bool { return len(victims[i]) > len(victims[j]) })
	n := 0
	for _, p := range victims {
		if err := os.RemoveAll(p); err == nil {
			n++
		} else {
			c.log("warn: residue %s: %v", p, err)
		}
	}
	return n
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cleanSorted(ps []string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, filepath.Clean("/"+p))
	}
	sort.Strings(out)
	return out
}

// embeddedState fills the heartbeat's embedded-runtime fields. The caller
// holds c.mu (heartbeat builds the whole state under it).
func (c *Controller) embeddedState(st *v1.SupervisorState) {
	if c.emb == nil {
		return
	}
	st.AppRuntime = v1.RuntimeEmbedded
	st.EmbeddedDigest = c.emb.Digest
	if len(c.redeploy) > 0 {
		st.RedeployRequired = make(map[string]string, len(c.redeploy))
		for k, v := range c.redeploy {
			st.RedeployRequired[k] = v
		}
	}
	if os.Geteuid() != 0 {
		st.MissingCaps = nil // expected: the embedded runtime needs none
	}
}

// startEmbeddedRuntime decides what an embedded-runtime container runs at
// start: a synced release from local state, the image's own process, or —
// with --start latest and nothing yet — nothing until the console assigns a
// release.
func (c *Controller) startEmbeddedRuntime(cur *release) {
	emb := c.emb
	switch {
	case cur != nil && cur.Process != nil:
		c.mu.Lock()
		c.previous = c.loadRelease("previous.json")
		c.mu.Unlock()
		c.startInPlace(cur, *cur.Process, "resumed from local state")
	case cur != nil:
		// state without a process record: the files are the image's
		c.startInPlace(c.embeddedRelease(cur.ReleaseID), emb.Process, "resumed the embedded release")
	case emb.Start == embedded.StartLatest:
		timeout := time.Duration(emb.StartTimeoutS) * time.Second
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		c.mu.Lock()
		c.awaitLatest = time.Now().Add(timeout)
		c.mu.Unlock()
		c.setPhase("starting")
		c.log("embedded runtime, --start latest: waiting up to %s for the console to assign a release (%s)", timeout, emb.StartFallback)
	default:
		c.startInPlace(c.embeddedRelease("embedded"), emb.Process, "the embedded release")
	}
}

// runStandaloneEmbedded supervises the embedded application with no console
// at all.
func (c *Controller) runStandaloneEmbedded(ctx context.Context) (int, error) {
	c.log("no console configured: running the embedded release %s standalone (set FLEETWIDE_KEY to enable updates)", shortDigest(c.emb.Digest))
	supDone := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := c.sup.Run(ctx)
		supDone <- struct {
			code int
			err  error
		}{code, err}
	}()
	c.sup.WaitStarted(ctx)
	c.startInPlace(c.embeddedRelease("embedded"), c.emb.Process, "standalone")
	select {
	case <-ctx.Done():
		return 0, nil
	case r := <-supDone:
		return r.code, r.err
	}
}
