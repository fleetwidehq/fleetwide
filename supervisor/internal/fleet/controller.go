// Package fleet is the Supervisor's managed mode: enroll with the Console, run
// whatever release the Console assigns, heartbeat state, update in place
// when the channel moves (removing the previous release's leftover files),
// and roll back automatically when a fresh release stays unhealthy.
package fleet

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/assets"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/baked"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/caps"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/consoleclient"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/embedded"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/features"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/fsinfo"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/health"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/identity"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/logbuf"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/manifest"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/metrics"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/progress"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/rootfs"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/supervise"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/telemetry"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/tunnel"
)

// Config for the controller.
type Config struct {
	Key           string // deployment key (fw1.…): console URL + app key + secret + CA pin; overrides the three below
	Console       string // https://host:port (optional once enrolled: remembered in the identity)
	AppKey        string
	Secret        string // one-time enrollment secret (only needed until enrolled)
	CAPEM         []byte // Console CA to trust; nil = pin from token, else system roots
	CAPin         string // hex SHA-256 of the Console CA (from the token)
	Name          string // FLEETWIDE_INSTANCE_NAME: display name in the console; the hostname is the identity
	Runtime       string // FLEETWIDE_RUNTIME override: k8s | swarm | docker | compose (detected when empty)
	InsecureTLS   bool   // dev only
	StateDir      string // identity, current release, path lists
	Cache         *layercache.Cache
	Platform      registry.Platform
	ReadyListen   string
	SupervisorVer string
	Log           func(string, ...any)
	// SkipSpaceCheck turns off the free-space preflight before a pull, for
	// filesystems whose statfs does not describe the real limit.
	SkipSpaceCheck bool
}

// release is the persisted record of a deployed release.
type release struct {
	ReleaseID string `json:"release_id"`
	Image     string `json:"image"`
	Digest    string `json:"digest"`
	// IndexDigest is the multi-platform index Digest came out of, when the
	// image has one; a release may be pinned to either.
	IndexDigest string `json:"index_digest,omitempty"`
	Platform    string `json:"platform"`
	Insecure    bool   `json:"insecure"`
	SkipVerify  bool   `json:"skip_verify,omitempty"`
	Manifest    string `json:"manifest_yaml,omitempty"`
	PathsFile   string `json:"paths_file"`
	// Layers are the image's layer digests: the cache blobs this release
	// needs, so retention can tell what may go.
	Layers []string `json:"layers,omitempty"`
	// Embedded runtime: Customer is the customer image the release was
	// embedded from (what its index describes), Process the process it
	// starts — kept so a resume needs no registry.
	Customer string            `json:"customer_digest,omitempty"`
	Process  *imagecfg.Runtime `json:"process,omitempty"`
	// Auth is the Console-supplied registry credential.
	Auth *registry.Auth `json:"registry_auth,omitempty"`
	// Env is the Console-delivered environment (NAME=VALUE) and its hash.
	Env     []string `json:"env,omitempty"`
	EnvHash string   `json:"env_hash,omitempty"`
}

// is reports whether digest names this release: the image it resolved to, or
// the index that image came out of.
func (r *release) is(digest string) bool {
	if r == nil || digest == "" {
		return false
	}
	return digest == r.Digest || (r.IndexDigest != "" && digest == r.IndexDigest)
}

func flattenEnv(in []v1.EnvVar) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		if e.Name != "" {
			out = append(out, e.Name+"="+e.Value)
		}
	}
	return out
}

// meta is small persisted controller state.
type meta struct {
	FailedReleaseID  string            `json:"failed_release_id,omitempty"`
	RedeployRequired map[string]string `json:"redeploy_required,omitempty"`
	Updates          int               `json:"updates"`
	AssetsHash       string            `json:"assets_hash,omitempty"`
	Assets           []v1.AssetState   `json:"assets,omitempty"`
}

// Controller runs the managed loop.
type Controller struct {
	cfg        Config
	log        func(string, ...any)
	sup        *supervise.Supervisor
	ident      *consoleclient.Identity
	cli        *consoleclient.Client
	renewTried time.Time           // last certificate renewal attempt; retried hourly
	tunnel     tunnel.Manager      // Access tunnels (built with the access feature; no-op otherwise)
	tel        telemetry.Collector // application metric scraping (telemetry feature; no-op otherwise)
	health     *v1.Healthcheck     // the console's probe definition, refreshed every heartbeat

	mu       sync.Mutex
	current  *release
	previous *release
	pending  string // release id deployed but not yet confirmed healthy
	failed   string // last release rolled back from
	phase    string
	updates  int
	lastErr  string
	events   []v1.Event
	started  time.Time
	hostname string
	fp       identity.Fingerprint
	baked    *baked.Info // present when running from a `fleetwide bake` image
	metrics  metrics.Sampler
	quiet    bool // fleet monitoring off: no metrics, no logs
	holding  bool // a change waits for the fleet's update window
	// onFailure is the fleet's Rollout.OnFailure as of the last heartbeat:
	// what to do when a release fails after the old application stopped.
	onFailure string
	// settled is the release the cache was last trimmed for, so the
	// console's repeated word is acted on once.
	settled string
	// Embedded runtime: the image's metadata, its index (read once), the
	// app's current sync paths from the console, releases this container
	// cannot take in place, and the deadline of a `--start latest` wait.
	emb         *embedded.Info
	localIdx    *embedded.Index
	syncPaths   []string
	redeploy    map[string]string
	awaitLatest time.Time
	// noStage names the image digest the space preflight decided "/" cannot
	// hold a staged copy of; stageRelease skips straight to the in-gap apply.
	noStage string
	// channel assets: hash applied, per-asset state, sync in flight, retry backoff
	assetsHash    string
	assetsState   []v1.AssetState
	assetsSyncing bool
	assetsRetryAt time.Time
	assetsFailed  string // hash of the list whose sync last failed (backoff applies to it only)
	assetDirs     []string
	dl            *progress.Tracker // what is downloading right now
	// snapshot job: one release+files change applied as a unit, in the fleet's order
	snapBusy     bool
	snapFailed   string // snapshot the supervisor gave up on (reported so the console withholds it)
	snapAttempts map[string]int
	snapRetryAt  time.Time
	logs         *logbuf.Buffer // nil when the customer disabled log streaming
	logWant      chan int64     // console asked for logs (value = seq it already has)
}

// New creates a controller.
func New(cfg Config) *Controller {
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	if cfg.Platform.OS == "" {
		cfg.Platform = registry.HostPlatform()
	}
	if cfg.Key != "" {
		if t, err := v1.DecodeKey(cfg.Key); err == nil {
			cfg.Console, cfg.AppKey, cfg.Secret, cfg.CAPin = t.ConsoleURL, t.AppKey, t.Secret, t.CASHA256
		} else {
			cfg.Log("deployment key: %v (falling back to FLEETWIDE_CONSOLE/APP_KEY/SECRET)", err)
		}
	}
	c := &Controller{cfg: cfg, log: cfg.Log, phase: "starting", started: time.Now(), logWant: make(chan int64, 1)}
	c.dl = progress.New(func(d v1.Download, took time.Duration) {
		c.event("downloaded", fmt.Sprintf("%s · %s in %s", d.Name, humanBytes(d.Done), took.Round(time.Second)), "")
	})
	c.metrics.DataDir = cfg.StateDir
	c.fp = identity.Detect()
	c.hostname = c.fp.Hostname
	if c.cfg.Runtime == "" {
		c.cfg.Runtime = c.fp.Runtime()
	}
	if features.Has(v1.CapLogs) {
		c.logs = logbuf.New()
	}
	// The console knows this container by its pod uid or container id; the
	// certificate in the state directory carries that identity across restarts.
	cfg.Log("identity: container %s, pod %s, hostname %q", short(c.fp.ContainerID), short(c.fp.PodUID), c.hostname)
	c.sup = supervise.New(supervise.Options{
		ReadyListen:    cfg.ReadyListen,
		Log:            cfg.Log,
		Logs:           c.logs,
		OnUnhealthyFor: c.onUnhealthyFor,
		OnRestart:      func(reason string) { c.event("restart", "health-triggered in-place restart: "+reason, "") },
	})
	return c
}

func (c *Controller) event(typ, msg, rel string) {
	c.mu.Lock()
	c.events = append(c.events, v1.Event{At: time.Now(), Type: typ, Message: msg, Release: rel})
	if len(c.events) > 100 {
		c.events = c.events[len(c.events)-100:]
	}
	c.mu.Unlock()
	c.log("event %s: %s", typ, msg)
}

// checkBakedKey refuses a key meant for a different app or console than the
// baked image says it belongs to, before any identity exists.
func checkBakedKey(bk *baked.Info, console, appKey string) error {
	if bk == nil || bk.AppKey == "" || appKey == "" {
		return nil
	}
	if bk.AppKey != appKey {
		return fmt.Errorf("this image was baked for app %q but the key is for %q: use the right key, or an unbaked image", bk.AppKey, appKey)
	}
	if bk.Console != "" && console != "" && !sameConsole(bk.Console, console) {
		return fmt.Errorf("this image was baked against %s but the key points at %s", bk.Console, console)
	}
	return nil
}

// sameConsole compares two console URLs ignoring a trailing slash.
func sameConsole(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// applyHealth takes the console's probe definition, which arrives on every
// heartbeat. Nil leaves whatever the release's manifest decided.
func (c *Controller) applyHealth(h *v1.Healthcheck) {
	c.mu.Lock()
	c.health = h
	c.mu.Unlock()
	if h == nil {
		return
	}
	c.sup.EnableReady(h.ReadyListen)
	c.sup.SetHealth(mergeHealth(c.sup.Manifest().Health, h))
}

// mergeHealth lays the console's definition over the manifest's: an unset
// field keeps what the image (or the supervisor's defaults) decided.
func mergeHealth(base manifest.Health, h *v1.Healthcheck) manifest.Health {
	out := base
	if h.ProcessOnly {
		// The fleet switched probes off: the process is the check, and
		// nothing may restart the app on health grounds.
		out.HTTP, out.TCP, out.Exec = "", "", nil
		out.OnUnhealthy = v1.OnUnhealthyReport
		return out
	}
	if h.Kind() != "process" {
		out.HTTP, out.TCP, out.Exec = h.HTTP, h.TCP, h.Exec
	}
	if h.IntervalS > 0 {
		out.Interval = time.Duration(h.IntervalS) * time.Second
	}
	if h.TimeoutS > 0 {
		out.Timeout = time.Duration(h.TimeoutS) * time.Second
	}
	if h.GraceS > 0 {
		out.Grace = time.Duration(h.GraceS) * time.Second
	}
	if h.FailureThreshold > 0 {
		out.FailureThreshold = h.FailureThreshold
	}
	if h.MaxRestarts > 0 {
		out.MaxRestarts = h.MaxRestarts
	}
	if h.OnUnhealthy != "" {
		out.OnUnhealthy = h.OnUnhealthy
	}
	return out
}

// humanBytes formats a byte count for an event line.
func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	d, e := int64(u), 0
	for m := n / u; m >= u; m /= u {
		d *= u
		e++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(d), "KMGTPE"[e])
}

func (c *Controller) setPhase(p string) {
	c.mu.Lock()
	c.phase = p
	c.mu.Unlock()
}

// Run blocks until the app exits on its own or ctx is cancelled. Returns the
// exit code to propagate.
func (c *Controller) Run(ctx context.Context) (int, error) {
	if err := os.MkdirAll(c.cfg.StateDir, 0o700); err != nil {
		return 0, err
	}
	emb, err := embedded.Load("/")
	if err != nil {
		c.log("embedded.json: %v (ignored)", err)
	}
	c.emb = emb
	if emb == nil || os.Geteuid() == 0 {
		if req, opt := caps.Missing(); req != 0 || opt != 0 {
			if req != 0 {
				c.log("warning: this container lacks %s, which the supervisor needs to write a release and start the app; updates will fail", req)
			}
			if opt != 0 {
				c.log("note: this container lacks %s; device nodes and file capabilities in images will not be reproduced", opt)
			}
		}
	}
	if emb != nil {
		c.embeddedSelfCheck()
		if emb.App != "" && c.cfg.AppKey != "" && emb.App != c.cfg.AppKey {
			return 0, fmt.Errorf("this image was embedded for app %q but the key is for %q", emb.App, c.cfg.AppKey)
		}
	}
	bk, err := baked.Load("/")
	if err != nil {
		c.log("baked.json: %v (ignored)", err)
	}
	c.baked = bk
	if err := checkBakedKey(bk, c.cfg.Console, c.cfg.AppKey); err != nil {
		return 0, err
	}
	if (bk != nil || emb != nil) && c.cfg.Key == "" && c.cfg.Console == "" {
		if _, err := consoleclient.LoadIdentity(filepath.Join(c.cfg.StateDir, "identity")); err != nil {
			// Started without any Console configuration: run the shipped
			// application on its own. Updates begin once a key is given.
			if emb != nil {
				return c.runStandaloneEmbedded(ctx)
			}
			return c.runStandalone(ctx, bk)
		}
	}
	if err := c.ensureIdentity(ctx); err != nil {
		return 0, err
	}
	if c.cfg.Console == "" {
		c.cfg.Console = c.ident.ConsoleURL
	}
	if c.cfg.Console == "" {
		return 0, errors.New("console URL unknown: set FLEETWIDE_KEY or FLEETWIDE_CONSOLE")
	}
	cli, err := consoleclient.New(c.cfg.Console, c.ident, c.cfg.InsecureTLS)
	if err != nil {
		return 0, err
	}
	c.cli = cli
	c.tunnel = tunnel.New(tunnel.Config{Identity: func() *consoleclient.Identity { c.mu.Lock(); defer c.mu.Unlock(); return c.ident }, InsecureTLS: c.cfg.InsecureTLS, SupervisorVersion: c.cfg.SupervisorVer, Log: c.log})
	defer c.tunnel.Close()
	c.tel = telemetry.New(telemetry.Config{Post: func(ctx context.Context, p []v1.MetricPoint) (*v1.MetricsResponse, error) {
		c.mu.Lock()
		cli := c.cli
		c.mu.Unlock()
		if cli == nil {
			return nil, errors.New("not connected to the console")
		}
		return cli.PostMetrics(ctx, p)
	}, Log: c.log})
	defer c.tel.Close()
	if c.logs != nil {
		go c.logPusher(ctx)
	}

	// The Supervisor runs for the life of the process; releases are deployed into it.
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

	// Offline start: bring back the last deployed release from the cache
	// before talking to the Console.
	if b, err := os.ReadFile(filepath.Join(c.cfg.StateDir, "meta.json")); err == nil {
		var m meta
		if json.Unmarshal(b, &m) == nil {
			c.mu.Lock()
			c.failed, c.updates = m.FailedReleaseID, m.Updates
			c.redeploy = m.RedeployRequired
			c.assetsHash, c.assetsState = m.AssetsHash, m.Assets
			for _, a := range m.Assets {
				c.assetDirs = append(c.assetDirs, filepath.Dir(filepath.Dir(a.Path)))
			}
			c.mu.Unlock()
		}
	}
	cur := c.loadRelease("current.json")
	if emb != nil {
		c.startEmbeddedRuntime(cur)
	} else if cur == nil && bk != nil {
		// Fresh container from a baked image: the application is already in
		// the rootfs. Run it as the fallback release; the Console may adopt
		// it (same digest) or update it.
		c.startBaked(bk, "baked")
	} else if cur != nil && bk != nil && cur.Digest == bk.Digest {
		// Resume of a baked release: nothing to pull, the rootfs is the image.
		c.mu.Lock()
		c.previous = c.loadRelease("previous.json")
		c.mu.Unlock()
		c.startBaked(bk, cur.ReleaseID)
	} else if cur != nil && cur.Image == "" {
		c.mu.Lock()
		c.current = cur
		c.mu.Unlock()
		c.log("resuming assets-only release %s from local state", cur.ReleaseID)
		c.setPhase("idle")
	} else if cur != nil {
		c.mu.Lock()
		c.current = cur
		c.previous = c.loadRelease("previous.json")
		c.mu.Unlock()
		leftover := c.staleStaging(cur.ReleaseID)
		c.mu.Lock()
		failed := c.failed
		c.mu.Unlock()
		if failed != "" && failed != cur.ReleaseID {
			// A release that failed after its files were written — parked
			// under the report policy, or a rollback this container did
			// not live to finish — left them in "/". Its paths file says
			// which; they go the same way as a half-committed stage.
			seen := false
			for _, id := range leftover {
				seen = seen || id == failed
			}
			if _, err := os.Stat(filepath.Join(c.cfg.StateDir, "paths", failed+".txt")); err == nil && !seen {
				leftover = append(leftover, failed)
			}
		}
		c.log("resuming release %s (%s) from local state", cur.ReleaseID, shortDigest(cur.Digest))
		if _, err := c.deploy(ctx, cur, false, nil); err != nil {
			c.log("resume failed: %v (waiting for Console)", err)
			c.setPhase("failed")
			c.mu.Lock()
			c.lastErr = err.Error()
			c.mu.Unlock()
		} else {
			c.setPhase("running")
			c.finishStaleStaging(leftover, cur)
		}
	}
	os.RemoveAll(stagingRoot) // anything else left there is a crash's litter

	interval := 10 * time.Second // until the console says otherwise
	unknown := 0
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			// SIGTERM/SIGINT from the orchestrator: the supervisor drains the
			// app; tell the Console this is a graceful stop, not a lost container.
			c.setPhase("drained")
			select {
			case <-supDone:
			case <-time.After(c.sup.StopTimeout() + 5*time.Second):
			}
			c.event("drained", "stopped by the orchestrator (termination signal); the app was shut down gracefully", c.currentID())
			c.finalHeartbeat()
			return 0, nil
		case r := <-supDone:
			c.log("supervisor finished: code=%d err=%v", r.code, r.err)
			if c.sup.Stopping() {
				c.setPhase("drained")
				c.event("drained", "stopped by the orchestrator (termination signal); the app was shut down gracefully", c.currentID())
			} else {
				c.setPhase("exited")
				c.event("exited", exitMessage(c.sup.LastExit(), r.code), c.currentID())
			}
			c.finalHeartbeat()
			return r.code, r.err
		case <-timer.C:
		}
		next := interval
		if c.emb != nil {
			c.awaitLatestOrFallback()
		}
		c.maybeRenew(ctx)
		resp, err := c.heartbeat(ctx)
		if err != nil {
			c.log("heartbeat: %v", err)
			// Unknown (removed from the console) or superseded (this same
			// container enrolled again after losing its identity directory, so
			// an older certificate is talking): either way, re-enroll.
			if errors.Is(err, consoleclient.ErrUnknownInstallation) || errors.Is(err, consoleclient.ErrSuperseded) {
				unknown++
				if c.cfg.Secret != "" && unknown >= 3 {
					// Still holding a deployment key: re-enroll.
					c.log("installation unknown to Console; re-enrolling with the deployment key")
					os.RemoveAll(filepath.Join(c.cfg.StateDir, "identity"))
					if err := c.ensureIdentity(ctx); err == nil {
						if cli, err := consoleclient.New(c.cfg.Console, c.ident, c.cfg.InsecureTLS); err == nil {
							c.cli = cli
							unknown = 0
						}
					}
				} else {
					c.log("installation unknown to Console; keeping the current release running")
				}
			}
		} else {
			unknown = 0
			if resp.IntervalS > 0 {
				next = time.Duration(resp.IntervalS) * time.Second
			}
			c.apply(ctx, resp)
		}
		timer.Reset(next)
	}
}

func (c *Controller) currentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return c.current.ReleaseID
	}
	return ""
}

// finalHeartbeat reports the terminal phase with a short deadline that does
// not depend on the (already cancelled) run context.
func (c *Controller) finalHeartbeat() {
	if c.cli == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.heartbeat(ctx); err != nil {
		c.log("final heartbeat: %v", err)
	}
}

func exitMessage(e *supervise.Exit, code int) string {
	switch {
	case e == nil:
		return fmt.Sprintf("application exited with code %d", code)
	case e.OOM:
		return fmt.Sprintf("application was killed by the kernel OOM killer (%s, code %d): raise the memory limit", e.Signal, code)
	case e.Reason == "restart_budget":
		return fmt.Sprintf("unhealthy and out of restarts; supervisor exiting %d for the orchestrator", code)
	case e.Signal != "":
		return fmt.Sprintf("application was killed by %s (code %d)", e.Signal, code)
	}
	return fmt.Sprintf("application exited with code %d", code)
}

func (c *Controller) ensureIdentity(ctx context.Context) error {
	idDir := filepath.Join(c.cfg.StateDir, "identity")
	id, err := consoleclient.LoadIdentity(idDir)
	if err == nil && id.Expired(time.Now()) {
		// An expired certificate cannot open the mTLS session, so it cannot
		// be renewed either: with a key, enroll afresh; without one, keep the
		// app running.
		if c.cfg.Secret != "" {
			c.log("identity: certificate for %s expired on %s; re-enrolling with the deployment key", id.InstallationID, id.NotAfter.Format(time.RFC3339))
			os.RemoveAll(idDir)
			err = os.ErrNotExist
		} else {
			c.log("WARNING: identity: certificate for %s expired on %s and no FLEETWIDE_KEY is set; the app keeps running but the console cannot reach it. Restart with the deployment key to re-enroll.", id.InstallationID, id.NotAfter.Format(time.RFC3339))
		}
	}
	if err == nil {
		c.ident = id
		c.log("identity: installation %s (channel %s, certificate until %s)", id.InstallationID, id.Channel, id.NotAfter.Format("2006-01-02"))
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("identity: %w", err)
	}
	if c.cfg.Secret == "" || c.cfg.AppKey == "" || c.cfg.Console == "" {
		return errors.New("not enrolled: set FLEETWIDE_KEY (or FLEETWIDE_CONSOLE + FLEETWIDE_APP_KEY + FLEETWIDE_SECRET)")
	}
	backoff := 2 * time.Second
	for {
		id, err = consoleclient.Enroll(ctx, c.cfg.Console, consoleclient.TLSOptions{CAPEM: c.cfg.CAPEM, CAFingerprint: c.cfg.CAPin, InsecureSkipVerify: c.cfg.InsecureTLS}, v1.EnrollRequest{
			AppKey: c.cfg.AppKey, Secret: c.cfg.Secret, SupervisorVersion: c.cfg.SupervisorVer, Platform: c.cfg.Platform.String(), Hostname: c.hostname, Name: c.cfg.Name,
			Runtime: c.cfg.Runtime, Variant: features.Variant(), Capabilities: features.Live(),
			ContainerID: c.fp.ContainerID, PodUID: c.fp.PodUID, MachineID: c.fp.MachineID, BootID: c.fp.BootID,
		})
		if err == nil {
			break
		}
		c.log("enroll failed: %v (retry in %s)", err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
	if err := id.Save(idDir); err != nil {
		return err
	}
	c.ident = id
	c.log("enrolled as installation %s (channel %s, hostname %q)", id.InstallationID, id.Channel, c.hostname)
	return nil
}

func (c *Controller) heartbeat(ctx context.Context) (*v1.HeartbeatResponse, error) {
	snap := c.sup.Snapshot()
	c.mu.Lock()
	tzName, tzOff := time.Now().Zone()
	if env := os.Getenv("TZ"); env != "" {
		tzName = env
	}
	st := v1.SupervisorState{
		SupervisorVersion: c.cfg.SupervisorVer, Platform: c.cfg.Platform.String(), Hostname: c.hostname, Kernel: kernel(), Baked: c.baked != nil,
		TZ: tzName, TZOffsetMin: tzOff / 60,
		ContainerID: c.fp.ContainerID, PodUID: c.fp.PodUID, MachineID: c.fp.MachineID, BootID: c.fp.BootID,
		Name: c.cfg.Name, Runtime: c.cfg.Runtime, Variant: features.Variant(), Capabilities: features.Live(),
		UptimeS: int64(time.Since(c.started).Seconds()), Phase: c.phase, Running: snap.Running, Healthy: snap.Health.Healthy,
		Ready: snap.Ready, Restarts: snap.Restarts, Updates: c.updates, PID: snap.PID, FailedReleaseID: c.failed, LastError: c.lastErr,
	}
	if c.tunnel != nil {
		st.Tunnel = c.tunnel.Status()
	}
	if req, opt := caps.Missing(); req|opt != 0 {
		st.MissingCaps = (req | opt).Names()
	}
	if c.tel != nil {
		st.TelemetryMissing = c.tel.Missing()
	}
	c.embeddedState(&st)
	if c.current != nil {
		st.ReleaseID, st.Digest, st.Image = c.current.ReleaseID, c.current.Digest, c.current.Image
	}
	if e := snap.LastExit; e != nil {
		st.LastExit = &v1.ExitInfo{At: e.At, Code: e.Code, Signal: e.Signal, OOM: e.OOM, Reason: e.Reason}
	}
	if c.phase == "drained" || c.phase == "exited" {
		st.Running, st.Healthy, st.Ready = false, false, false
	}
	if c.phase == "idle" {
		// assets-only: healthy means every asset is live and none failed
		st.Running, st.Ready = false, false
		st.Healthy = !c.assetsSyncing || len(c.assetsState) > 0
		for _, a := range c.assetsState {
			if a.Error != "" {
				st.Healthy = false
			}
		}
	}
	st.AssetsHash, st.Assets, st.AssetsSyncing = c.assetsHash, c.assetsState, c.assetsSyncing || c.snapBusy
	st.Download = c.dl.State()
	st.FailedSnapshot = c.snapFailed
	quiet := c.quiet
	st.Health.Check = snap.Health.Check
	st.Health.LastError = snap.Health.LastError
	st.Health.ConsecutiveFailures = snap.Health.ConsecutiveFailures
	st.Health.UnhealthyForS = int64(snap.Health.UnhealthyFor.Seconds())
	if snap.Ready && c.sup.Ready() != nil && c.sup.Ready().Override() == "unready" {
		st.Ready = false
	}
	// Confirmation: the pending release has proven itself.
	if c.pending != "" && snap.Confirmed && c.current != nil && c.current.ReleaseID == c.pending {
		c.pending = ""
		c.events = append(c.events, v1.Event{At: time.Now(), Type: "confirmed", Message: "release healthy past grace; confirmed", Release: c.current.ReleaseID})
	}
	events := c.events
	c.events = nil
	c.mu.Unlock()

	if !quiet {
		st.Metrics = c.metrics.Sample()
	}

	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	resp, err := c.cli.Heartbeat(cctx, v1.HeartbeatRequest{State: st, Events: events})
	if err != nil {
		c.mu.Lock()
		c.events = append(events, c.events...) // retry next time
		c.mu.Unlock()
		return nil, err
	}
	return resp, nil
}

func (c *Controller) apply(ctx context.Context, resp *v1.HeartbeatResponse) {
	if r := c.sup.Ready(); r != nil && resp.Override != "" && resp.Override != r.Override() {
		if err := r.SetOverride(resp.Override); err == nil {
			c.log("readiness override from Console: %s", resp.Override)
		}
	}
	if resp.Logs != nil && resp.Logs.Want && c.logs != nil {
		select {
		case c.logWant <- resp.Logs.Since:
		default:
		}
	}
	if resp.Restart {
		c.event("restart", "restart requested from Console", "")
		if err := c.sup.Restart("console request"); err != nil {
			c.log("restart: %v", err)
		}
	}
	c.mu.Lock()
	c.onFailure = resp.OnFailure
	c.mu.Unlock()
	if resp.Hold {
		// outside the fleet's update window: keep what we run; nothing below applies
		c.mu.Lock()
		first := !c.holding
		c.holding = true
		c.mu.Unlock()
		if first {
			when := "until the window opens"
			if !resp.NextWindow.IsZero() {
				when = "until " + resp.NextWindow.Local().Format("Mon 15:04 MST")
			}
			c.log("update pending but the fleet's update window is closed: holding %s", when)
		}
		return
	}
	if c.tunnel != nil {
		if features.Has(v1.CapAccess) {
			c.tunnel.Apply(resp.Tunnel)
		} else {
			c.tunnel.Apply(nil) // this image carries no tunnel; the console is told through the absent capability
		}
	}
	if c.tel != nil {
		if features.Has(v1.CapTelemetry) && !resp.MonitoringDisabled {
			c.tel.Apply(resp.Telemetry)
		} else {
			c.tel.Apply(nil) // vetoed here, or the fleet switched monitoring off
		}
	}
	c.applyHealth(resp.Health)
	c.mu.Lock()
	c.holding = false
	if c.quiet != resp.MonitoringDisabled {
		c.quiet = resp.MonitoringDisabled
		if c.quiet {
			c.log("fleet monitoring is off: metrics and log streaming suspended")
		}
	}
	c.mu.Unlock()
	c.settle(resp.Settled)
	if resp.Desired == nil {
		return
	}
	resolveAuthEnv(resp.Desired, c.log)
	d := resp.Desired
	if len(d.SyncPaths) > 0 {
		c.mu.Lock()
		c.syncPaths = cleanSorted(d.SyncPaths)
		c.mu.Unlock()
	}
	c.mu.Lock()
	curID, curDigest, sameBytes := "", "", false
	if c.current != nil {
		curID, curDigest = c.current.ReleaseID, c.current.Digest
		sameBytes = c.current.is(d.Digest)
	}
	c.mu.Unlock()
	if d.Image != "" && d.ReleaseID != curID && sameBytes {
		// Same bytes already running (typically the baked release): adopt the
		// Console's release id without re-extracting.
		c.mu.Lock()
		c.current.ReleaseID, c.current.Image, c.current.Manifest = d.ReleaseID, d.Image, d.Manifest
		c.current.Auth = authOf(d.RegistryAuth)
		c.mu.Unlock()
		c.saveState()
		c.event("adopted", fmt.Sprintf("running image matches %s (%s); adopted without redeploy", d.ReleaseID, shortDigest(curDigest)), d.ReleaseID)
		curID = d.ReleaseID
	}
	if d.ReleaseID == "" && d.Image == "" {
		// a file-only fleet: nothing to run, deliver and sit idle
		c.mu.Lock()
		if c.phase == "starting" || c.phase == "enrolled" {
			c.phase = "idle"
		}
		c.mu.Unlock()
	}
	c.applySnapshot(ctx, d)
	if d.ReleaseID == curID {
		c.applyEnv(d)
	}
}

// applyEnv restarts the running release in place when the Console-delivered
// environment changed (same release, new values).
func (c *Controller) applyEnv(d *v1.Desired) {
	c.mu.Lock()
	cur := c.current
	same := cur == nil || cur.EnvHash == d.EnvHash
	if !same {
		cur.Env, cur.EnvHash = flattenEnv(d.Env), d.EnvHash
	}
	c.mu.Unlock()
	if same {
		return
	}
	c.saveState()
	changed, err := c.sup.SetExtraEnv(flattenEnv(d.Env), true)
	if err != nil {
		c.log("environment update: %v", err)
		c.event("env_failed", err.Error(), d.ReleaseID)
		return
	}
	if changed {
		c.event("env_updated", fmt.Sprintf("%d variable(s) from the console applied; app restarted in place", len(d.Env)), d.ReleaseID)
	}
}

func (c *Controller) assetDirsSnapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.assetDirs...)
}

// applySnapshot brings the container to the fleet's snapshot: the release
// and the files of every subscription, applied as one unit. Everything is
// staged first (image layers into the cache, asset versions next to the live
// ones); then items are switched in the fleet's order, the app being the
// restart point. Runs in the background; heartbeats report progress.
func (c *Controller) applySnapshot(ctx context.Context, d *v1.Desired) {
	c.mu.Lock()
	curID := ""
	if c.current != nil {
		curID = c.current.ReleaseID
	}
	relChanged := d.Image != "" && d.ReleaseID != curID && d.ReleaseID != c.failed && c.redeploy[d.ReleaseID] == ""
	assetsChanged := d.AssetsHash != c.assetsHash
	if c.snapBusy || (!relChanged && !assetsChanged) || d.Snapshot == c.snapFailed || (d.Snapshot != "" && time.Now().Before(c.snapRetryAt) && c.snapAttempts[d.Snapshot] > 0) {
		c.mu.Unlock()
		return
	}
	c.snapBusy = true
	dirs := make([]string, 0, len(d.Assets))
	for _, a := range d.Assets {
		dirs = append(dirs, a.UnpackTo)
	}
	c.assetDirs = dirs
	c.mu.Unlock()
	cp := *d
	cp.Assets = append([]v1.Asset(nil), d.Assets...)
	cp.Order = append([]string(nil), d.Order...)
	go c.runSnapshot(ctx, &cp, relChanged, assetsChanged)
}

func (c *Controller) runSnapshot(ctx context.Context, d *v1.Desired, relChanged, assetsChanged bool) {
	finish := func(failed bool, err error) {
		c.mu.Lock()
		c.snapBusy = false
		if failed {
			if c.snapAttempts == nil {
				c.snapAttempts = map[string]int{}
			}
			c.snapAttempts[d.Snapshot]++
			c.snapRetryAt = time.Now().Add(time.Minute)
			if c.snapAttempts[d.Snapshot] >= 3 {
				c.snapFailed = d.Snapshot
				c.lastErr = err.Error()
			}
		}
		c.mu.Unlock()
		c.saveState()
	}
	// 1. stage: pull image layers and unpack asset versions, switching nothing
	var fetched *rootfs.Fetched
	if relChanged && c.emb == nil { // the embedded runtime pulls only what it needs, inside deploy
		ref, err := registry.PinByDigest(d.Image, d.Digest, d.Insecure)
		if err == nil {
			fetched, err = rootfs.Fetch(ctx, ref, c.fetchOptions(d.Insecure, d.SkipVerify, authOf(d.RegistryAuth), d.Digest))
		}
		if err != nil {
			c.log("update to %s failed: staging image %s: %v", d.ReleaseID, d.Image, err)
			c.mu.Lock()
			c.failed = d.ReleaseID
			c.lastErr = err.Error()
			c.snapBusy = false
			c.mu.Unlock()
			c.saveState()
			c.event("update_failed", err.Error(), d.ReleaseID)
			return
		}
	}
	var staged []assets.Result
	if assetsChanged {
		var err error
		staged, err = assets.Stage(ctx, d.Assets, assets.Options{Cache: c.cfg.Cache, Log: c.log, Progress: c.dl})
		if err != nil {
			c.log("snapshot %s: staging files: %v", d.Snapshot, err)
			c.event("snapshot_failed", "staging files failed: "+err.Error(), d.ReleaseID)
			c.recordAssetStates(staged)
			finish(true, err)
			return
		}
	}
	// 2. switch in the app's apply order: items as listed, "app" is the
	// image deploy / restart point; anything unlisted follows, app last
	byKey := map[string][]v1.Asset{}
	for _, a := range d.Assets {
		byKey[a.From] = append(byKey[a.From], a)
	}
	inOrder := map[string]bool{}
	steps := append([]string(nil), d.Order...)
	for _, k := range steps {
		inOrder[k] = true
	}
	for k := range byKey {
		if !inOrder[k] {
			steps = append(steps, k)
		}
	}
	if !inOrder[v1.ApplyOrderApp] {
		steps = append(steps, v1.ApplyOrderApp)
	}
	appAt := -1
	for i, k := range steps {
		if k == v1.ApplyOrderApp {
			appAt = i
		}
	}
	var switched []string
	for i, k := range steps {
		if k == v1.ApplyOrderApp {
			if !relChanged {
				continue
			}
			if !c.update(ctx, d, fetched) { // deploy failed: c.failed is set and the console withholds the release
				c.mu.Lock()
				c.snapBusy = false
				c.mu.Unlock()
				return
			}
			c.waitHealthy(ctx, 60*time.Second)
			switched = append(switched, "app")
			continue
		}
		list := byKey[k]
		if len(list) == 0 || !assetsChanged {
			continue
		}
		results := assets.Activate(list, assets.Options{Cache: c.cfg.Cache, Log: c.log})
		var changed []string
		hooks := map[string]string{}
		for _, r := range results {
			if r.Err != nil {
				c.log("snapshot %s: switching %s/%s: %v", d.Snapshot, k, r.Name, r.Err)
				c.event("snapshot_failed", fmt.Sprintf("switching %s failed: %v", r.Name, r.Err), d.ReleaseID)
				c.recordAssetStates(results)
				finish(true, r.Err)
				return
			}
			if r.Changed {
				changed = append(changed, r.Name)
				for _, a := range list {
					if a.Name == r.Name {
						hooks[a.Name] = a.OnChange
					}
				}
			}
		}
		if len(changed) > 0 {
			switched = append(switched, k)
			// a restart or signal is pointless when the app is (re)deployed later in this switch
			skipRestartHooks := relChanged && appAt > i
			c.runAssetHooks(ctx, changed, hooks, skipRestartHooks)
		}
	}
	// 3. record
	c.mu.Lock()
	if assetsChanged {
		c.assetsHash = d.AssetsHash
	}
	states := make([]v1.AssetState, 0, len(d.Assets))
	for _, a := range d.Assets {
		states = append(states, v1.AssetState{Name: a.Name, From: a.From, Digest: a.Digest, Path: a.UnpackTo + "/" + a.Name + "/current", UpdatedAt: time.Now()})
	}
	c.assetsState = states
	delete(c.snapAttempts, d.Snapshot)
	c.snapBusy = false
	c.mu.Unlock()
	c.saveState()
	if assetsChanged && len(switched) > 0 { // a release-only move is already reported by update_ok
		c.event("snapshot_applied", fmt.Sprintf("switched in order: %s", strings.Join(switched, " → ")), d.ReleaseID)
	}
}

func (c *Controller) recordAssetStates(results []assets.Result) {
	if len(results) == 0 {
		return
	}
	states := make([]v1.AssetState, 0, len(results))
	for _, r := range results {
		st := v1.AssetState{Name: r.Name, From: r.From, Digest: r.Digest, Path: r.Path, UpdatedAt: time.Now()}
		if r.Err != nil {
			st.Error = r.Err.Error()
		}
		states = append(states, st)
	}
	c.mu.Lock()
	c.assetsState = states
	c.mu.Unlock()
}

// waitHealthy blocks until the app started by the last deploy has passed a
// health probe (a fresh monitor reports healthy before its first check, so
// Healthy alone says nothing about the new process), or until max.
func (c *Controller) waitHealthy(ctx context.Context, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		snap := c.sup.Snapshot()
		if snap.Ready && !snap.Transitioning && snap.Health.LastOK.After(snap.DeployedAt) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	c.log("app not healthy within %s; continuing with the next item", max)
}

// runAssetHooks applies each changed asset's on_change: one restart at most,
// signals and exec commands as given.
func (c *Controller) runAssetHooks(ctx context.Context, changed []string, hooks map[string]string, skipRestart bool) {
	restart := false
	for _, n := range changed {
		h := hooks[n]
		switch {
		case h == "" || h == "none":
		case skipRestart && (h == "restart" || strings.HasPrefix(h, "signal:")):
			c.log("asset %s: %s skipped, the app is redeployed in this rollout", n, h)
		case h == "restart":
			restart = true
		case strings.HasPrefix(h, "signal:"):
			sig, ok := signalByName(strings.TrimPrefix(h, "signal:"))
			if !ok {
				c.log("asset %s: unknown signal %q", n, h)
				continue
			}
			if err := c.sup.Signal(sig); err != nil {
				c.log("asset %s: %s: %v", n, h, err)
			} else {
				c.log("asset %s: sent %s to the app", n, strings.TrimPrefix(h, "signal:"))
			}
		case strings.HasPrefix(h, "exec:"):
			cmd := strings.TrimPrefix(h, "exec:")
			cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			out, err := exec.CommandContext(cctx, "/bin/sh", "-c", cmd).CombinedOutput()
			cancel()
			if err != nil {
				c.log("asset %s: exec %q: %v: %s", n, cmd, err, strings.TrimSpace(string(out)))
				c.event("assets_hook_failed", fmt.Sprintf("%s: %q: %v", n, cmd, err), "")
			} else {
				c.log("asset %s: exec %q ok", n, cmd)
			}
		}
	}
	if restart {
		if err := c.sup.Restart("assets updated"); err != nil {
			c.log("assets: restart: %v", err)
		}
	}
}

func signalByName(name string) (syscall.Signal, bool) {
	switch strings.ToUpper(strings.TrimPrefix(name, "SIG")) {
	case "HUP":
		return syscall.SIGHUP, true
	case "USR1":
		return syscall.SIGUSR1, true
	case "USR2":
		return syscall.SIGUSR2, true
	case "TERM":
		return syscall.SIGTERM, true
	case "INT":
		return syscall.SIGINT, true
	case "QUIT":
		return syscall.SIGQUIT, true
	case "WINCH":
		return syscall.SIGWINCH, true
	}
	return 0, false
}

// logPusher streams application output while the Console keeps asking for it
// (a heartbeat or a push reply with want=true within the last 30 s). The first
// batch after a fresh request is the recent tail so a viewer sees context.
func (c *Controller) logPusher(ctx context.Context) {
	var wantedUntil time.Time
	var since int64
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case have := <-c.logWant:
			if time.Now().After(wantedUntil) {
				// new viewer: start from what the console holds, or the last 200 lines
				since = have
				if have == 0 {
					if tail := c.logs.Since(0, 200); len(tail) > 0 {
						since = tail[0].Seq - 1
					}
				}
			}
			wantedUntil = time.Now().Add(30 * time.Second)
		case <-tick.C:
		}
		if time.Now().After(wantedUntil) {
			continue
		}
		lines := c.logs.Since(since, 500)
		if len(lines) == 0 {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ack, err := c.cli.PostLogs(cctx, lines)
		cancel()
		if err != nil {
			c.log("logs: %v", err)
			continue
		}
		since = lines[len(lines)-1].Seq
		if ack.Want {
			wantedUntil = time.Now().Add(30 * time.Second)
		} else {
			wantedUntil = time.Time{}
		}
	}
}

func authOf(a *v1.RegistryAuth) *registry.Auth {
	if a == nil || a.Secret == "" {
		return nil
	}
	return &registry.Auth{Registry: a.Registry, Username: a.Username, Secret: a.Secret, Type: a.Type, SessionToken: a.SessionToken, RoleARN: a.RoleARN, Region: a.Region}
}

// startBaked runs the application already present in the rootfs of a baked
// image and records it as the current release under id.
func (c *Controller) startBaked(bk *baked.Info, id string) {
	rel := &release{ReleaseID: id, Image: bk.Image, Digest: bk.Digest, IndexDigest: bk.IndexDigest, Platform: bk.Platform, PathsFile: baked.PathsFile}
	c.mu.Lock()
	c.current = rel
	c.mu.Unlock()
	man, err := manifest.Load("/", "")
	if err != nil {
		c.log("baked manifest: %v (using defaults)", err)
		man = manifest.Defaults()
	}
	c.sup.SetInfo(map[string]any{
		"release":      map[string]any{"id": id, "reference": bk.Image, "digest": bk.Digest, "platform": bk.Platform, "baked": true},
		"supervisor":   c.cfg.SupervisorVer,
		"installation": c.installationID(),
	})
	c.log("starting baked release %s (%s) from the image rootfs", bk.Image, bk.Digest[:19])
	if err := c.sup.Deploy(bk.Runtime, man, nil); err != nil {
		c.log("baked start failed: %v", err)
		c.mu.Lock()
		c.lastErr = err.Error()
		c.mu.Unlock()
		c.setPhase("failed")
		return
	}
	c.setPhase("running")
	c.event("baked_start", fmt.Sprintf("running baked release (%s)", bk.Digest[:19]), id)
}

func (c *Controller) installationID() string {
	if c.ident != nil {
		return c.ident.InstallationID
	}
	return ""
}

// runStandalone supervises the baked application with no Console at all.
func (c *Controller) runStandalone(ctx context.Context, bk *baked.Info) (int, error) {
	c.log("no console configured: running baked release %s standalone (set FLEETWIDE_KEY to enable updates)", bk.Digest[:19])
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
	c.startBaked(bk, "baked")
	select {
	case <-ctx.Done():
		return 0, nil
	case r := <-supDone:
		return r.code, r.err
	}
}

// update brings the container onto the desired release: stages it while the
// old application runs, swaps in the gap, and records state. fetched is the
// image runSnapshot already pulled, or nil to fetch here.
func (c *Controller) update(ctx context.Context, d *v1.Desired, fetched *rootfs.Fetched) bool {
	c.mu.Lock()
	old := c.current
	c.mu.Unlock()
	initial := old == nil
	if d.Image == "" {
		// Assets-only release (assets / model apps without a serving image):
		// nothing to run; record it, deliver the assets, sit idle.
		rel := &release{ReleaseID: d.ReleaseID, Env: flattenEnv(d.Env), EnvHash: d.EnvHash}
		c.mu.Lock()
		if old != nil && old.Image != "" {
			c.previous = old
		}
		c.current = rel
		c.updates++
		c.mu.Unlock()
		c.saveState()
		c.setPhase("idle")
		c.event("release_applied", fmt.Sprintf("%s is assets-only: %d asset(s) to deliver, no image to run", d.ReleaseID, len(d.Assets)), d.ReleaseID)
		return true
	}
	c.setPhase("updating")
	if initial {
		c.event("deploy_started", fmt.Sprintf("initial release %s (%s)", d.ReleaseID, shortDigest(d.Digest)), d.ReleaseID)
	} else {
		c.event("update_started", fmt.Sprintf("%s -> %s (%s)", old.ReleaseID, d.ReleaseID, shortDigest(d.Digest)), d.ReleaseID)
	}

	rel := &release{ReleaseID: d.ReleaseID, Image: d.Image, Digest: d.Digest, Platform: d.Platform, Insecure: d.Insecure, SkipVerify: d.SkipVerify, Manifest: d.Manifest,
		PathsFile: filepath.Join(c.cfg.StateDir, "paths", d.ReleaseID+".txt"), Auth: authOf(d.RegistryAuth), Env: flattenEnv(d.Env), EnvHash: d.EnvHash}
	rep, err := c.deploy(ctx, rel, true, fetched)
	var redeploy *RedeployError
	if errors.As(err, &redeploy) {
		// Not a failure of the release: this container cannot take it in
		// place. Say so, keep running what runs, never retry.
		c.markRedeploy(d.ReleaseID, redeploy.Reason)
		if c.sup.AppRunning() {
			c.setPhase("running")
		} else if c.emb != nil && c.emb.Start == embedded.StartLatest && !c.awaitLatest.IsZero() {
			c.setPhase("starting") // still waiting for a release it can take
		} else {
			c.setPhase("failed")
		}
		return false
	}
	if err != nil {
		c.log("update to %s failed: %v", d.ReleaseID, err)
		c.mu.Lock()
		c.failed = d.ReleaseID
		c.lastErr = err.Error()
		c.mu.Unlock()
		c.saveState()
		msg := err.Error()
		// A failure inside the gap leaves nothing running. The fleet's policy
		// decides: write the old release back from the cache and start it,
		// or leave the container down for the orchestrator to recreate. A
		// first deploy has nothing to fall back to.
		if !c.sup.AppRunning() {
			switch {
			case old == nil:
				msg += "; nothing running (no previous release)"
			case c.failurePolicy() == v1.OnFailureReport:
				c.sup.Park("update to " + d.ReleaseID + " failed; the fleet's policy is report")
				msg += "; policy is report: nothing running until the container is recreated (it starts " + old.ReleaseID + ")"
			default:
				if _, rerr := c.deploy(ctx, old, true, nil); rerr != nil {
					c.log("recovery to %s failed: %v", old.ReleaseID, rerr)
					msg += "; recovery to " + old.ReleaseID + " failed: " + rerr.Error()
					c.event("update_failed", msg, d.ReleaseID)
					c.setPhase("failed")
					return false
				}
				c.finishStaleStaging([]string{d.ReleaseID}, old) // what the failed release put in "/"
				msg += "; rolled back to " + old.ReleaseID
			}
		}
		c.event("update_failed", msg, d.ReleaseID)
		if c.sup.AppRunning() {
			c.setPhase("running")
		} else {
			c.setPhase("failed")
		}
		return false
	}
	c.mu.Lock()
	c.awaitLatest = time.Time{}
	c.previous = old
	c.current = rel
	c.pending = rel.ReleaseID
	if !initial {
		c.updates++
	}
	c.lastErr = ""
	c.mu.Unlock()
	c.saveState()
	c.setPhase("running")
	if initial {
		c.event("deployed", fmt.Sprintf("running %s; awaiting health confirmation; %s", d.ReleaseID, rep), d.ReleaseID)
	} else {
		c.event("update_ok", fmt.Sprintf("running %s; awaiting health confirmation; %s", d.ReleaseID, rep), d.ReleaseID)
	}
	return true
}

// stagingRoot is where a release is unpacked before it is committed. It must
// be on the same filesystem as "/": the commit moves files by hard link.
const stagingRoot = "/.fleetwide-staging"

// deployReport is how an update went, for the event the console keeps.
type deployReport struct {
	PullMS, StageMS int64
	Staged          bool // false: "/" was short of room and the image was extracted in the gap
	Swap            supervise.Swap
}

func (r deployReport) String() string {
	down := time.Duration(r.Swap.StopMS+r.Swap.PrepareMS+r.Swap.StartMS) * time.Millisecond
	how := "commit"
	if !r.Staged {
		how = "extract"
	}
	return fmt.Sprintf("down %s (stop %dms, %s %dms, start %dms); pull %dms, stage %dms before it",
		down.Round(100*time.Millisecond), r.Swap.StopMS, how, r.Swap.PrepareMS, r.Swap.StartMS, r.PullMS, r.StageMS)
}

// fetchOptions are the rootfs options for a release aimed at "/". The
// platform is always this container's own: an index is resolved here, by the
// supervisor that has to run the result.
func (c *Controller) fetchOptions(insecure, skipVerify bool, auth *registry.Auth, digest string) rootfs.Options {
	o := rootfs.Options{
		Cache: c.cfg.Cache, Platform: c.cfg.Platform, Root: "/", Chown: true, Insecure: insecure, SkipVerify: skipVerify,
		Auth: auth, ExpectDigest: digest,
		Protected: append([]string{c.cfg.StateDir, stagingRoot}, c.assetDirsSnapshot()...), Log: c.log, Progress: c.dl,
	}
	if !c.cfg.SkipSpaceCheck {
		o.Preflight = c.spaceCheck
	}
	return o
}

// stageFactor is how many times its compressed size an image is assumed to
// take once extracted; deliberately loose, so only an image that certainly
// cannot fit is refused.
const stageFactor = 3

// freeSpace is fsinfo.Free, replaceable so a test can make a disk small.
var freeSpace = freeSpaceDefault

func freeSpaceDefault(path string) (uint64, uint64, bool) { return fsinfo.Free(path) }

// spaceCheck runs between resolve and pull, with the old application running
// and nothing written. It refuses the pull when the uncached layers do not
// fit the cache dir (after trimming the cache with the incoming layers kept)
// or "/" cannot hold even the compressed image; when "/" merely lacks room
// for a staged copy, the release is extracted in the gap instead. When the
// cache dir lives on "/" the two share one pool.
func (c *Controller) spaceCheck(img *registry.Image) error {
	var need, compressed int64
	layers := make([]string, 0, len(img.Layers))
	for _, l := range img.Layers {
		layers = append(layers, l.Digest)
		compressed += l.Size
		if !c.cfg.Cache.Has(l.Digest) {
			need += l.Size
		}
	}
	cacheDir := c.cfg.Cache.Dir()
	shared := rootfs.SameFilesystem(cacheDir, "/")

	free, total, ok := freeSpace(cacheDir)
	if ok && int64(free) < need {
		c.retain(layers)
		free, total, ok = freeSpace(cacheDir)
	}
	if ok && int64(free) < need {
		return fmt.Errorf("layer cache on %s: %s needed for %d layer(s) not yet cached, %s of %s free after trimming", cacheDir, humanBytes(need), uncached(img, c.cfg.Cache), humanBytes(int64(free)), humanBytes(int64(total)))
	}

	rootFree, rootTotal, rok := freeSpace("/")
	if !rok {
		return nil
	}
	avail := int64(rootFree)
	if shared {
		avail -= need // the pull lands here too
	}
	stageNeed := compressed * stageFactor
	c.mu.Lock()
	c.noStage = ""
	if avail < stageNeed {
		c.noStage = img.Digest
	}
	c.mu.Unlock()
	switch {
	case avail < compressed:
		return fmt.Errorf("root filesystem: %s free of %s, less than the image's %s compressed; nothing can be written", humanBytes(avail), humanBytes(int64(rootTotal)), humanBytes(compressed))
	case avail < stageNeed:
		c.log("space: / has %s free of %s, image is %s compressed (×%d = %s): extracting in the gap instead of staging", humanBytes(avail), humanBytes(int64(rootTotal)), humanBytes(compressed), stageFactor, humanBytes(stageNeed))
	default:
		c.log("space: / %s free of %s, cache %s free, image %s compressed (%s to pull)", humanBytes(avail), humanBytes(int64(rootTotal)), humanBytes(int64(free)), humanBytes(compressed), humanBytes(need))
	}
	return nil
}

func uncached(img *registry.Image, cache *layercache.Cache) int {
	n := 0
	for _, l := range img.Layers {
		if !cache.Has(l.Digest) {
			n++
		}
	}
	return n
}

// deploy brings rel onto the container in three moves, only the last of
// which touches what the application can see:
//
//	fetch   resolve, verify the pinned digest, pull into the layer cache
//	stage   unpack into stagingRoot/<release>, under "/" but out of the way
//	commit  in the supervisor's gap — old app gone, new one not started —
//	        move the staged tree into "/", read the manifest, record paths,
//	        remove the previous release's residue
//
// Everything up to the stop can fail and the old application keeps running
// on an untouched root. fetched, when given, is the image runSnapshot already
// pulled. When cleanup is true the previous release's residue is removed.
func (c *Controller) deploy(ctx context.Context, rel *release, cleanup bool, fetched *rootfs.Fetched) (deployReport, error) {
	if c.emb != nil {
		return c.deployEmbedded(ctx, rel, cleanup)
	}
	var rep deployReport
	if fetched == nil || !fetched.Image.Matches(rel.Digest) {
		ref, err := registry.PinByDigest(rel.Image, rel.Digest, rel.Insecure)
		if err != nil {
			return rep, err
		}
		fetched, err = rootfs.Fetch(ctx, ref, c.fetchOptions(rel.Insecure, rel.SkipVerify, rel.Auth, rel.Digest))
		if err != nil {
			return rep, fmt.Errorf("fetch: %w", err)
		}
	}
	if !fetched.Image.Matches(rel.Digest) {
		return rep, fmt.Errorf("digest mismatch: console said %s, registry served %s", rel.Digest, fetched.Image.Digest)
	}
	rel.Layers = fetched.Layers()
	rel.IndexDigest = fetched.Image.IndexDigest
	rep.PullMS = fetched.PullMS
	plat := fetched.Image.Platform

	// Stage while the old application runs. Only a shortage of room falls
	// back to extracting in the gap; anything else is a plain failure now,
	// with nothing stopped and nothing in "/" changed.
	t0 := time.Now()
	stagedDir, err := c.stageRelease(fetched, rel)
	if err != nil {
		return rep, err
	}
	rep.StageMS, rep.Staged = time.Since(t0).Milliseconds(), stagedDir != ""

	c.mu.Lock()
	old, h := c.current, c.health
	c.mu.Unlock()
	c.sup.SetInfo(map[string]any{
		"release":      map[string]any{"id": rel.ReleaseID, "reference": rel.Image, "digest": rel.Digest, "platform": plat.String()},
		"supervisor":   c.cfg.SupervisorVer,
		"installation": c.ident.InstallationID,
	})
	c.sup.SetExtraEnv(rel.Env, false) // applied by the swap; no separate restart

	sw, err := c.sup.DeployWith(func() (supervise.Prepared, error) {
		return c.commitRelease(fetched, stagedDir, rel, old, h, cleanup)
	})
	rep.Swap = sw
	if stagedDir != "" {
		// Committed leaves are gone from it already; what is left is empty
		// directories, or the whole tree on a failure.
		os.RemoveAll(stagedDir)
	}
	if err != nil {
		return rep, err
	}
	c.log("swap %s: %s", rel.ReleaseID, rep)
	return rep, nil
}

// staleStaging lists releases with a staging directory left from a run that
// did not finish — a crash while staging (harmless) or mid-commit (some of
// that release's files are in "/" while current is something else).
func (c *Controller) staleStaging(currentID string) []string {
	entries, err := os.ReadDir(stagingRoot)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != currentID {
			out = append(out, e.Name())
		}
	}
	return out
}

// finishStaleStaging runs after current has been written back over "/":
// whatever a half-committed release left in "/" that current does not have
// is residue, and its paths file — written before the commit began — says
// what that is.
func (c *Controller) finishStaleStaging(ids []string, cur *release) {
	if len(ids) == 0 {
		return
	}
	curPaths, _ := readPaths(cur.PathsFile)
	protected, _ := rootfs.ProtectedPaths("/", append([]string{c.cfg.Cache.Dir(), c.cfg.StateDir, stagingRoot}, c.assetDirsSnapshot()...)...)
	for _, id := range ids {
		pf := filepath.Join(c.cfg.StateDir, "paths", id+".txt")
		if stale, err := readPaths(pf); err == nil && len(stale) > 0 {
			removed := c.removeResidue(stale, curPaths, protected)
			c.log("cleaned up %d entries left by the interrupted update to %s", removed, id)
			os.Remove(pf)
		}
		os.RemoveAll(filepath.Join(stagingRoot, id))
	}
}

// stageRelease unpacks a fetched release under stagingRoot and returns the
// directory, or "" when "/" has no room for a staged copy and the image is
// to be extracted in the gap instead. A partial tree is removed before
// returning.
func (c *Controller) stageRelease(f *rootfs.Fetched, rel *release) (string, error) {
	dir := filepath.Join(stagingRoot, rel.ReleaseID)
	c.mu.Lock()
	skip := c.noStage != "" && c.noStage == f.Image.Digest
	c.noStage = ""
	c.mu.Unlock()
	if skip {
		return "", nil // the preflight said "/" cannot hold a staged copy
	}
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if errors.Is(err, syscall.EROFS) {
			return "", fmt.Errorf("the root filesystem is read-only: Fleetwide updates the application in place and needs a writable rootfs (%w)", err)
		}
		return "", fmt.Errorf("staging dir: %w", err)
	}
	res, err := f.ApplyTo(dir)
	if err != nil {
		used := treeSize(dir)
		os.RemoveAll(dir)
		if errors.Is(err, syscall.ENOSPC) {
			free, _, _ := fsinfo.Free("/")
			c.log("staging %s: no space left on / after %s (%s free); extracting in the gap instead", rel.ReleaseID, humanBytes(used), humanBytes(int64(free)))
			return "", nil
		}
		return "", fmt.Errorf("stage: %w", err)
	}
	var compressed int64
	for _, l := range f.Image.Layers {
		compressed += l.Size
	}
	ratio := 0.0
	if compressed > 0 {
		ratio = float64(res.Stats.BytesWriten) / float64(compressed)
	}
	c.log("staged %s: %d files, %d dirs, %s in %dms (%.1f× the %s compressed)", rel.ReleaseID, res.Stats.Files, res.Stats.Dirs, humanBytes(res.Stats.BytesWriten), res.UnpackMS, ratio, humanBytes(compressed))
	return dir, nil
}

// commitRelease runs in the supervisor's gap. It writes the release into "/"
// — by moving the staged tree, or by extracting when nothing was staged —
// then reads the manifest, records the paths and removes the previous
// release's residue, in that order: the paths file is the record cleanup and
// the next start depend on.
func (c *Controller) commitRelease(f *rootfs.Fetched, stagedDir string, rel, old *release, h *v1.Healthcheck, cleanup bool) (supervise.Prepared, error) {
	var paths, protected []string
	manifestRoot := "/"
	if stagedDir != "" {
		// A crash between here and the rewrite below leaves this list, so
		// the next start knows what the half-committed release put in "/".
		if pre, err := rootfs.StagedPaths(stagedDir, "/"); err == nil {
			_ = writePaths(rel.PathsFile, pre)
		}
		var err error
		protected, err = rootfs.ProtectedPaths("/", append([]string{c.cfg.Cache.Dir(), c.cfg.StateDir, stagingRoot}, c.assetDirsSnapshot()...)...)
		if err != nil {
			return supervise.Prepared{}, err
		}
		cres, err := rootfs.Commit(stagedDir, "/", rootfs.CommitOptions{Protected: protected, Chown: true, Log: c.log, Warn: func(f string, a ...any) { c.log("warn: "+f, a...) }})
		if err != nil {
			return supervise.Prepared{}, fmt.Errorf("commit: %w", err)
		}
		paths = cres.Paths
	} else {
		res, err := f.Apply()
		if err != nil {
			return supervise.Prepared{}, fmt.Errorf("extract: %w", err)
		}
		paths, protected = res.Paths, res.Protected
	}

	var man *manifest.Manifest
	var err error
	if rel.Manifest != "" {
		man, err = manifest.Parse([]byte(rel.Manifest), "console")
	} else {
		man, err = manifest.Load(manifestRoot, "")
	}
	if err != nil {
		return supervise.Prepared{}, err
	}
	if man.Ready.Listen != "" {
		c.sup.EnableReady(man.Ready.Listen)
	}
	if h != nil {
		man.Health = mergeHealth(man.Health, h) // the console's definition wins over the image's
		c.sup.EnableReady(h.ReadyListen)
	}
	if err := writePaths(rel.PathsFile, paths); err != nil {
		return supervise.Prepared{}, err
	}
	// Residue last: files the old release had and the new one does not,
	// removed with nothing running.
	if cleanup && old != nil && old.PathsFile != rel.PathsFile {
		oldPaths, _ := readPaths(old.PathsFile)
		removed := c.removeResidue(oldPaths, paths, protected)
		c.log("residue cleanup: removed %d entries left by %s", removed, old.ReleaseID)
	}
	return supervise.Prepared{Runtime: f.Runtime, Manifest: man}, nil
}

// treeSize is what a directory holds, for a log line.
func treeSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, e := d.Info(); e == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// onUnhealthyFor is consulted by the supervisor before an in-place restart.
// A release that has never been confirmed healthy is rolled back instead.
func (c *Controller) onUnhealthyFor(st health.State) bool {
	c.mu.Lock()
	pending, prev, cur := c.pending, c.previous, c.current
	c.mu.Unlock()
	if pending == "" || cur == nil || cur.ReleaseID != pending {
		return false // confirmed release: let the supervisor restart it in place
	}
	if c.failurePolicy() == v1.OnFailureReport {
		// Report policy: stop, record the failure, stay down so an
		// orchestrator recreates the container. The previous release, where
		// there is one, is recorded as the one to start on.
		c.event("update_failed", fmt.Sprintf("%s unhealthy for %s (%s) before confirmation; policy is report: stopped, nothing running until the container is recreated", cur.ReleaseID, st.UnhealthyFor.Round(time.Second), st.LastError), cur.ReleaseID)
		c.sup.Park("release " + cur.ReleaseID + " unhealthy before confirmation; the fleet's policy is report")
		c.mu.Lock()
		c.failed = cur.ReleaseID
		if prev != nil {
			c.current, c.previous = prev, nil
		}
		c.pending = ""
		c.lastErr = cur.ReleaseID + " unhealthy before confirmation: " + st.LastError
		c.mu.Unlock()
		c.saveState()
		c.setPhase("failed")
		return true
	}
	if prev == nil {
		return false // nothing to roll back to: let the supervisor restart within its budget
	}
	c.setPhase("rolling_back")
	c.event("rollback", fmt.Sprintf("%s unhealthy for %s (%s) before confirmation; rolling back to %s", cur.ReleaseID, st.UnhealthyFor.Round(time.Second), st.LastError, prev.ReleaseID), cur.ReleaseID)
	// Intent first: a container killed mid-rollback must come back on prev,
	// never on the release being escaped. In memory current stays cur until
	// the swap, so residue cleanup knows whose files to remove.
	c.persistReleases(prev, nil, cur.ReleaseID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := c.deploy(ctx, prev, true, nil); err != nil {
		c.log("rollback failed: %v", err)
		c.mu.Lock()
		c.failed = cur.ReleaseID
		c.current, c.previous = prev, nil
		c.pending = ""
		c.lastErr = "rollback failed: " + err.Error()
		c.mu.Unlock()
		c.saveState()
		c.setPhase("failed")
		c.event("rollback_failed", "rollback to "+prev.ReleaseID+" failed: "+err.Error()+"; nothing running until the container is recreated", cur.ReleaseID)
		return false
	}
	c.mu.Lock()
	c.failed = cur.ReleaseID
	c.current = prev
	c.previous = nil
	c.pending = "" // the previous release was confirmed before
	c.lastErr = "rolled back from " + cur.ReleaseID + ": " + st.LastError
	c.mu.Unlock()
	c.saveState()
	c.setPhase("running")
	c.event("rollback_ok", "running "+prev.ReleaseID+" again", prev.ReleaseID)
	return true
}

// settle acts on the console's word that the whole deployment is on the
// release this container runs: the previous release is forgotten and the
// layer cache trimmed to what remains. Only once the release is confirmed
// here too, and never while a snapshot or asset sync is in flight.
func (c *Controller) settle(id string) {
	c.mu.Lock()
	cur := c.current
	skip := id == "" || cur == nil || cur.ReleaseID != id || c.pending != "" || c.snapBusy || c.assetsSyncing || c.settled == id
	if !skip {
		c.settled = id
	}
	hadPrev := c.previous != nil
	if !skip {
		c.previous = nil
	}
	c.mu.Unlock()
	if skip {
		return
	}
	if hadPrev {
		c.saveState()
		c.log("deployment settled on %s: previous release forgotten", id)
	}
	c.retain(nil)
}

// retain trims the layer cache to the blobs this container can still need:
// current's layers, previous's while it is remembered, the live assets'
// digests, and extra (an incoming release's layers at preflight). A current
// whose layers are not recorded stops retention altogether. No age floor:
// every pull runs behind snapBusy or assetsSyncing, which the callers check.
func (c *Controller) retain(extra []string) {
	keep := map[string]bool{}
	add := func(ds []string) {
		for _, d := range ds {
			if d != "" {
				keep[d] = true
			}
		}
	}
	c.mu.Lock()
	cur, prev := c.current, c.previous
	if cur != nil {
		add(cur.Layers)
	}
	if prev != nil {
		add(prev.Layers)
	}
	for _, a := range c.assetsState {
		keep[a.Digest] = true
	}
	c.mu.Unlock()
	add(extra)
	if cur != nil && cur.Image != "" && len(cur.Layers) == 0 {
		c.log("layer cache: not trimmed, the running release's layers are not recorded")
		return
	}
	r, err := c.cfg.Cache.Retain(keep, 0)
	if err != nil {
		c.log("layer cache: %v", err)
		return
	}
	if r.Blobs > 0 || r.Temps > 0 {
		size, n := c.cfg.Cache.Size()
		c.log("layer cache: removed %d blob(s) (%s) and %d abandoned download(s); %d blob(s), %s kept", r.Blobs, humanBytes(r.Bytes), r.Temps, n, humanBytes(size))
	}
}

// failurePolicy is the fleet's answer to a release that fails after the old
// application has stopped: rollback (the default) or report.
func (c *Controller) failurePolicy() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.onFailure == v1.OnFailureReport {
		return v1.OnFailureReport
	}
	return v1.OnFailureRollback
}

// ---- state files ----

func (c *Controller) saveState() {
	c.mu.Lock()
	cur, prev, failed := c.current, c.previous, c.failed
	c.mu.Unlock()
	c.persistReleases(cur, prev, failed)
}

// persistReleases writes the release files and meta.json with the given
// releases and failed id in place of the in-memory ones: how a rollback
// records where a recreated container must land before it starts moving.
func (c *Controller) persistReleases(cur, prev *release, failed string) {
	c.mu.Lock()
	m := meta{FailedReleaseID: failed, RedeployRequired: c.redeploy, Updates: c.updates, AssetsHash: c.assetsHash, Assets: c.assetsState}
	c.mu.Unlock()
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		p := filepath.Join(c.cfg.StateDir, "meta.json")
		os.WriteFile(p+".tmp", b, 0o600)
		os.Rename(p+".tmp", p)
	}
	write := func(name string, r *release) {
		p := filepath.Join(c.cfg.StateDir, name)
		if r == nil {
			os.Remove(p)
			return
		}
		b, _ := json.MarshalIndent(r, "", "  ")
		os.WriteFile(p+".tmp", b, 0o600)
		os.Rename(p+".tmp", p)
	}
	write("current.json", cur)
	write("previous.json", prev)
}

func (c *Controller) loadRelease(name string) *release {
	b, err := os.ReadFile(filepath.Join(c.cfg.StateDir, name))
	if err != nil {
		return nil
	}
	var r release
	if json.Unmarshal(b, &r) != nil || r.Digest == "" {
		return nil
	}
	return &r
}

func writePaths(file string, paths []string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	f, err := os.Create(file + ".tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, p := range paths {
		w.WriteString(p)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(file+".tmp", file)
}

func readPaths(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// removeResidue deletes entries written by the old release that the new one
// did not write: deepest first, directories only when empty, protected paths
// never.
func (c *Controller) removeResidue(oldPaths, newPaths, protected []string) int {
	keep := make(map[string]struct{}, len(newPaths))
	for _, p := range newPaths {
		keep[p] = struct{}{}
	}
	isProtected := func(p string) bool {
		for _, pr := range protected {
			if p == pr || strings.HasPrefix(p, pr+"/") || strings.HasPrefix(pr, p+"/") {
				return true
			}
		}
		return false
	}
	var victims []string
	for _, p := range oldPaths {
		if _, ok := keep[p]; !ok && !isProtected(p) {
			victims = append(victims, p)
		}
	}
	// A name the old release wrote can resolve elsewhere in the new one
	// (/bin/sh once /bin became a symlink to usr/bin); a victim that now
	// lands on a file of the new release is left alone.
	victims = dropResolvingIntoNewRelease(victims, newPaths)
	victims = dropResolvingIntoProtected(victims, protected)
	sort.Slice(victims, func(i, j int) bool { return len(victims[i]) > len(victims[j]) }) // deepest first
	n := 0
	for _, p := range victims {
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			if os.Remove(p) == nil { // only when empty
				n++
			}
			continue
		}
		if os.Remove(p) == nil {
			n++
		}
	}
	return n
}

// dropResolvingIntoProtected removes victims whose real location is under a
// protected mount. unlink follows every directory symlink but the last
// component, so with /a -> /data, removing "/a/file" removes /data/file on
// the volume.
func dropResolvingIntoProtected(victims, protected []string) []string {
	// Both sides resolved: a protected entry can itself sit behind a symlinked
	// directory.
	real := make([]string, 0, len(protected))
	for _, pr := range protected {
		if rp, err := filepath.EvalSymlinks(pr); err == nil {
			real = append(real, rp)
		} else {
			real = append(real, pr)
		}
	}
	out := make([]string, 0, len(victims))
	for _, p := range victims {
		rp, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err == nil {
			v := filepath.Join(rp, filepath.Base(p))
			under := false
			for _, pr := range real {
				if v == pr || strings.HasPrefix(v, pr+"/") {
					under = true
					break
				}
			}
			if under {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// dropResolvingIntoNewRelease removes from the victim list every path that,
// followed through the symlinks now on disk, lands on a file the new release
// wrote. Both sides are resolved: the new release's own paths may run through
// symlinked directories too.
func dropResolvingIntoNewRelease(victims, newPaths []string) []string {
	real := make(map[string]struct{}, len(newPaths))
	for _, p := range newPaths {
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			real[rp] = struct{}{}
		}
	}
	out := make([]string, 0, len(victims))
	for _, p := range victims {
		rp, err := filepath.EvalSymlinks(p)
		if err == nil && rp != p {
			if _, ok := real[rp]; ok {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "-"
	}
	return s
}

func kernel() string {
	if runtime.GOOS != "linux" {
		return runtime.GOOS
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	if d == "" {
		return "no image"
	}
	return d
}

// resolveAuthEnv fills credentials the fleet chose to keep on the customer
// side: the console sent the environment variable name, the container has
// the value.
func resolveAuthEnv(d *v1.Desired, log func(string, ...any)) {
	fixAuthEnv(d.RegistryAuth, "the image registry", log)
	ResolveAssetAuthEnv(d.Assets, log)
}

// ResolveAssetAuthEnv is resolveAuthEnv for a bare asset list (the fetch-only
// command gets assets without a Desired around them).
func ResolveAssetAuthEnv(assets []v1.Asset, log func(string, ...any)) {
	for i := range assets {
		fixAuthEnv(assets[i].Auth, "asset "+assets[i].Name, log)
	}
}

func fixAuthEnv(a *v1.RegistryAuth, what string, log func(string, ...any)) {
	if a == nil || a.FromEnv == "" {
		return
	}
	if v := os.Getenv(a.FromEnv); v != "" {
		a.Secret = v
	} else {
		log("credential for %s: environment variable %s is not set in this container", what, a.FromEnv)
	}
}

// renewBefore is how long before expiry the supervisor asks for a new certificate.
const renewBefore = 30 * 24 * time.Hour

// maybeRenew swaps in a fresh certificate when the current one is within
// renewBefore of expiring. The new identity is saved before the client
// switches to it, because the console refuses the old certificate as soon
// as it has issued the new one.
func (c *Controller) maybeRenew(ctx context.Context) {
	now := time.Now()
	if c.ident == nil || !c.ident.RenewDue(now, renewBefore) || now.Sub(c.renewTried) < time.Hour {
		return
	}
	c.renewTried = now
	id, err := c.cli.Renew(ctx, c.ident)
	if err != nil {
		c.log("certificate renewal: %v (certificate valid until %s; retrying hourly)", err, c.ident.NotAfter.Format(time.RFC3339))
		return
	}
	if err := id.Save(filepath.Join(c.cfg.StateDir, "identity")); err != nil {
		c.log("certificate renewal: issued but could not be saved: %v", err)
		// The console now expects the new serial; use it in memory so this
		// process keeps working, and try the save again next hour.
	}
	cli, err := consoleclient.New(c.cfg.Console, id, c.cfg.InsecureTLS)
	if err != nil {
		c.log("certificate renewal: %v", err)
		return
	}
	c.mu.Lock()
	c.ident = id
	c.mu.Unlock()
	c.cli = cli
	c.log("certificate renewed; valid until %s", id.NotAfter.Format("2006-01-02"))
	c.event("certificate_renewed", "client certificate renewed", c.currentID())
}
