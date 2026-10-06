// Package v1 holds the wire types the Fleetwide Supervisor and the Console speak.
//
// This file is the supervisor protocol: enrollment, the heartbeat, desired state,
// health, telemetry and the deployment key.
//
// Enrollment is the one supervisor call made without a client certificate; it
// exchanges a one-time secret and a CSR for a certificate. Every later call
// authenticates with that certificate.
package v1

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// App runtimes.
const (
	RuntimeSupervisor = "supervisor"
	RuntimeEmbedded   = "embedded"
)

// Healthcheck is how the supervisor decides an application is healthy, plus the
// readiness endpoint it may expose for the customer's own probes. The app
// defines it; the fleet decides whether probes run at all and whether the
// endpoint is opened. It travels on the heartbeat, so a change takes effect
// without redeploying the app.
//
// Precedence, highest first: the fleet's switches, this definition, the
// image's manifest, the supervisor's defaults.
type Healthcheck struct {
	// The probe. With none of the three set the check is the process itself:
	// the app counts as healthy while it runs.
	HTTP string   `json:"http,omitempty"` // GET, 2xx/3xx healthy
	TCP  string   `json:"tcp,omitempty"`  // host:port connect
	Exec []string `json:"exec,omitempty"` // exit 0 healthy

	IntervalS        int    `json:"interval_s,omitempty"`
	TimeoutS         int    `json:"timeout_s,omitempty"`
	GraceS           int    `json:"grace_s,omitempty"` // failures ignored after (re)start
	FailureThreshold int    `json:"failure_threshold,omitempty"`
	OnUnhealthy      string `json:"on_unhealthy,omitempty"` // restart | ignore
	MaxRestarts      int    `json:"max_restarts,omitempty"`

	// ReadyListen is the supervisor's own endpoint mirroring the check
	// (/fleetwide/ready, /fleetwide/live), for orchestrator probes. Sent only
	// where the fleet asks for it.
	ReadyListen string `json:"ready_listen,omitempty"`

	// ProcessOnly is set by the console, never by the app: the fleet switched
	// probes off, so the running process is the only check.
	ProcessOnly bool `json:"process_only,omitempty"`
}

// The health actions, and the endpoint a fleet opens when it asks for
// readiness without the app naming an address.
const (
	OnUnhealthyRestart = "restart"
	OnUnhealthyReport  = "report" // keep the app running, report unhealthy to the console
	OnUnhealthyIgnore  = "ignore" // accepted as report

	DefaultReadyListen = ":9100"
)

// Kind names the check in use, matching the supervisor's manifest vocabulary.
func (h *Healthcheck) Kind() string {
	switch {
	case h == nil || h.ProcessOnly:
		return "process"
	case h.HTTP != "":
		return "http"
	case h.TCP != "":
		return "tcp"
	case len(h.Exec) > 0:
		return "exec"
	}
	return "process"
}

// Telemetry declares what an app exposes: the endpoints the supervisor scrapes
// and the metrics it promises to publish. A metric that is not declared is
// dropped at ingest.
type Telemetry struct {
	Scrape  []ScrapeTarget `json:"scrape,omitempty"`
	Metrics []MetricDecl   `json:"metrics,omitempty"`
}

// ScrapeTarget is an endpoint inside the container. The supervisor dials
// 127.0.0.1:<port> — the application is not exposed to anyone else for this.
type ScrapeTarget struct {
	Name      string `json:"name"`                 // shown in the console and in errors
	Port      int    `json:"port"`                 // on 127.0.0.1 inside the container
	Path      string `json:"path,omitempty"`       // default /metrics
	Format    string `json:"format,omitempty"`     // prometheus (the only one so far)
	IntervalS int    `json:"interval_s,omitempty"` // default 60, minimum 15
}

// MetricDecl is one metric the app publishes.
type MetricDecl struct {
	Name string `json:"name"`           // queue_depth
	Type string `json:"type,omitempty"` // gauge | counter
	Unit string `json:"unit,omitempty"` // requests, ms, bytes
	Help string `json:"help,omitempty"`
}

// Telemetry formats, metric types and the limits that keep a declaration and
// its data bounded.
const (
	ScrapePrometheus = "prometheus"

	MetricGauge   = "gauge"
	MetricCounter = "counter"

	MaxScrapeTargets  = 4
	MaxMetricDecls    = 40
	MinScrapeInterval = 15
	DefScrapeInterval = 60
	MaxScrapePoints   = 500 // points the supervisor may post at once
	MaxMetricLabels   = 6
	MaxLabelLen       = 64
)

// Declares reports whether this metric name is one the app promised.
func (t *Telemetry) Declares(name string) bool {
	if t == nil {
		return false
	}
	for _, m := range t.Metrics {
		if m.Name == name {
			return true
		}
	}
	return false
}

// Interval is the scrape period, with the default and floor applied.
func (s ScrapeTarget) Interval() time.Duration {
	n := s.IntervalS
	if n == 0 {
		n = DefScrapeInterval
	}
	if n < MinScrapeInterval {
		n = MinScrapeInterval
	}
	return time.Duration(n) * time.Second
}

// URL is the endpoint on the loopback interface inside the container.
func (s ScrapeTarget) URL() string {
	path := s.Path
	if path == "" {
		path = "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("http://127.0.0.1:%d%s", s.Port, path)
}

// ApplyOrderApp is the app's own entry in Desired.Order.
const ApplyOrderApp = "app"

// Failure policies (HeartbeatResponse.OnFailure).
const (
	OnFailureRollback = "rollback"
	OnFailureReport   = "report"
)

// EnvVar is a console-delivered environment variable. Precedence at run time
// is image ENV < channel Env < fleet Env < the container's own environment.
type EnvVar struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Secret bool   `json:"secret,omitempty"` // write-only in the console API; delivered to supervisors over mTLS
}

// BakedImage is the vendor image with the supervisor already inside it: it runs the
// application on its own with no console, and is adopted as this release the
// moment it is given a key.
type BakedImage struct {
	Ref               string    `json:"ref"`    // where it was pushed
	Digest            string    `json:"digest"` // of the baked image itself
	Platform          string    `json:"platform"`
	Variant           string    `json:"variant"` // supervisor image it carries: slim | telemetry | developer
	SupervisorVersion string    `json:"supervisor_version"`
	BakedAt           time.Time `json:"baked_at"`
}

// BakePlan is what the CLI needs to bake a release: what to pull, what to put
// inside it and what the result should say about itself. GET
// /v1/apps/{key}/bake?release=&profile=
type BakePlan struct {
	AppKey            string `json:"app_key"`
	ReleaseID         string `json:"release_id"`
	Version           string `json:"version"`
	Image             string `json:"image"`  // as registered
	Digest            string `json:"digest"` // what the baked image must contain
	Platform          string `json:"platform"`
	Insecure          bool   `json:"insecure,omitempty"`
	SkipVerify        bool   `json:"skip_verify,omitempty"`
	RegistryMode      string `json:"registry_mode,omitempty"`
	Variant           string `json:"variant"`          // resolved profile
	SupervisorImage   string `json:"supervisor_image"` // published image for that profile
	SupervisorVersion string `json:"supervisor_version"`
	// Console and CASHA256 are the public half of a deployment key, baked into
	// the image so it can say where it belongs. The secret is never baked.
	Console  string `json:"console,omitempty"`
	CASHA256 string `json:"ca_sha256,omitempty"`
	// Runtime and, for the embedded runtime, the paths the supervisor keeps in
	// sync and the asset paths: what `fleetwide embed` makes writable.
	Runtime    string   `json:"runtime,omitempty"`
	SyncPaths  []string `json:"sync_paths,omitempty"`
	AssetPaths []string `json:"asset_paths,omitempty"`
}

// RegistryAuth is what a supervisor uses to pull a release's layers.
type RegistryAuth struct {
	Registry string `json:"registry"`
	Username string `json:"username"` // registry: user; ecr: access key id
	Secret   string `json:"secret"`   // registry: password/token; ecr: secret access key; gar: service-account JSON key
	// FromEnv names a container environment variable the Supervisor reads the
	// secret from instead of Secret.
	FromEnv string `json:"from_env,omitempty"`
	Type    string `json:"type,omitempty"` // registry | ecr | gar | git
	Mode    string `json:"mode,omitempty"` // ecr / gar: identity (use the container's own) | key
	// ecr with keys: an optional session token and a role to assume with
	// the keys before asking ECR for a login. Region is derived from the
	// ECR host unless given.
	SessionToken string `json:"session_token,omitempty"`
	RoleARN      string `json:"role_arn,omitempty"`
	Region       string `json:"region,omitempty"`
}

// Asset is one item version as delivered to a container: the app's mapping
// (directory, hook) applied to the pinned version, with credentials attached.
type Asset struct {
	Name   string `json:"name"`   // item key; directory under UnpackTo
	Source string `json:"source"` // oci | git
	// Ref: oci → artifact reference (registry/repo:tag); git → repository URL.
	Ref string `json:"ref"`
	// Digest pins the content: oci → manifest digest; git → full commit SHA.
	Digest     string `json:"digest,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`    // plain-HTTP registry (test setups)
	SkipVerify bool   `json:"skip_verify,omitempty"` // accept any TLS certificate from the registry
	UnpackTo   string `json:"unpack_to"`             // absolute directory on the container (a mounted volume for sidecar/init use)
	// OnChange is what the Supervisor does after a new version is in place:
	// none | restart | signal:<SIGNAME> | exec:<command>.
	OnChange string `json:"on_change,omitempty"`
	Size     int64  `json:"size,omitempty"` // bytes when known (from the OCI manifest)
	Tag      string `json:"tag,omitempty"`  // the tag / branch / commit the vendor pinned (Digest is what it resolved to)
	From     string `json:"from,omitempty"` // item key (same as Name)
	// Auth is filled by the Console for the Supervisor only; never returned to vendors.
	Auth *RegistryAuth `json:"auth,omitempty"`
}

// AssetsRequest is the fetch-only call (init container / sidecar mode): a
// deployment key proves membership of a fleet; nothing is enrolled.
type AssetsRequest struct {
	AppKey string `json:"app_key"`
	Secret string `json:"secret"`
}

// AssetsResponse is the fleet's channel assets with credentials attached.
type AssetsResponse struct {
	AppKey     string  `json:"app_key"`
	FleetID    string  `json:"fleet_id"`
	Channel    string  `json:"channel"`
	ReleaseID  string  `json:"release_id,omitempty"`
	Assets     []Asset `json:"assets"`
	AssetsHash string  `json:"assets_hash"`
}

// Download is what the Supervisor is fetching right now: an image layer set or
// one asset. Reported while the fetch runs.
type Download struct {
	What      string    `json:"what"`            // image | asset
	Name      string    `json:"name"`            // image reference, or asset name
	Done      int64     `json:"done"`            // bytes fetched so far
	Total     int64     `json:"total,omitempty"` // 0 when the size is not known
	StartedAt time.Time `json:"started_at"`
}

// Pct is the share of the download that is done, or -1 when the total is
// unknown (nothing to show a bar for).
func (d *Download) Pct() int {
	if d == nil || d.Total <= 0 {
		return -1
	}
	p := int(d.Done * 100 / d.Total)
	if p > 100 {
		return 100
	}
	return p
}

// AssetState is what the Supervisor reports about one delivered asset.
type AssetState struct {
	Name      string    `json:"name"`
	From      string    `json:"from,omitempty"`
	Digest    string    `json:"digest"`
	Path      string    `json:"path"` // <unpack_to>/<name>/current
	UpdatedAt time.Time `json:"updated_at"`
	Error     string    `json:"error,omitempty"`
}

// Event is a notable transition reported by a supervisor.
type Event struct {
	At      time.Time `json:"at"`
	Type    string    `json:"type"` // enrolled | update_started | update_ok | update_failed | rollback | health_changed | restart
	Message string    `json:"message,omitempty"`
	Release string    `json:"release_id,omitempty"`
}

// ---- enrollment and the heartbeat ----

// EnrollRequest is sent once, over server-authenticated TLS only.
type EnrollRequest struct {
	AppKey            string `json:"app_key"`
	Secret            string `json:"secret"`
	CSR               string `json:"csr_pem"`
	SupervisorVersion string `json:"supervisor_version"`
	Platform          string `json:"platform"`
	// Hostname is shown in the console. Name is an optional display name
	// (FLEETWIDE_INSTANCE_NAME). The identity within the deployment is the
	// pod uid or container id below.
	Hostname string `json:"hostname,omitempty"`
	Name     string `json:"name,omitempty"`
	Runtime  string `json:"runtime,omitempty"` // k8s | swarm | docker | compose | other (detected)
	// What this supervisor can do, declared at enrollment: Variant is the image
	// (slim | telemetry | developer) and Capabilities the features that are
	// live on this container, the image's features minus the customer's vetoes.
	Variant      string   `json:"variant,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	// Detected identity of the pod/container (see SupervisorState).
	ContainerID string `json:"container_id,omitempty"`
	PodUID      string `json:"pod_uid,omitempty"`
	MachineID   string `json:"machine_id,omitempty"`
	BootID      string `json:"boot_id,omitempty"`
}

// RenewRequest asks for a fresh certificate over the mTLS session the current
// one still opens. Supervisors renew before their certificate expires; the
// installation is the current certificate's CN, never the body.
type RenewRequest struct {
	CSR string `json:"csr_pem"`
}

// RenewResponse carries the new certificate; the CA is unchanged.
type RenewResponse struct {
	Certificate string `json:"certificate_pem"`
	CA          string `json:"ca_pem"`
	NotAfter    string `json:"not_after"` // RFC 3339
}

// EnrollResponse carries the client certificate.
type EnrollResponse struct {
	InstallationID string `json:"installation_id"`
	Reenrolled     bool   `json:"reenrolled,omitempty"` // the same container (pod uid / container id) enrolled again and reclaimed its record
	Certificate    string `json:"certificate_pem"`
	CA             string `json:"ca_pem"`
	Channel        string `json:"channel"`
}

// SupervisorState is what the Supervisor reports on every heartbeat.
type SupervisorState struct {
	SupervisorVersion string `json:"supervisor_version"`
	Platform          string `json:"platform"`
	Hostname          string `json:"hostname,omitempty"`
	Kernel            string `json:"kernel,omitempty"`
	UptimeS           int64  `json:"uptime_s"`
	Baked             bool   `json:"baked,omitempty"` // running from a `fleetwide bake` image (fallback release present)
	// Deployment is filled by the console from the deployment the container
	// belongs to; Name is the display name the supervisor reports
	// (FLEETWIDE_INSTANCE_NAME); Runtime is detected.
	Deployment string `json:"deployment,omitempty"`
	Name       string `json:"name,omitempty"`
	Runtime    string `json:"runtime,omitempty"`
	// Variant is the supervisor image (slim | telemetry | developer) and
	// Capabilities the features compiled into it that are live here.
	Variant      string       `json:"variant,omitempty"`
	Capabilities []string     `json:"capabilities,omitempty"`
	Tunnel       *TunnelState `json:"tunnel,omitempty"`
	// MissingCaps are Linux capabilities the supervisor needs that this container
	// does not hold: required ones (updates fail without them) and optional
	// ones (device nodes and file capabilities in images are not reproduced).
	MissingCaps []string `json:"missing_caps,omitempty"`
	// TelemetryMissing lists declared metrics the app's endpoints did not expose
	// at the last scrape.
	TelemetryMissing []string `json:"telemetry_missing,omitempty"`
	// AppRuntime is supervisor or embedded (Runtime above is the orchestrator).
	// EmbeddedDigest is the customer image the embedded image was built from.
	// RedeployRequired lists releases this container cannot apply in place —
	// they change the image outside the sync paths — with the reason: the
	// container needs a new embedded image, which only a redeploy brings.
	AppRuntime       string            `json:"app_runtime,omitempty"`
	EmbeddedDigest   string            `json:"embedded_digest,omitempty"`
	RedeployRequired map[string]string `json:"redeploy_required,omitempty"`
	// Timezone of the container (TZ env or /etc/localtime) and its UTC offset,
	// so a fleet's "local time" update window can be evaluated per container.
	TZ          string `json:"tz,omitempty"`
	TZOffsetMin int    `json:"tz_offset_min"`
	// Fingerprint of the running pod/container, detected from /proc: unique
	// per instance, stable across in-place restarts, gone on recreate.
	ContainerID string `json:"container_id,omitempty"`
	PodUID      string `json:"pod_uid,omitempty"`
	MachineID   string `json:"machine_id,omitempty"` // host or node id when visible
	BootID      string `json:"boot_id,omitempty"`    // node boot id: same for every container on the node

	// Running release.
	ReleaseID string `json:"release_id,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Image     string `json:"image,omitempty"`

	// Phase: starting | running | updating | rolling_back | failed |
	// drained (supervisor stopped by the orchestrator's SIGTERM, reported on the
	// way out) | exited (the app ended on its own; see LastExit).
	Phase   string `json:"phase"`
	Running bool   `json:"running"`
	Healthy bool   `json:"healthy"`
	Ready   bool   `json:"ready"`
	Health  struct {
		Check               string `json:"check"`
		LastError           string `json:"last_error,omitempty"`
		ConsecutiveFailures int    `json:"consecutive_failures"`
		UnhealthyForS       int64  `json:"unhealthy_for_s"`
	} `json:"health"`
	Restarts int `json:"restarts"`
	Updates  int `json:"updates"`
	PID      int `json:"pid,omitempty"`

	// Last failed release.
	FailedReleaseID string `json:"failed_release_id,omitempty"`
	// FailedSnapshot: the snapshot whose files could not be applied.
	FailedSnapshot string `json:"failed_snapshot,omitempty"`
	LastError      string `json:"last_error,omitempty"`

	// LastExit is how the application last stopped; Metrics is the container's
	// resource usage at heartbeat time.
	LastExit *ExitInfo `json:"last_exit,omitempty"`
	Metrics  *Metrics  `json:"metrics,omitempty"`

	// Assets delivered so far; AssetsHash is the channel list the Supervisor has
	// applied, AssetsSyncing true while a download is in progress.
	AssetsHash    string       `json:"assets_hash,omitempty"`
	Assets        []AssetState `json:"assets,omitempty"`
	AssetsSyncing bool         `json:"assets_syncing,omitempty"`

	// Download is the fetch running at heartbeat time, nil when idle.
	Download *Download `json:"download,omitempty"`
}

// The optional supervisor features, and the three images that carry them: slim
// carries none, telemetry carries metric collection, dev carries all three.
// Credential helpers are baked into every image and are not a feature.
const (
	CapLogs      = "logs"
	CapAccess    = "access"
	CapTelemetry = "telemetry"

	VariantSlim      = "slim"
	VariantTelemetry = "telemetry"
	VariantDeveloper = "developer"
)

// Features is every optional feature, in display order.
var Features = []string{CapLogs, CapAccess, CapTelemetry}

// VariantFeatures is what each image is built with. A supervisor reports what
// it can really do in Capabilities; this is only for install snippets.
var VariantFeatures = map[string][]string{
	VariantSlim:      nil,
	VariantTelemetry: {CapTelemetry},
	VariantDeveloper: {CapLogs, CapAccess, CapTelemetry},
}

// VariantFor is the smallest image that carries every feature asked for.
func VariantFor(caps ...string) string {
	want := map[string]bool{}
	for _, c := range caps {
		want[c] = true
	}
	switch {
	case want[CapLogs] || want[CapAccess]:
		return VariantDeveloper
	case want[CapTelemetry]:
		return VariantTelemetry
	}
	return VariantSlim
}

// Normalize rewrites legacy capability and variant names reported by older
// supervisors and derives DataPercent when it is missing.
func (st *SupervisorState) Normalize() {
	legacyTunnel := false
	kept := st.Capabilities[:0]
	for _, c := range st.Capabilities {
		if c == "tunnel" {
			legacyTunnel = true
			continue
		}
		kept = append(kept, c)
	}
	st.Capabilities = kept
	if legacyTunnel {
		st.Capabilities = append(st.Capabilities, CapLogs, CapAccess)
	}
	// Older names of the developer image.
	if st.Variant == "dev" || st.Variant == "development" {
		st.Variant = VariantDeveloper
	}
	if st.Variant == "" && len(st.Capabilities) > 0 {
		st.Variant = VariantFor(st.Capabilities...)
	}
	// Older supervisors send the state volume's bytes but no percentage.
	if m := st.Metrics; m != nil && m.DataPercent == 0 && m.DataTotal > 0 {
		m.DataPercent = math.Round(float64(m.DataUsed)/float64(m.DataTotal)*1000) / 10
	}
}

// Can reports whether this container can run a feature: the image carries it
// and the customer has not vetoed it.
func (st *SupervisorState) Can(cap string) bool {
	for _, c := range st.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// TunnelState is the supervisor's Access tunnel status.
type TunnelState struct {
	Connected bool        `json:"connected"`
	Since     time.Time   `json:"since,omitempty"`
	Endpoint  string      `json:"endpoint,omitempty"`
	Error     string      `json:"error,omitempty"`
	Ports     []PortState `json:"ports,omitempty"` // whether the app listens on each Access port
}

// PortState: is something listening on 127.0.0.1:Port inside the container?
type PortState struct {
	Port      int  `json:"port"`
	Listening bool `json:"listening"`
}

// TunnelWanted asks an access-capable supervisor to keep a tunnel open to the Access
// proxy for the listed container ports.
type TunnelWanted struct {
	Endpoint string `json:"endpoint"` // host:port of the proxy's supervisor listener
	Ports    []int  `json:"ports"`
}

// ExitInfo describes how the supervised application stopped.
type ExitInfo struct {
	At     time.Time `json:"at"`
	Code   int       `json:"code"`
	Signal string    `json:"signal,omitempty"` // SIGKILL, SIGTERM, … when killed by a signal
	OOM    bool      `json:"oom,omitempty"`    // the kernel's OOM killer (cgroup oom_kill counter moved)
	Reason string    `json:"reason"`           // app_exit | oom | stop_signal | restart_budget | restart
}

// Metrics is a resource-usage sample taken by the supervisor from its cgroup.
// Percentages are of the container's limit (or of the node when unlimited).
type Metrics struct {
	CPUPercent float64 `json:"cpu_pct"`
	CPUCores   float64 `json:"cpu_cores"` // limit in cores, or the node's count
	MemUsed    uint64  `json:"mem_used"`  // working set, bytes
	MemLimit   uint64  `json:"mem_limit"`
	MemPercent float64 `json:"mem_pct"`
	// The state volume (releases, assets and the layer cache), reported only
	// when /var/lib/fleetwide is a filesystem of its own. The container's root
	// filesystem is not reported.
	DataUsed    uint64  `json:"data_used,omitempty"`
	DataTotal   uint64  `json:"data_total,omitempty"`
	DataPercent float64 `json:"data_pct,omitempty"`
	Source      string  `json:"source"` // cgroup2 | cgroup1 | proc
}

// HeartbeatRequest is posted over mTLS.
type HeartbeatRequest struct {
	State  SupervisorState `json:"state"`
	Events []Event         `json:"events,omitempty"` // since last heartbeat
}

// Desired tells the Supervisor what to run.
type Desired struct {
	ReleaseID  string `json:"release_id"`
	Image      string `json:"image"`
	Digest     string `json:"digest"`
	Platform   string `json:"platform"`
	Insecure   bool   `json:"insecure,omitempty"`
	SkipVerify bool   `json:"skip_verify,omitempty"` // accept any TLS certificate from the registry
	Manifest   string `json:"manifest_yaml,omitempty"`
	// RegistryAuth, when set, is tried first when pulling; the Supervisor then
	// falls back to a mounted Docker config and cloud IAM (ECR, Artifact Registry).
	RegistryAuth *RegistryAuth `json:"registry_auth,omitempty"`
	// Env is the merged channel + fleet environment; EnvHash changes whenever
	// it does, so the Supervisor restarts the app in place with new values.
	Env     []EnvVar `json:"env,omitempty"`
	EnvHash string   `json:"env_hash,omitempty"`
	// Assets are the release's pinned item versions placed per the app's
	// mapping, with credentials attached; AssetsHash changes whenever the
	// list does and the Supervisor re-syncs.
	Assets     []Asset `json:"assets,omitempty"`
	AssetsHash string  `json:"assets_hash,omitempty"`
	// Snapshot identifies release + assets together; Order is the app's
	// ApplyOrder: item keys and ApplyOrderApp in the sequence the Supervisor
	// switches them (the app entry is the image deploy / restart point).
	Snapshot string   `json:"snapshot,omitempty"`
	Order    []string `json:"order,omitempty"`
	// SyncPaths (embedded runtime) are the app's current sync paths; a
	// release embedded with a different list is not applied.
	SyncPaths []string `json:"sync_paths,omitempty"`
}

// MetricsRequest is posted by the Supervisor over mTLS, separately from the
// heartbeat.
type MetricsRequest struct {
	Points []MetricPoint `json:"points"`
}

// MetricPoint is one reading of one declared metric.
type MetricPoint struct {
	At     time.Time         `json:"at"`
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
}

// MetricsResponse tells the supervisor what was kept, so a container whose metrics
// are all being dropped can say so in its log instead of posting for ever.
type MetricsResponse struct {
	Stored  int    `json:"stored"`
	Dropped int    `json:"dropped,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// HeartbeatResponse is the Console's answer.
type HeartbeatResponse struct {
	Desired   *Desired `json:"desired,omitempty"` // nil = nothing assigned yet
	Override  string   `json:"override"`          // none | ready | unready
	IntervalS int      `json:"interval_s"`
	Restart   bool     `json:"restart,omitempty"` // one-shot: restart the app in place
	// Logs asks the Supervisor to stream its application output while someone
	// watches in the console (nil / Want=false otherwise).
	Logs *LogsWanted `json:"logs,omitempty"`
	// Health is the probe the container should run and, where the fleet asks
	// for it, the readiness endpoint to open. nil leaves the image's manifest
	// in charge.
	Health *Healthcheck `json:"health,omitempty"`
	// Telemetry is the app's declaration of what to scrape, sent only where
	// the fleet has telemetry on and the supervisor reports the capability; nil
	// means scrape nothing.
	Telemetry *Telemetry `json:"telemetry,omitempty"`
	// MonitoringDisabled: the fleet turned monitoring off; the Supervisor sends no
	// metrics or logs and the Console raises no health alarms for it.
	MonitoringDisabled bool `json:"monitoring_disabled,omitempty"`
	// Hold: a change is pending but the fleet's update window is closed; the
	// Supervisor keeps running what it has until NextWindow.
	Hold       bool      `json:"hold,omitempty"`
	NextWindow time.Time `json:"next_window,omitempty"`
	// Tunnel is set when the fleet has Fleetwide Proxy switched on and the
	// deployment has access ports configured; nil = close any open tunnel.
	Tunnel *TunnelWanted `json:"tunnel,omitempty"`
	// OnFailure is the fleet's failure policy (rollback | report), refreshed
	// every heartbeat.
	OnFailure string `json:"on_failure,omitempty"`
	// Settled names the release this container runs once its whole
	// deployment is on that snapshot, healthy and not halted; the supervisor
	// may then drop the previous release from its layer cache. Empty until then.
	Settled string `json:"settled,omitempty"`
}

// LogsWanted is the Console's request for live logs.
type LogsWanted struct {
	Want  bool  `json:"want"`
	Since int64 `json:"since"` // last sequence the Console has; the Supervisor sends newer lines
}

// LogLine is one line of application output.
type LogLine struct {
	Seq    int64     `json:"seq"`
	At     time.Time `json:"at"`
	Stream string    `json:"stream"` // stdout | stderr
	Text   string    `json:"text"`
}

// SupervisorLogsRequest is a batch the Supervisor pushes while logs are wanted.
type SupervisorLogsRequest struct {
	Lines []LogLine `json:"lines"`
}
