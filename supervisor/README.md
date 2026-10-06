# Fleetwide supervisor

The supervisor runs inside a container as its entrypoint and keeps the
container on the release its fleet follows. It is a static Go binary in a
`FROM scratch` image: it pulls an OCI image's layers straight from the
registry, verifies digests while streaming, caches blobs content-addressed,
unpacks with full whiteout semantics, extracts the image over its own `/`,
execs the entrypoint and supervises it. Enrolled with a console it runs
whatever release the channel points at, updates in place, reports health and
metrics, and rolls back releases that never become healthy. No Docker daemon,
no Docker-in-Docker, no privileged mode.

Docs: https://fleetwide.io/docs

## Run it

```sh
docker run -d --name my-app -e FLEETWIDE_KEY=fw1.… public.ecr.aws/fleetwide/slim:1
```

The deployment key comes from the console (a deployment owns its keys) and
carries the console URL, the app, the enrollment secret and the console CA
fingerprint in one value. It is the only thing a container needs. The same
`docker run` works in Compose, Swarm and Kubernetes; the supervisor detects
the runtime. A volume on `/var/lib/fleetwide` gives offline start and a warm
layer cache; without one a recreated container enrolls again and re-downloads.

Images are published for `linux/amd64` and `linux/arm64`:

| Image | build tags | live logs | Fleetwide proxy | telemetry |
| --- | --- | --- | --- | --- |
| `public.ecr.aws/fleetwide/slim` | — | | | |
| `public.ecr.aws/fleetwide/telemetry` | `telemetry` | | | ✓ |
| `public.ecr.aws/fleetwide/developer` | `logs,access,telemetry` | ✓ | ✓ | ✓ |

Three builds from one source, differing only in which optional features are
compiled in (`internal/features`). The supervisor reports its `variant` and
its `capabilities` at enrollment and on every heartbeat; the console runs a
feature only where the fleet switch is on *and* the container reports the
capability. A slim binary links no tunnel code at all, so it cannot open one
however it is configured. `fleetwide-supervisor version` prints both.

The image starts the supervisor on its own (`ENTRYPOINT ["/fleetwide-supervisor"]`,
`CMD ["supervise"]`). Override the command to reach the other subcommands.

## Commands

```sh
fleetwide-supervisor supervise                                     # managed mode, the image's default
fleetwide-supervisor run [--ready-listen :9100] [--manifest f.yaml] IMAGE [-- CMD...]   # standalone (linux)
fleetwide-supervisor assets [--watch --interval 60s]               # fetch the deployment's assets only (sidecar)
fleetwide-supervisor inspect docker.io/library/nginx:1.27          # manifest + config as JSON
fleetwide-supervisor unpack --dest /tmp/nginx docker.io/library/nginx:1.27    # works on macOS too
fleetwide-supervisor healthcheck --addr 127.0.0.1:9100             # Docker HEALTHCHECK entry
fleetwide-supervisor env | ps                                      # inside a running container
fleetwide-supervisor version
```

Common flags: `--platform os/arch[/variant]`, `--cache DIR`, `--plain-http`
(local and test registries), `--quiet`, `--json`.

### Managed mode

A key is all a container needs; a display name is optional:

| Variable | Meaning |
|---|---|
| `FLEETWIDE_KEY` | the deployment key (`fw1.…`). |
| `FLEETWIDE_INSTANCE_NAME` | optional display name for this container in the console. Several containers may share one. |

The console knows a container by its certificate, kept in the state
directory; without one, by its pod uid or container id. `FLEETWIDE_RUNTIME`
(`k8s | swarm | docker | compose`) overrides runtime detection, and
`FLEETWIDE_CONSOLE` + `FLEETWIDE_APP_KEY` + `FLEETWIDE_SECRET` are accepted in
place of a key for scripted installs.

Everything else is a flag on `supervise`, a choice made once by whoever
writes the compose file:

| Flag | Meaning |
|---|---|
| `--state DIR` | state directory, default `/var/lib/fleetwide`: identity (cert, key, CA, console URL), `current.json`, `previous.json`, `meta.json`, `paths/`, `cache/` |
| `--cache DIR` | layer cache, default `<state>/cache` |
| `--ready-listen ADDR` | serve the ready endpoint (the console's healthcheck can also ask for it) |
| `--runtime` | `k8s | swarm | docker | compose`, detected when empty |
| `--console-ca FILE` | PEM of a console CA to trust |
| `--insecure-tls` | skip console certificate verification (local testing only) |
| `--skip-space-check` | do not check free space before pulling, where `statfs` does not show the real limit |
| `--platform` | `os/arch[/variant]`, default the host's |

Trust on first contact: the key pins the console's CA by SHA-256 fingerprint
(the console serves its CA in the TLS chain); the supervisor then stores the
CA PEM for all later mTLS calls. With a publicly trusted console certificate
the key omits the pin and system roots are used. Client certificates are
renewed over the mTLS channel before they expire.

Keys are reusable: keep one in a Kubernetes Secret or a Compose file and a
recreated container enrolls again. With a state volume the recreated
container keeps its certificate and so its record in the console (same id,
history kept). Keys can be capped, expire and be revoked from the console.

## Readiness and liveness

- `/fleetwide/ready` mirrors the health check: 200 when the app is running
  and the check has passed at least once since the last (re)start, 503 when
  the app is down or failing. The supervisor never forces it unready on its
  own; a `none | ready | unready` override is set from the console and
  echoed on the heartbeat.
- `/fleetwide/live` stays 200 while the supervisor is supervising, including
  during a supervisor-managed restart or update, so a liveness probe pointed
  here does not kill the pod mid-update. It fails only when the app is down
  and the supervisor is not managing a transition.
- `/fleetwide/status` reports the supervised process; `/fleetwide/override`
  takes the override.
- A customer's own probes against the app keep working unchanged; the
  endpoint is optional.

The console's probe definition arrives on every heartbeat and is laid over the
manifest's: an unset field keeps what the image decided. Switching probes off
for a fleet drops every probe and makes the process the only check.

## Update and rollback

1. A heartbeat returns a `desired` release different from the running one.
2. Check space, then pull by digest into the layer cache; nothing under `/`
   changes yet. The layers not already cached must fit the cache volume (the
   cache is trimmed first if that is what stands in the way), and `/` must
   have room for a staged copy (three times the compressed image, loosely)
   or the release is extracted in the gap instead; less than the compressed
   image on `/` is a refusal. `--skip-space-check` turns this off.
3. Stage: extract the image into `/.fleetwide-staging/<release>` while the
   old app runs. Staging lives on `/`, not the state volume, so the next
   step is a rename, not a copy. If `/` has no room the release is applied
   directly over `/` in the gap instead: slower, never wrong. A read-only
   rootfs fails here, before anything stops.
4. Stop the old app, then commit: link every staged file into place,
   recreate symlinks, give directories the staged mode, owner and xattrs,
   write the paths file, remove files the old release wrote that the new one
   did not (residue), start the new app. Mount points, the state directory
   and asset directories are never written or removed, checked on the
   resolved destination so a symlink in the image cannot redirect a write
   into a volume.
5. Remove the staging tree. A tree left behind by a crash mid-commit is
   found on the next start: its paths file drives residue cleanup, then it
   is swept.
6. The release is *pending* until healthy past `grace + 2×interval`
   (confirmed). If it stays unhealthy for `rollback.on_unhealthy_for` before
   confirmation, the supervisor redeploys the previous release the same way,
   reports a `rollback` event and remembers the failed release id
   (`meta.json`); the console stops offering it.
7. A confirmed release that later turns unhealthy is restarted in place
   (`health.max_restarts`), not rolled back.

The layer cache keeps the current and previous releases. When the console
reports that the whole deployment is on the running release, healthy and not
halted (`settled` on the heartbeat), the previous release is no longer needed
for a fleet-wide rollback: the supervisor forgets it and removes every blob
that neither the running release nor the live assets use. Until then it
stays, so a halted rollout can roll every container back from cache.

A release that fails *after* the old app has stopped (the commit cannot
complete, the entrypoint is missing, the health check never passes before
confirmation) follows the fleet's `rollout.on_failure`: `rollback` (default)
writes the previous release back from the layer cache and starts it;
`report` leaves nothing running, ready and live answer 503 so an orchestrator
recreates the container, and the recorded release is the previous one so that
container starts on it. Both report an `update_failed` event naming the cause
and the outcome.

On start with `current.json` present the supervisor resumes that release from
the layer cache before talking to the console (offline start), keeping its
identity; no secret is needed again. If the console answers heartbeats with
404 three times (record deleted or superseded) and a key is still configured,
the supervisor discards its identity and enrolls again.

### Linux capabilities

These are the supervisor's, not the application's. The supervisor runs as
root because writing a release over `/` and starting the app as its `USER`
uses what a runtime normally exercises on the container's behalf, on every
update, so nothing can be dropped after start.

- **Required**: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `SETUID`,
  `SETGID`, `KILL`. Without one of these updates fail, and the supervisor
  says so at start (`warning: … lacks …; updates will fail`).
- **Optional**: `MKNOD`, `SETFCAP`. Without them device nodes and file
  capabilities in an image are not reproduced (`note: … lacks …`), which is
  what CRI-O's default set amounts to.

Both are reported on the heartbeat as `state.missing_caps`. Everything else
in Docker's default set can go (`--cap-drop ALL --cap-add` the required
list). Pod Security *restricted* and OpenShift *restricted-v2* (non-root,
drop ALL) cannot run the supervisor image; use the embedded runtime there.
What the application needs (a low port, raw sockets, a file capability on
its binary) is the container's configuration, the same as it would be
without Fleetwide; the supervisor neither checks nor compensates for it.

The container needs a writable root filesystem (`--read-only` /
`readOnlyRootFilesystem` cannot work without `CAP_SYS_ADMIN`, which the
supervisor does not ask for) and room on `/` for one extracted copy of the
image beside the running one during an update. On Kubernetes,
`ephemeral-storage` limits are enforced by eviction and are invisible to
`statfs`; a pod near its limit can be evicted mid-update and resumes from the
layer cache when recreated. The staging tree is `0700 root`: an application
running as a non-root `USER` cannot read or alter it.

## Two runtimes

| | Supervisor runtime | Embedded runtime |
|---|---|---|
| What runs | the supervisor image; the supervisor pulls the app image and becomes it | the app's own image with `/fleetwide-supervisor` as the start command (`fleetwide embed`) |
| Update surface | the whole image | the app's declared **sync paths**, from the layers of each release that touch them |
| Base image change | delivered | `redeploy_required`: reported, the container keeps running, the orchestrator redeploys the new embedded image |
| Runs as | root, with the capabilities above | the image's `USER`, no capabilities (Pod Security *restricted*, OpenShift) |
| Supervisor ↔ app boundary | yes | none: one uid |
| Offline first start | a baked image | `--start embedded` |

## Embedded runtime

1. Register the app with runtime `embedded` and its sync paths, the
   directories the supervisor keeps in step with each release (`/app`,
   `/usr/share/nginx/html`, `/etc/nginx/conf.d`): code and configuration,
   not data. Asset paths join them automatically.
2. `fleetwide embed --app KEY --api-key TOKEN --image IMAGE --start
   embedded|latest --tag DEST --push` fetches the sync paths, reads the
   image's `USER`, resolves it against the image's `/etc/passwd`, and
   appends three layers: the supervisor; a permission layer (directory
   entries only: the sync and asset directories, `/fleetwide` and
   `/var/lib/fleetwide`, owned `uid:0` with group `rwx`, so an arbitrary uid
   with gid 0 can write too; files stay root-owned and are replaced by
   unlink + create); and a metadata layer (`embedded.json` plus an index of
   every path of the image outside `/fleetwide*` and `/var/lib/fleetwide`
   with type, mode, owner, size, sha256 and link target). The config keeps
   `USER`, points `ENTRYPOINT` at the supervisor, and names the metadata
   layer in the label `io.fleetwide.meta.layer`. Publish the pushed tag as a
   release: every release of an embedded app is an embedded image.
3. At start, `--start embedded` runs the embedded app at once (offline
   capable) and syncs when the console assigns something newer; `--start
   latest` enrolls first, syncs the assigned release, then starts; past
   `--start-timeout` it starts the embedded app (`--start-fallback
   fallback`) or stays down for the orchestrator (`strict`).
4. On a new release the supervisor resolves it, reads the label, pulls the
   one metadata layer (about 1 MB) and compares its index with the local one
   outside the sync paths. Any difference is a base change:
   `redeploy_required` with the first paths and a count, and nothing is
   pulled or written; the console shows the container as needing a redeploy
   and leaves it out of the batch and settle arithmetic without halting the
   deployment. Identical outside: pull only the layers that touch the sync
   paths, stage their merged view under `/fleetwide/staging`, check every
   destination is writable as this user (else `redeploy_required` with the
   path), then in the gap link the tree in, remove what the sync paths held
   that the release does not, and start the release's own process
   definition. The same image again (adoption) syncs nothing.
5. Limits: files the app writes under a sync path are residue at the next
   sync; a release is applied whole or not at all; the supervisor and the
   app share one uid (the app can read the identity key); a read-only
   rootfs is report-only; indexing is paid once at embed time (roughly
   10–20 CPU-seconds and 2–3 GB read per GB of image), never per container.

## Baking

`fleetwide embed` puts the supervisor inside an image (`bake` is the same
command under its older name): the result runs the
application with no console at all and is adopted as a known release the
moment it is given a key. `--profile` picks which supervisor goes in (slim,
telemetry, developer).

- The deployment key is never baked. What goes in is the public half (which
  console, which app, which release, the console's CA fingerprint) so the
  image can say where it belongs without being a credential. The supervisor
  refuses a key for a different app before any identity exists.
- Provenance is answerable with `docker inspect`: `io.fleetwide.app`,
  `.release`, `.version`, `.console`, `.supervisor.version`,
  `.supervisor.variant`, `.baked.digest` and the OCI `base.name` /
  `base.digest` / `created` labels.
- One release, every architecture: a release pins what its tag serves, the
  index of a multi-platform image or the manifest of a single one. Each
  supervisor resolves its own platform out of the index at pull time and
  verifies against the pinned digest. An index with no image for this
  container fails the release with a message naming the platforms it does
  have. For a private registry `fleetwide digest` prints exactly what to
  paste.
- Multi-platform: a multi-platform source is covered whole, and the result
  is an index of the same platforms; `--platform linux/arm64` narrows it to
  one. Attestation manifests (`unknown/unknown`) are skipped. Every platform
  is built on its own, with its own supervisor layers and metadata.
  `--supervisor-image` is multi-platform and resolved per platform;
  `--supervisor-binary` is one architecture, so with several platforms give
  one each (`--supervisor-binary linux/amd64=… --supervisor-binary
  linux/arm64=…`). A source image that turns out not to have the requested
  platform is refused.
- `--verify` loads the result into the local Docker daemon and runs it with
  no key: the application has to start from the image alone.

## Registry credentials

Every pull goes through one keychain, first match wins:

1. the fleet's credential for that registry, delivered by the console on the
   heartbeat (`desired.registry_auth`): a docker-login registry, an `ecr`
   or `gar` credential in key mode, or a git token for assets;
2. a Docker config: `DOCKER_CONFIG`, or a `config.json` mounted at the
   usual places (`~/.docker/config.json` or a Kubernetes pull secret,
   read-only);
3. Amazon ECR through the container's IAM role (task role, instance
   profile, IRSA);
4. Google Artifact Registry and GCR through the attached service account.

So on AWS and GCP a role or service account on the container needs no
console credential at all; the vendor records that as an `ecr` or `gar`
credential in identity mode. In key mode the supervisor exchanges `ecr` keys
(access key id + secret, optional session token, optional role to assume) for
an ECR login itself, cached for the login's lifetime, and uses a `gar`
service-account key directly. Either can be read from a container
environment variable (`from_env`) so the key stays in the customer's secret
store; a missing variable is logged.

Releases carry a digest: the supervisor refuses to pull when the resolved
manifest digest differs, and layers are verified while streaming. A registry
marked plain-HTTP or self-signed in the console is pulled accordingly.

## Fleets, deployments and containers

The deployment key decides the deployment, and so the fleet: a deployment is
created in the console and owns its keys, and every container that enrolls
with one of them is a container of that deployment, rolling together one
batch at a time. Within the deployment a container is known by its
certificate, else its pod uid or container id. The supervisor never names or
creates a deployment.

`hold: true` on the heartbeat (the fleet's update window is closed) makes
the supervisor keep what it runs until `next_window`; the supervisor reports
its timezone (`TZ` or the container clock) so local-time windows work per
container. `monitoring_disabled` suspends metrics and log streaming; health
supervision keeps running locally.

## Assets

`internal/assets` delivers the deployment's assets (`desired.assets`: the
items the app ships, pinned per release): OCI artifacts (tar layers
extracted, other layers such as model weights written as files named by their
title annotation) and git commits (archive URL for GitHub, GitLab, Gitea and
Bitbucket, top directory stripped). A release without an image is applied as
`phase=idle`: nothing runs, assets are delivered, health means every asset is
live. Each version lands in `<unpack_to>/<name>/.versions/<key>`; `current`
is switched with symlink + rename and the previous version is kept, so
rolling back is instant. Sync runs in the background (heartbeats report
`assets_syncing`), a failure retries after a minute, and unpack directories
are protected from release residue cleanup. `on_change` runs once the new
version is live: `restart`, `signal:SIGHUP` (forwarded to the app) or
`exec:<cmd>` (`/bin/sh -c` inside the container).

`fleetwide-supervisor assets` is the fetch-only mode: with `FLEETWIDE_KEY` it
syncs into the unpack directories (a volume shared with the app container)
and exits 0; `--watch` keeps syncing every `--interval`, as a sidecar.
Nothing is enrolled and no record appears in the console.

`desired` carries the release and the assets together (`snapshot`, `order`).
The supervisor stages everything first, then switches in `order`: assets via
activation plus their hook, the app via the usual deploy followed by a wait
for health. Three failed staging attempts mark the snapshot failed
(`state.failed_snapshot`) so the console stops offering it.

## Telemetry

Compiled in with the `telemetry` build tag; elsewhere the directive is
logged once and ignored. The console sends the app's declaration on each
heartbeat; one goroutine per endpoint scrapes `http://127.0.0.1:<port><path>`
immediately and then on its interval (minimum 15 s), parses the Prometheus
text format, keeps only the declared names and posts them. A scrape failure
is logged once per run of failures. Endpoints with no metrics declared are not
scraped.

## Signals, exit reporting and metrics

The supervisor is PID 1. SIGTERM, SIGINT and SIGQUIT from the orchestrator are
forwarded to the app; the supervisor waits `health.stop_timeout`, sends a
final heartbeat with `phase=drained`, and exits 0. When the app stops on its
own the supervisor reports `phase=exited` with `state.last_exit = {code,
signal, oom, reason}` and exits with the app's code for the orchestrator to
restart the container. A SIGKILL while the cgroup's `oom_kill` counter
(`memory.events`, v1 `memory.oom_control`) moved since start is reported as
the kernel OOM killer. If a container is killed without any signal reaching
PID 1 there is nothing to report; the console marks it offline after two
minutes of silence.

Every heartbeat carries `state.metrics`: cgroup v2 (`memory.current` minus
`inactive_file`, `memory.max`, `cpu.stat`, `cpu.max`,
`cpuset.cpus.effective`), the cgroup v1 equivalents, or `/proc` when the
supervisor is not confined. CPU percent is the delta of `usage_usec` between
heartbeats over the CPU limit. The only disk figure is the state volume, and
only when the state directory is a filesystem of its own.

## Live logs

The runner tees the application's stdout and stderr into a bounded ring
(2000 lines / 1 MB) while still writing to the container's own stdout and
stderr, so `docker logs` keeps working. When a heartbeat says `logs.want`,
new lines are sent every second (the first batch is the last 200 lines) until
nothing has asked for 30 s. Only the developer image reports the `logs`
capability; elsewhere the buffer is not created.

## Console-delivered environment

`desired.env` (channel values under fleet values, merged by the console) is
merged onto the image's `ENV` before the app starts; the container's own
environment still wins, so a customer's `-e` flags override vendor values.
When `desired.env_hash` changes for the running release the supervisor
restarts the app in place (event `env_updated`). Values are persisted with the
release for offline resume.

The same variables are written to files, because a `docker exec` shell only
sees the container's own environment: `/run/fleetwide/env` (`set -a; .
/run/fleetwide/env`), `/etc/profile.d/fleetwide-env.sh` (login shells pick it
up) and `/run/fleetwide/env.d/<NAME>` (one file per variable).
`docker exec <container> /fleetwide-supervisor env` prints them together with
the supervised process.

## `fleetwide` CLI

```
fleetwide digest [--platform linux/arm64] [--plain-http] IMAGE
fleetwide embed --image REF --tag DEST [--push] [--output FILE.tar]
               [--supervisor-image REF | --supervisor-binary [os/arch=]FILE]
               [--app KEY [--release ID]] [--profile slim|telemetry|developer]
               [--platform os/arch[,os/arch] | --all-platforms] [--verify]
fleetwide embed --app KEY --api-key TOKEN --image REF --tag DEST --push     # embedded-runtime app
               --start embedded|latest [--start-fallback fallback|strict] [--start-timeout 60s]
fleetwide version
```

`embed` layers the supervisor onto an image without a Docker daemon and
writes `/fleetwide/baked.json` and `/fleetwide/baked.paths.txt`. The result
runs the app at once: standalone when no key is given, enrolling and updating
over the air otherwise. If the console's current release has the same digest
the container is adopted without a redeploy. `--output` produces a `docker
load` tarball for isolated sites. The supervisor layers come from the
published image for the CLI's own version (`--supervisor-image` or
`--supervisor-binary` override it). `--dockerfile` runs `docker build` first;
`--build-tag` names and keeps that build. For an embedded-runtime app the
same command reads the app's sync paths from the console and keeps the
image's own user; every platform rule applies to both. `bake` is accepted
as the older name. `--console` and
`FLEETWIDE_CONSOLE` point at a self-hosted console; `FLEETWIDE_API_KEY`
stands in for `--api-key`.

Install:

```sh
curl -fsSL https://fleetwide.io/install.sh | sh
go install github.com/fleetwidehq/fleetwide/supervisor/cmd/fleetwide@latest
```

## Layout

```
cmd/fleetwide-supervisor/  the supervisor binary
cmd/fleetwide/             the CLI: digest, embed (bake), version
internal/registry/         resolve reference → platform image; stream layers into the cache; pin by digest; keychain (docker config, ECR, GAR)
internal/layercache/       blobs/sha256/<hex>, tmp+rename, hash-while-streaming
internal/unpack/           tar layer applier: whiteouts, hardlinks, symlinks, devices, xattrs, protected paths, containment
internal/rootfs/           materialize: resolve → pull → decompress → apply; staging and commit
internal/manifest/         fleetwide.yaml reader, defaults, validation
internal/health/           http / tcp / exec / process checks; grace, threshold, unhealthy-for
internal/ready/            /fleetwide/ready, /live, /status, /override
internal/runner/           exec with env/user/workdir; PID 1 reaper; stop with SIGKILL fallback
internal/supervise/        one app slot: start, monitor, in-place restart, deploy, restart
internal/consoleclient/    enrollment (CSR), mTLS heartbeat, logs and metrics
internal/identity/         certificate, key and CA in the state directory; renewal
internal/fleet/            managed mode: enroll, heartbeat, update, rollback, offline resume, embedded sync
internal/embedded/         embedded runtime: index, metadata layer, sync paths
internal/bake/             bake and embed: layer assembly without a daemon
internal/baked/            what a baked image records about itself
internal/assets/           OCI and git assets, versions, hooks
internal/telemetry/        Prometheus scraping (build tag telemetry)
internal/tunnel/           Fleetwide proxy tunnel (build tag access)
internal/logbuf/           bounded log ring (build tag logs)
internal/features/         which features this build carries
internal/metrics/          cgroup and /proc resource figures
internal/caps/             capability check at start
internal/mounts/           /proc/self/mountinfo parser
internal/fsinfo/           free-space checks
internal/passwd/           USER resolution against the image's passwd and group files
internal/imagecfg/         image config helpers
internal/progress/         pull progress on stderr
internal/buildinfo/        version and image registry, stamped at build time
```

## Build and test

```sh
make build && make test                                   # host build and unit tests
make build-all                                            # the three variants must compile
docker build -f supervisor/Dockerfile -t fleetwide-supervisor:dev .   # from the repository root
supervisor/scripts/matrix.sh                              # public images: unpack parity against docker export
supervisor/scripts/e2e-health.sh                          # manifest, health, restart, ready endpoint (local registry)
```

Licensed under the Apache License 2.0.
