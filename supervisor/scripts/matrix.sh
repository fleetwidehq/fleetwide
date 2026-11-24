#!/usr/bin/env bash
# Pull + verify + unpack + exec matrix for the Fleetwide Supervisor.
#
# For every image:
#   A. unpack inside a Linux container (as root, full semantics) with the supervisor
#   B. compare the resulting tree with `docker export` of the same image:
#      entry names, modes, owners, symlink targets, sha256 of regular files
#   C. `run` the image inside the scratch supervisor container (extract over /)
#      with a command whose output proves the app's own userland works
#
# Needs: docker (linux/arm64 or amd64 engine), python3.
# The docker export side is pinned to the exact digest the supervisor resolved so a
# stale local copy of a moving tag cannot skew the comparison.
# Usage: scripts/matrix.sh [output.md]
set -uo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
SUPERVISOR_IMAGE=${SUPERVISOR_IMAGE:-fleetwide-supervisor/slim:dev}
# extra docker run flags for the supervisor container, e.g. --cap-drop SETFCAP --cap-drop MKNOD to see what a CRI-O default set does
SUPERVISOR_DOCKER_ARGS=${SUPERVISOR_DOCKER_ARGS:-}
PLATFORM=${PLATFORM:-linux/$(docker version --format '{{.Server.Arch}}')}
WORK=${WORK:-/tmp/fleetwide-matrix}
# Official images are pulled from the public.ecr.aws/docker/library mirror.
# Set MIRROR= (empty) to use docker.io/library directly.
MIRROR=${MIRROR-public.ecr.aws/docker/library}
CACHE=$WORK/cache
# Trees live in a native Docker volume, not a macOS bind mount: VirtioFS does
# not give container root the usual override of read-only directory modes,
# which breaks tar extraction of images such as UBI (read-only ca-trust dirs).
TREES_VOL=${TREES_VOL:-fleetwide-matrix-trees}
docker volume create "$TREES_VOL" >/dev/null
OUT=${1:-$HERE/test-results/unpack-matrix.md}
mkdir -p "$CACHE" "$(dirname "$OUT")"

# Produces a normalized listing of a tree: "<type> <mode> <uid>:<gid> <path> [-> link | sha256]"
LISTER='cd "$1" && find . -mindepth 1 \( -type d -o -type f -o -type l -o -type p -o -type b -o -type c \) | sort | while IFS= read -r p; do
  if [ -L "$p" ]; then printf "l %s %s %s -> %s\n" "$(stat -c %a "$p")" "$(stat -c %u:%g "$p")" "$p" "$(readlink "$p")";
  elif [ -d "$p" ]; then printf "d %s %s %s\n" "$(stat -c %a "$p")" "$(stat -c %u:%g "$p")" "$p";
  elif [ -f "$p" ]; then printf "f %s %s %s %s\n" "$(stat -c %a "$p")" "$(stat -c %u:%g "$p")" "$p" "$(sha256sum "$p" | cut -c1-16)";
  else printf "s %s %s %s\n" "$(stat -c %a "$p")" "$(stat -c %u:%g "$p")" "$p"; fi; done'

# jf 'python-expression-over-d' : evaluate against the JSON on stdin
jf() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

rows=()
pass=0; fail=0

run_case() {
  # run_case NAME REF EXPECT_SUBSTR [-- CMD...]   (EXPECT_SUBSTR="-" = unpack only)
  local name=$1 ref=$2 expect=$3; shift 3
  if [ -n "$MIRROR" ]; then ref=${ref/#docker.io\/library\//$MIRROR/}; fi
  local cmd=()
  if [ "${1:-}" = "--" ]; then shift; cmd=("$@"); fi
  echo "=== $name  ($ref)"
  local tree=/work/trees/$name
  docker run --rm -v "$TREES_VOL":/work/trees alpine:3.20 sh -c "rm -rf /work/trees/$name /work/trees/ref-$name; mkdir -p /work/trees/ref-$name"

  # A. unpack in Linux
  local t0=$(date +%s)
  local json
  json=$(docker run --rm $SUPERVISOR_DOCKER_ARGS --platform "$PLATFORM" -v "$CACHE":/cache -v "$TREES_VOL":/work/trees \
      "$SUPERVISOR_IMAGE" unpack --quiet --json --cache /cache --dest "$tree" "$ref" 2>"$WORK/$name.unpack.err")
  local rc=$?
  local t1=$(date +%s)
  if [ $rc -ne 0 ]; then
    echo "  unpack FAILED: $(tail -1 "$WORK/$name.unpack.err")"
    rows+=("| $name | \`$ref\` | – | – | – | – | – | **unpack failed** | – | ✗ |")
    fail=$((fail+1)); return
  fi
  local layers files links wh comp digest
  layers=$(echo "$json" | jf 'len(d["image"]["layers"])')
  files=$(echo "$json" | jf '"%df/%dd/%dl/%dh" % (d["stats"]["files"], d["stats"]["dirs"], d["stats"]["symlinks"], d["stats"]["hardlinks"])')
  wh=$(echo "$json" | jf '"%d+%dopq/%drm" % (d["stats"]["whiteouts"], d["stats"]["opaques"], d["stats"]["removed"])')
  comp=$(echo "$json" | jf '",".join(sorted(set(d["compression"])))')
  local fulldigest; fulldigest=$(echo "$json" | jf 'd["image"]["digest"]')
  digest=${fulldigest:7:12}
  local warns; warns=$(echo "$json" | jf 'len(d.get("warnings") or [])')
  echo "  unpacked: $layers layers ($comp) $files whiteouts=$wh warnings=$warns in $((t1-t0))s"

  # B. compare with docker export
  local cid
  local repo=$ref
  case "${ref##*/}" in *:*) repo=${ref%:*};; esac
  # a dummy command lets images without CMD/ENTRYPOINT (distroless) be created
  cid=$(docker create --platform "$PLATFORM" "$repo@$fulldigest" /fleetwide-noop 2>"$WORK/$name.create.err")
  if [ -z "$cid" ]; then echo "  docker create failed: $(tail -1 "$WORK/$name.create.err")"; fi
  docker export "$cid" | docker run --rm -i --platform "$PLATFORM" -v "$TREES_VOL":/work/trees alpine:3.20 \
      sh -c "tar -x -C /work/trees/ref-$name" 2>/dev/null
  docker rm -f "$cid" >/dev/null 2>&1
  local FILTER=' \./(\.dockerenv|etc/hosts|etc/hostname|etc/resolv\.conf|etc/mtab|dev|proc|sys)(/| |$)'
  docker run --rm --platform "$PLATFORM" -v "$TREES_VOL":/work/trees alpine:3.20 sh -c "$LISTER" _ "/work/trees/$name" \
      | grep -Ev "$FILTER" | grep -Ev '^d [0-9]+ 0:0 \./etc$' | LC_ALL=C sort > "$WORK/$name.ours.lst"
  docker run --rm --platform "$PLATFORM" -v "$TREES_VOL":/work/trees alpine:3.20 sh -c "$LISTER" _ "/work/trees/ref-$name" \
      | grep -Ev "$FILTER" | grep -Ev '^d [0-9]+ 0:0 \./etc$' | LC_ALL=C sort > "$WORK/$name.ref.lst"
  local missing extra
  missing=$(comm -13 "$WORK/$name.ours.lst" "$WORK/$name.ref.lst" | wc -l | tr -d ' ')
  extra=$(comm -23 "$WORK/$name.ours.lst" "$WORK/$name.ref.lst" | wc -l | tr -d ' ')
  local total; total=$(wc -l < "$WORK/$name.ref.lst" | tr -d ' ')
  local cmpres="identical ($total entries)"
  [ "$missing" != 0 -o "$extra" != 0 ] && cmpres="**$missing missing / $extra extra** of $total"
  echo "  vs docker export: $cmpres"
  if [ "$missing" != 0 -o "$extra" != 0 ]; then
    comm -3 "$WORK/$name.ours.lst" "$WORK/$name.ref.lst" | head -8 | sed 's/^/    /'
  fi

  # C. run
  local runres="unpack only" runok="✓"
  if [ "$expect" != "-" ]; then
    local out rc2
    local runargs=("$ref")
    if [ ${#cmd[@]} -gt 0 ]; then runargs+=(-- "${cmd[@]}"); fi
    out=$(docker run --rm --platform "$PLATFORM" -v "$CACHE":/cache "$SUPERVISOR_IMAGE" run --quiet --cache /cache "${runargs[@]}" 2>&1)
    rc2=$?
    local first; first=$(echo "$out" | grep -v '^$' | grep -m1 -F "$expect" || echo "$out" | grep -v '^$' | head -1)
    if [ $rc2 -eq 0 ] && echo "$out" | grep -qF "$expect"; then
      runres="exit 0: \`$(echo "$first" | cut -c1-60 | sed 's/|/\\|/g')\`"
    else
      runres="**exit $rc2**: \`$(echo "$out" | grep -v '^$' | tail -1 | cut -c1-70 | sed 's/|/\\|/g')\`"; runok="✗"
    fi
    echo "  run: $runres"
  fi
  local ok="✓"
  if [ "$missing" != 0 -o "$extra" != 0 -o "$runok" = "✗" ]; then ok="✗"; fail=$((fail+1)); else pass=$((pass+1)); fi
  rows+=("| $name | \`$ref\` | $digest | $layers ($comp) | $files | $wh | $cmpres | $runres | ${warns} | $ok |")
}

# ---- matrix -----------------------------------------------------------------
# name          ref                                              expect                 -- command
run_case alpine       docker.io/library/alpine:3.20               "Alpine Linux"        -- cat /etc/os-release
run_case busybox      docker.io/library/busybox:1.36              "BusyBox v1.36"       -- busybox --help
run_case debian       docker.io/library/debian:bookworm-slim      "12."                 -- cat /etc/debian_version
run_case ubuntu       docker.io/library/ubuntu:24.04              "24.04"               -- cat /etc/os-release
run_case nginx        docker.io/library/nginx:1.27                "nginx version"       -- nginx -v
run_case redis        docker.io/library/redis:7                   "Redis server"        -- redis-server --version
run_case postgres     docker.io/library/postgres:16               "PostgreSQL"          -- postgres --version
run_case python       docker.io/library/python:3.12-slim          "py ok 3.12"          -- python -c 'import sys; print("py ok", sys.version.split()[0])'
run_case node         docker.io/library/node:22-alpine            "node v22"            -- node -e 'console.log("node", process.version)'
run_case temurin-jre  docker.io/library/eclipse-temurin:21-jre    'openjdk version "21' -- java -version
run_case caddy        docker.io/library/caddy:2                   "v2."                 -- caddy version
run_case traefik      docker.io/library/traefik:v3.1              "Version"             -- traefik version
run_case envoy        docker.io/envoyproxy/envoy:v1.31-latest     "version:"            -- envoy --version
run_case node-exp     quay.io/prometheus/node-exporter:v1.8.2     "node_exporter"       -- --version
run_case fluent-bit   cr.fluentbit.io/fluent/fluent-bit:3.1            "Fluent Bit"          -- --version
run_case keycloak     quay.io/keycloak/keycloak:26.0              "Keycloak 26.0"       -- --version
run_case hello-world  docker.io/library/hello-world:latest        "Hello from Docker"
run_case distroless   gcr.io/distroless/static-debian12:latest    "-"

# ---- report -----------------------------------------------------------------
{
  echo "# Fleetwide Supervisor — pull/unpack/exec matrix"
  echo
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) · supervisor image \`$SUPERVISOR_IMAGE\` · platform \`$PLATFORM\` · docker $(docker version --format '{{.Server.Version}}')"
  echo
  echo "Method per image: (A) supervisor \`unpack\` inside a Linux container as root; (B) tree compared with \`docker export\` of the same image — entry names, modes, uid:gid, symlink targets and sha256 of every regular file (excluding Docker's injected \`.dockerenv\`, \`/etc/mtab\`, \`/etc/hosts\`, \`/etc/hostname\`, \`/etc/resolv.conf\`, the bare \`/etc\` directory entry, \`/dev\`, \`/proc\`, \`/sys\`); (C) supervisor \`run\` inside the \`FROM scratch\` supervisor container — extracts the image over \`/\` and execs the entrypoint with the given command."
  echo
  echo "**Result: $pass passed, $fail failed.**"
  echo
  echo "| image | reference | digest | layers | files/dirs/symlinks/hardlinks | whiteouts+opaque/removed | tree vs docker export | run | warnings | ok |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
  for r in "${rows[@]}"; do echo "$r"; done
  echo
  echo "Layer cache after the run: $(du -sh "$CACHE" | cut -f1), $(ls "$CACHE/blobs/sha256" | wc -l | tr -d ' ') blobs."
} > "$OUT"
echo
echo "report: $OUT  ($pass passed, $fail failed)"
[ $fail -eq 0 ]
