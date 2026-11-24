#!/usr/bin/env bash
# End-to-end test of manifest reading, health checks, in-place restart and the
# optional /fleetwide/ready endpoint, using a local registry so images with a
# baked-in manifest can be pulled by the supervisor exactly like vendor images.
#
# Needs: docker, curl, python3. Usage: scripts/e2e-health.sh [output.md]
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
SUPERVISOR_IMAGE=${SUPERVISOR_IMAGE:-fleetwide/supervisor:dev}
NET=fw-e2e
REG=fw-registry
REGPORT=5001
OUT=${1:-$HERE/test-results/health-ready-matrix.md}
CACHE=${CACHE:-/tmp/fleetwide-matrix/cache}
mkdir -p "$CACHE" "$(dirname "$OUT")"

# use the system curl
CURL=${CURL:-/usr/bin/curl}
pass=0; fail=0; rows=()
ok()   { pass=$((pass+1)); rows+=("| $1 | $2 | ✓ |"); echo "  PASS: $1 — $2"; }
bad()  { fail=$((fail+1)); rows+=("| $1 | **$2** | ✗ |"); echo "  FAIL: $1 — $2"; }
code() { $CURL -s -o /dev/null -w '%{http_code}' --max-time 2 "$1" 2>/dev/null; } # prints 000 on connection failure
jsonf(){ $CURL -s --max-time 2 "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$2" 2>/dev/null; }
# wait_code URL CODE TIMEOUT_S → prints seconds waited, returns 1 on timeout
wait_code(){ local t=0; while [ $t -lt $3 ]; do [ "$(code "$1")" = "$2" ] && { echo $t; return 0; }; sleep 1; t=$((t+1)); done; echo $t; return 1; }
cleanup(){ docker rm -f fw-a1 fw-a2 fw-a3 fw-a4 fw-a5 >/dev/null 2>&1; }
trap 'cleanup' EXIT

echo "== setup: network + local registry + test images"
docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null
docker rm -f $REG >/dev/null 2>&1
docker run -d --name $REG --network $NET -p $REGPORT:5000 registry:2 >/dev/null
for i in nginx-fw flaky; do
  docker build --platform linux/arm64 -q -t localhost:$REGPORT/test/$i:1 "$HERE/test/images/$i" >/dev/null && docker push -q localhost:$REGPORT/test/$i:1 >/dev/null || { echo "build/push $i failed"; exit 1; }
done
DRUN="docker run -d --network $NET -v $CACHE:/cache"
RUN_FLAGS="run --quiet --cache /cache --plain-http"
RUN_FLAGS_V="run --cache /cache --plain-http"   # with supervisor logs, for log assertions

# ---------------------------------------------------------------- 1. nginx-fw
echo "== 1. nginx + manifest in image (http health, ready endpoint from manifest)"
cleanup
$DRUN --name fw-a1 -p 9100:9100 -p 8081:80 $SUPERVISOR_IMAGE $RUN_FLAGS $REG:5000/test/nginx-fw:1 >/dev/null; sleep 0.5
first=$(code http://localhost:9100/fleetwide/ready)
t=$(wait_code http://localhost:9100/fleetwide/ready 200 15) && ok "nginx ready" "ready 200 after ${t}s (first response $first during grace)" || bad "nginx ready" "never 200 (last $(code http://localhost:9100/fleetwide/ready))"
src=$(jsonf http://localhost:9100/fleetwide/status 'd["manifest"]["source"]'); hk=$(jsonf http://localhost:9100/fleetwide/status 'd["manifest"]["health"]')
[ "$src" = "image:/fleetwide/fleetwide.yaml" ] && [ "$hk" = "http" ] && ok "nginx manifest" "source=$src health=$hk" || bad "nginx manifest" "source=$src health=$hk"
v=$($CURL -s --max-time 2 http://localhost:8081/version.txt); [ "$v" = "nginx-fw v1" ] && ok "nginx serves" "GET /version.txt → $v" || bad "nginx serves" "got '$v'"
$CURL -s -X POST -o /dev/null -d '{"status":"unready"}' http://localhost:9100/fleetwide/override; c=$(code http://localhost:9100/fleetwide/ready); a=$(jsonf http://localhost:9100/fleetwide/ready 'd["actual"]')
[ "$c" = 503 ] && [ "$a" = True ] && ok "nginx override unready" "forced unready → 503 while actual=true (app untouched)" || bad "nginx override unready" "code=$c actual=$a"
$CURL -s -X POST -o /dev/null -d '{"status":"none"}' http://localhost:9100/fleetwide/override; c=$(code http://localhost:9100/fleetwide/ready)
[ "$c" = 200 ] && ok "nginx override cleared" "override none → ready 200" || bad "nginx override cleared" "code=$c"
docker exec fw-a1 /fleetwide-supervisor healthcheck --addr 127.0.0.1:9100; rc=$?
[ $rc -eq 0 ] && ok "healthcheck subcommand" "exit 0 against local ready endpoint" || bad "healthcheck subcommand" "exit $rc"
lc=$(code http://localhost:9100/fleetwide/live); [ "$lc" = 200 ] && ok "nginx live" "/fleetwide/live 200" || bad "nginx live" "code=$lc"
docker stop -t 10 fw-a1 >/dev/null; rc=$(docker wait fw-a1 2>/dev/null || docker inspect -f '{{.State.ExitCode}}' fw-a1)
logs=$(docker logs fw-a1 2>&1)
[ "$rc" = 0 ] && ok "nginx SIGTERM" "docker stop → supervisor exit $rc (app exit forwarded)" || bad "nginx SIGTERM" "exit $rc"

# ---------------------------------------------------------------- 2. flaky
echo "== 2. flaky app: goes unhealthy after 6s → threshold → unhealthy_for → in-place restart → healthy"
$DRUN --name fw-a2 -p 9101:9100 -p 8082:8080 $SUPERVISOR_IMAGE $RUN_FLAGS_V $REG:5000/test/flaky:1 >/dev/null
seq=""; last=""; restarts=0; live_fail=0; t0=$(date +%s)
while [ $(( $(date +%s) - t0 )) -lt 25 ]; do
  c=$(code http://localhost:9101/fleetwide/ready); [ "$c" != "$last" ] && { seq="$seq${seq:+→}$c@$(( $(date +%s) - t0 ))s"; last=$c; }
  l=$(code http://localhost:9101/fleetwide/live); [ "$l" != 200 ] && [ "$l" != 000 ] && live_fail=$((live_fail+1))
  r=$(jsonf http://localhost:9101/fleetwide/status 'd["restarts"]'); [ -n "$r" ] && restarts=$r
  [ "$restarts" = 1 ] && [ "$c" = 200 ] && break
  sleep 0.5
done
body=$($CURL -s --max-time 2 http://localhost:8082/)
echo "  ready timeline: $seq ; restarts=$restarts ; app says: $body"
echo "$seq" | grep -Eq '200@[0-9]+s→503@[0-9]+s→200@' && [ "$restarts" = 1 ] && ok "flaky restart" "ready $seq, restarts=1" || bad "flaky restart" "seq=$seq restarts=$restarts"
[ "$live_fail" = 0 ] && ok "flaky liveness" "/fleetwide/live never left 200 during the managed restart" || bad "flaky liveness" "live returned non-200 $live_fail times"
echo "$body" | grep -q 'first_run=False' && ok "flaky new process" "app reports $body" || bad "flaky new process" "$body"
[ "$(docker logs fw-a2 2>&1 | grep -c 'restarting in place (1/3)')" -gt 0 ] && ok "flaky log" "$(docker logs fw-a2 2>&1 | grep -m1 'restarting in place')" || bad "flaky log" "no restart log line"
[ "$(docker logs fw-a2 2>&1 | grep -c 'UNHEALTHY after 2 consecutive')" -gt 0 ] && ok "flaky threshold" "$(docker logs fw-a2 2>&1 | grep -m1 UNHEALTHY | cut -c1-90)" || bad "flaky threshold" "no UNHEALTHY line"
docker rm -f fw-a2 >/dev/null

# ---------------------------------------------------------------- 3. redis + override manifest
echo "== 3. upstream redis + console-supplied manifest (--manifest override, tcp health)"
$DRUN -v "$HERE/test/manifests/redis-tcp.yaml":/m.yaml:ro --name fw-a3 -p 9102:9100 $SUPERVISOR_IMAGE $RUN_FLAGS --manifest /m.yaml public.ecr.aws/docker/library/redis:7 >/dev/null
t=$(wait_code http://localhost:9102/fleetwide/ready 200 20) && ok "redis tcp ready" "ready 200 after ${t}s" || bad "redis tcp ready" "never 200"
src=$(jsonf http://localhost:9102/fleetwide/status 'd["manifest"]["source"]'); hk=$(jsonf http://localhost:9102/fleetwide/status 'd["health"]["check"]')
[ "$src" = "file:/m.yaml" ] && [ "$hk" = "tcp 127.0.0.1:6379" ] && ok "redis manifest" "source=$src check='$hk'" || bad "redis manifest" "source=$src check=$hk"
docker rm -f fw-a3 >/dev/null

# ---------------------------------------------------------------- 4. alpine + exec check, external damage → restart
echo "== 4. alpine + exec health (test -f /tmp/ok); delete the file → unhealthy → restart recreates it"
$DRUN -v "$HERE/test/manifests/alpine-exec.yaml":/m.yaml:ro --name fw-a4 -p 9103:9100 $SUPERVISOR_IMAGE $RUN_FLAGS --manifest /m.yaml public.ecr.aws/docker/library/alpine:3.20 -- sh -c 'sleep 2; touch /tmp/ok; exec sleep 300' >/dev/null
first=$(code http://localhost:9103/fleetwide/ready)
t=$(wait_code http://localhost:9103/fleetwide/ready 200 15) && ok "exec ready" "ready 200 after ${t}s (first $first)" || bad "exec ready" "never 200"
docker exec fw-a4 rm /tmp/ok
t=$(wait_code http://localhost:9103/fleetwide/ready 503 10) && ok "exec unhealthy" "ready 503 ${t}s after file removed" || bad "exec unhealthy" "stayed 200"
t=$(wait_code http://localhost:9103/fleetwide/ready 200 90) && r=$(jsonf http://localhost:9103/fleetwide/status 'd["restarts"]') && [ "$r" = 1 ] && ok "exec restart" "healthy again after ${t}s, restarts=$r" || bad "exec restart" "t=$t restarts=$(jsonf http://localhost:9103/fleetwide/status 'd["restarts"]')"
docker rm -f fw-a4 >/dev/null

# ---------------------------------------------------------------- 5. defaults, no ready endpoint, exit codes
echo "== 5. no manifest, no endpoint: supervisor exits with the app's code"
rc=$(docker run --rm --network $NET -v $CACHE:/cache $SUPERVISOR_IMAGE $RUN_FLAGS public.ecr.aws/docker/library/hello-world:latest >/dev/null 2>&1; echo $?)
[ "$rc" = 0 ] && ok "defaults hello-world" "exit 0" || bad "defaults hello-world" "exit $rc"
rc=$(docker run --rm --network $NET -v $CACHE:/cache $SUPERVISOR_IMAGE $RUN_FLAGS public.ecr.aws/docker/library/alpine:3.20 -- sh -c 'exit 3' >/dev/null 2>&1; echo $?)
[ "$rc" = 3 ] && ok "defaults exit code" "sh -c 'exit 3' → supervisor exit 3" || bad "defaults exit code" "exit $rc"

# ---------------------------------------------------------------- report
{
  echo "# Fleetwide Supervisor — manifest, health and /fleetwide/ready end-to-end"
  echo
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) · supervisor image \`$SUPERVISOR_IMAGE\` · images pulled from a local \`registry:2\` over plain HTTP (\`--plain-http\`)."
  echo
  echo "**Result: $pass passed, $fail failed.**"
  echo
  echo "| check | evidence | ok |"; echo "|---|---|---|"
  for r in "${rows[@]}"; do echo "$r"; done
  echo
  echo "Scenarios: (1) nginx with \`/fleetwide/fleetwide.yaml\` baked in — HTTP health, ready endpoint address from manifest, forced override, \`healthcheck\` subcommand, SIGTERM forwarding; (2) an app that goes unhealthy 6 s after first start — failure threshold, \`rollback.on_unhealthy_for\`, in-place restart, ready 200→503→200 while /fleetwide/live stays 200; (3) unmodified upstream redis with a Console-style \`--manifest\` override and a TCP check; (4) exec check on alpine, external damage detected and repaired by restart; (5) defaults with no manifest and no endpoint — exit code propagation."
} > "$OUT"
echo; echo "report: $OUT ($pass passed, $fail failed)"
docker rm -f $REG >/dev/null 2>&1
[ $fail -eq 0 ]
