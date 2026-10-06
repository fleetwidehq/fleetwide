# Fleetwide Supervisor image: one static binary, nothing else.
#
# VARIANT selects which optional features are compiled in:
#   slim         no live logs, no Access tunnel, no telemetry
#   telemetry    telemetry only
#   developer    all three
# Credential helpers (Amazon ECR, Google Artifact Registry) are in every variant.
#
# `docker run <image>` needs no command, only FLEETWIDE_KEY. The other
# subcommands are reachable by overriding the command.
#
# Build from the repo root:
#   docker build -f supervisor/Dockerfile -t fleetwide-supervisor/slim:dev .
#   docker build -f supervisor/Dockerfile --build-arg VARIANT=developer -t fleetwide-supervisor/developer:dev .
# TLS roots are compiled in (golang.org/x/crypto/x509roots/fallback).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
# The supervisor module depends only on api/.
ENV GOWORK=off
COPY api/ api/
COPY supervisor/go.mod supervisor/go.sum supervisor/
RUN cd supervisor && go mod download
COPY supervisor/ supervisor/
ARG TARGETOS TARGETARCH
# VARIANT=slim (default) | telemetry | developer
ARG VARIANT=slim
# VERSION is what the supervisor reports; SUPERVISOR_REGISTRY where its images live.
ARG VERSION=dev
ARG SUPERVISOR_REGISTRY=public.ecr.aws/fleetwide
RUN cd supervisor && \
    case "$VARIANT" in \
      slim)        TAGS="" ;; \
      telemetry)   TAGS="telemetry" ;; \
      developer)   TAGS="logs,access,telemetry" ;; \
      *) echo "unknown VARIANT=$VARIANT (slim|telemetry|developer)" >&2; exit 2 ;; \
    esac; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags "$TAGS" -ldflags="-s -w \
      -X github.com/fleetwidehq/fleetwide/supervisor/internal/buildinfo.Version=$VERSION \
      -X github.com/fleetwidehq/fleetwide/supervisor/internal/buildinfo.Registry=$SUPERVISOR_REGISTRY" \
    -o /out/fleetwide-supervisor ./cmd/fleetwide-supervisor

FROM scratch
COPY --from=build /out/fleetwide-supervisor /fleetwide-supervisor
ARG VARIANT=slim
ARG VERSION=dev
LABEL io.fleetwide.supervisor.variant="$VARIANT" io.fleetwide.supervisor.version="$VERSION"
ENTRYPOINT ["/fleetwide-supervisor"]
CMD ["supervise"]
