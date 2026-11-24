# Vendor image with a Fleetwide manifest baked in: upstream nginx + fleetwide.yaml.
#   docker build --build-arg VERSION=2 .                       # healthy v2
#   docker build --build-arg VERSION=3 --build-arg MANIFEST=fleetwide-broken.yaml .   # health check that can never pass
# BASE and PORT swap the official image for nginx-unprivileged (port 8080,
# uid 101) to exercise the embedded runtime as a non-root user; APP_USER is
# the USER the final image runs as.
ARG BASE=public.ecr.aws/docker/library/nginx:1.27
FROM ${BASE}
ARG VERSION=1
ARG MANIFEST=fleetwide.yaml
ARG PORT=80
ARG APP_USER=root
USER root
# BROKEN_ENTRYPOINT=1 removes the entrypoint script: a release that stages and
# commits fine and then cannot start — the failure the fleet's on_failure
# policy is for.
ARG BROKEN_ENTRYPOINT=
COPY ${MANIFEST} /fleetwide/fleetwide.yaml
RUN if [ -n "$BROKEN_ENTRYPOINT" ]; then rm /docker-entrypoint.sh; fi
# metrics.txt stands in for the application's own exporter: the supervisor scrapes
# it on the container's loopback, the same as a real /metrics endpoint.
RUN echo "nginx-fw v${VERSION}" > /usr/share/nginx/html/version.txt \
 && echo "only in v${VERSION}" > /usr/share/nginx/html/only-v${VERSION}.txt \
 && printf '# HELP queue_depth Jobs waiting\n# TYPE queue_depth gauge\nqueue_depth{queue="jobs"} 7\nqueue_depth{queue="mail"} 3\nrequests_total 1234\ngo_goroutines 41\n' > /usr/share/nginx/html/metrics.txt \
 && sed -i "s/^version: .*/version: \"${VERSION}\"/" /fleetwide/fleetwide.yaml \
 && sed -i "s#127.0.0.1:80/#127.0.0.1:${PORT}/#g" /fleetwide/fleetwide.yaml
USER ${APP_USER}
