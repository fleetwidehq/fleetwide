# Security policy

## Reporting a vulnerability

Use **Report a vulnerability** on this repository's Security tab (GitHub
private vulnerability reporting), or email **info@cloud2scale.com** with
"security" in the subject. Include a description, the affected component
(supervisor, CLI, console, proxy) and steps to reproduce. Do not open a
public issue for a vulnerability.

You will get an acknowledgement within two business days and a fix or a
mitigation plan within thirty. We credit reporters in the release notes
unless asked not to.

## Scope

- The supervisor and CLI in this repository, the published images under
  `public.ecr.aws/fleetwide`, and the wire protocol in `api/`.
- The hosted console and proxy at fleetwide.io and fleetwide.app. Please keep
  testing to accounts and containers you own; do not access other
  organizations' data or disrupt the service.

## Supported versions

The latest release receives fixes. Containers on the `latest` or major (`1`)
image tag pick fixes up on their next pull; the console shows the supervisor
version each container runs.

## What the supervisor does and does not do

Knowing the boundaries helps triage:

- It runs as root inside its container with Docker's default capabilities
  (embedded mode runs as the image's own user with none), writes releases
  over the container's own filesystem, and never writes into a mount point.
- All connections are outbound over mutual TLS. The proxy tunnel can only
  reach ports of the container the supervisor runs in; the protocol has no
  field for another host.
- Images are pulled by digest and verified while streaming; registry
  credentials stay on the customer's side or are delivered encrypted to one
  fleet.

A report that one of these boundaries can be crossed is the kind we most
want to hear about.
