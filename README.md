# Fleetwide supervisor and CLI

The supervisor runs inside a container as its entrypoint, keeps the container on
the release its fleet follows, reports health and metrics, and rolls back when a
release fails. The `fleetwide` CLI bakes images and talks to the console.

Docs: https://fleetwide.io/docs

```
curl -fsSL https://fleetwide.io/install.sh | sh
go install github.com/fleetwidehq/fleetwide/supervisor/cmd/fleetwide@latest
```

Images: `public.ecr.aws/fleetwide/{slim,telemetry,developer,cli}`.

## Contributing

Issues are welcome here: bugs, questions and proposals.

This repository is published from the Fleetwide source tree on every release,
and each release replaces its history. Pull requests cannot be merged here, so
open an issue first; a fix that is accepted is applied upstream, tested with the
console and the fleet test suite, credited to you in the release notes, and
appears in the next release.

Licensed under the Apache License 2.0.
