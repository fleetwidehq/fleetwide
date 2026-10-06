// Package buildinfo holds the supervisor/CLI version and the names of the
// supervisor images.
package buildinfo

import (
	"os"
	"strings"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// Version of the supervisor and CLI binaries, stamped at build time:
//
//	go build -ldflags "-X github.com/fleetwidehq/fleetwide/supervisor/internal/buildinfo.Version=1.4.2"
var Version = "0.0.5-dev"

// Registry is the namespace the supervisor images are published under, and
// Tag the tag the CLI embeds by default. Both are stamped the same way as
// Version; FLEETWIDE_IMAGE_REGISTRY / FLEETWIDE_IMAGE_TAG override them at
// run time.
var (
	Registry = "public.ecr.aws/fleetwide"
	Tag      = "latest"
)

func init() {
	if v := os.Getenv("FLEETWIDE_IMAGE_REGISTRY"); v != "" {
		Registry = strings.TrimSuffix(v, "/")
	}
	if v := os.Getenv("FLEETWIDE_IMAGE_TAG"); v != "" {
		Tag = v
	}
}

// DefaultSupervisorImage is the slim image.
func DefaultSupervisorImage() string { return SupervisorImage(v1.VariantSlim) }

// SupervisorImage is the published image for a variant ("slim", "telemetry",
// "developer"). An unknown variant falls back to the slim image.
func SupervisorImage(variant string) string {
	if _, ok := v1.VariantFeatures[variant]; !ok {
		variant = v1.VariantSlim
	}
	return Registry + "/" + variant + ":" + Tag
}
