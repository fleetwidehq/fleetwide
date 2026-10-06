// Package baked describes an image produced by `fleetwide bake`: a customer
// image with the Supervisor layered on top. The Supervisor finds baked.json at
// start and runs the baked application as its fallback release, before or
// without talking to the Console.
package baked

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
)

// Files written into the image by the CLI.
const (
	Dir            = "/fleetwide"
	File           = Dir + "/baked.json"
	PathsFile      = Dir + "/baked.paths.txt" // every path of the customer image, for residue cleanup on first update
	SupervisorPath = "/fleetwide-supervisor"
)

// Info is the content of baked.json.
type Info struct {
	Image  string `json:"image"`  // customer image as baked, pinned by digest
	Digest string `json:"digest"` // platform manifest digest of the customer image
	// IndexDigest is the multi-platform index that manifest came out of,
	// when there was one; a release may pin either.
	IndexDigest       string           `json:"index_digest,omitempty"`
	Platform          string           `json:"platform"`
	Version           string           `json:"version,omitempty"` // release version label, if given
	AppKey            string           `json:"app_key,omitempty"`
	ReleaseID         string           `json:"release_id,omitempty"`
	Runtime           imagecfg.Runtime `json:"runtime"` // original entrypoint/cmd/env/user/workdir
	SupervisorVersion string           `json:"supervisor_version"`
	SupervisorVariant string           `json:"supervisor_variant,omitempty"` // slim | telemetry | developer
	BakedAt           time.Time        `json:"baked_at"`

	// The public half of a deployment key: which console and app this image
	// belongs to, and the fingerprint of that console's CA. The secret is
	// never baked.
	Console  string `json:"console,omitempty"`
	CASHA256 string `json:"ca_sha256,omitempty"`
}

// Load reads baked.json under root. Returns (nil, nil) when the image is not baked.
func Load(root string) (*Info, error) {
	b, err := os.ReadFile(filepath.Join(root, File))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var in Info
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, err
	}
	if in.Digest == "" {
		return nil, errors.New("baked.json: missing digest")
	}
	return &in, nil
}
