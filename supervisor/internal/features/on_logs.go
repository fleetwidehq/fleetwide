//go:build logs

package features

import v1 "github.com/fleetwidehq/fleetwide/api/v1"

func init() { add(v1.CapLogs) }
