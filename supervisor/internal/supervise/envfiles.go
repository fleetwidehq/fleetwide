package supervise

import (
	"os"
	"path/filepath"
	"strings"
)

// Console-delivered environment is also written to files so that scripts,
// cron jobs and `docker exec` shells can use it. A container's exec
// environment is fixed by Docker at creation time, so files are the only
// way to reach processes the supervisor did not start.
const (
	EnvFile     = "/run/fleetwide/env"              // NAME=VALUE lines: `set -a; . /run/fleetwide/env`
	EnvProfile  = "/etc/profile.d/fleetwide-env.sh" // exports, sourced by login shells (`sh -l`, `bash -l`)
	EnvDir      = "/run/fleetwide/env.d"            // one file per variable (systemd/envdir style)
	envFileMode = 0o600
)

// WriteEnvFiles (re)writes the env files from NAME=VALUE pairs. Errors are
// returned but callers treat them as non-fatal: the app already has the env.
func WriteEnvFiles(vars []string) error {
	os.MkdirAll(filepath.Dir(EnvFile), 0o755)
	os.MkdirAll(filepath.Dir(EnvProfile), 0o755)
	os.RemoveAll(EnvDir)
	os.MkdirAll(EnvDir, 0o700)
	var plain, prof strings.Builder
	prof.WriteString("# Written by fleetwide-supervisor: environment delivered by the console for the current release.\n")
	for _, kv := range vars {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		plain.WriteString(k + "=" + v + "\n")
		prof.WriteString("export " + k + "=" + shellQuote(v) + "\n")
		os.WriteFile(filepath.Join(EnvDir, k), []byte(v), envFileMode)
	}
	if err := os.WriteFile(EnvFile, []byte(plain.String()), envFileMode); err != nil {
		return err
	}
	return os.WriteFile(EnvProfile, []byte(prof.String()), envFileMode)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
