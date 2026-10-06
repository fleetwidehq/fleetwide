// Package imagecfg extracts the runtime-relevant parts of an OCI image config.
package imagecfg

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Runtime is what the supervisor needs to start the application.
type Runtime struct {
	Entrypoint []string          `json:"entrypoint"`
	Cmd        []string          `json:"cmd"`
	Env        []string          `json:"env"`
	WorkingDir string            `json:"working_dir"`
	User       string            `json:"user"`
	Labels     map[string]string `json:"labels,omitempty"`
	StopSignal string            `json:"stop_signal,omitempty"`
	OS         string            `json:"os"`
	Arch       string            `json:"arch"`
	Variant    string            `json:"variant,omitempty"`
}

// FromConfigFile pulls the runtime fields out of a v1.ConfigFile.
func FromConfigFile(cf *v1.ConfigFile) Runtime {
	if cf == nil {
		return Runtime{}
	}
	return Runtime{
		Entrypoint: cf.Config.Entrypoint,
		Cmd:        cf.Config.Cmd,
		Env:        cf.Config.Env,
		WorkingDir: cf.Config.WorkingDir,
		User:       cf.Config.User,
		Labels:     cf.Config.Labels,
		StopSignal: cf.Config.StopSignal,
		OS:         cf.OS,
		Arch:       cf.Architecture,
		Variant:    cf.Variant,
	}
}

// Argv computes the process argv the way a container runtime does:
// entrypoint + cmd, with cmd replaced by override when override is non-empty.
func (r Runtime) Argv(override []string) []string {
	cmd := r.Cmd
	if len(override) > 0 {
		cmd = override
	}
	out := make([]string, 0, len(r.Entrypoint)+len(cmd))
	out = append(out, r.Entrypoint...)
	out = append(out, cmd...)
	return out
}
