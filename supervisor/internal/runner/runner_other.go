//go:build !linux

package runner

import (
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
)

// Options mirrors the Linux type so callers compile everywhere.
type Options struct {
	Root           string
	CmdOver        []string
	Log            func(format string, args ...any)
	SkipUser       bool
	Stdout, Stderr io.Writer
}

// Proc mirrors the Linux type.
type Proc struct{}

var errLinuxOnly = errors.New("run is only supported on linux; use `unpack` on this platform")

// Start is Linux-only: the images are Linux images.
func Start(imagecfg.Runtime, Options) (*Proc, error) { return nil, errLinuxOnly }

// Run is Linux-only.
func Run(imagecfg.Runtime, Options) (int, error) { return 0, errLinuxOnly }

func (p *Proc) Pid() int                                   { return 0 }
func (p *Proc) Signaled() syscall.Signal                   { return 0 }
func (p *Proc) Done() <-chan struct{}                      { return nil }
func (p *Proc) Running() bool                              { return false }
func (p *Proc) Exit() (int, error)                         { return 0, errLinuxOnly }
func (p *Proc) Signal(os.Signal) error                     { return errLinuxOnly }
func (p *Proc) Stop(os.Signal, time.Duration) (int, error) { return 0, errLinuxOnly }
