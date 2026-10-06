//go:build linux

// Package runner starts the unpacked application as a child process with the
// image's entrypoint, cmd, env, working directory and user, forwards signals
// and reports its exit code. By the time Start is called the container's root
// filesystem is the vendor image.
package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/passwd"
)

// Options for Start.
type Options struct {
	Root     string // filesystem root the app lives in ("/" for overwrite mode)
	CmdOver  []string
	Log      func(format string, args ...any)
	SkipUser bool // do not drop privileges even if the image sets USER
	// Stdout / Stderr, when set, receive a copy of the app's output in
	// addition to the container's own stdout/stderr (live log streaming).
	Stdout, Stderr io.Writer
}

// Proc is a running (or exited) application process.
type Proc struct {
	cmd  *exec.Cmd
	done chan struct{}
	mu   sync.Mutex
	code int
	sig  syscall.Signal // signal that terminated the main child, 0 when it exited
	err  error
	log  func(string, ...any)
}

// Start launches the application and begins reaping. Returns once the
// process is running. Only one Proc should be alive at a time: as PID 1 the
// reaper collects every child in the container.
func Start(rt imagecfg.Runtime, opts Options) (*Proc, error) {
	if opts.Log == nil {
		opts.Log = func(string, ...any) {}
	}
	if opts.Root != "/" {
		return nil, errors.New("runner: only Root=\"/\" (extract-over-root) is implemented; chroot cannot provide /proc and /sys without CAP_SYS_ADMIN")
	}
	argv := rt.Argv(opts.CmdOver)
	if len(argv) == 0 {
		return nil, errors.New("image has no entrypoint or cmd and none was given")
	}

	env := mergeEnv(rt.Env, os.Environ())
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			os.Setenv(k, v)
		}
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("entrypoint %q: %w (PATH=%s)", argv[0], err, os.Getenv("PATH"))
	}

	cmd := exec.Command(bin, argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if opts.Stdout != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, opts.Stdout)
	}
	if opts.Stderr != nil {
		cmd.Stderr = io.MultiWriter(os.Stderr, opts.Stderr)
	}
	if rt.WorkingDir != "" {
		if err := os.MkdirAll(rt.WorkingDir, 0o755); err == nil {
			cmd.Dir = rt.WorkingDir
		} else {
			opts.Log("warn: workdir %s: %v", rt.WorkingDir, err)
		}
	}
	if rt.User != "" && !opts.SkipUser && os.Geteuid() == 0 {
		uid, gid, err := resolveUser(rt.User)
		if err != nil {
			return nil, fmt.Errorf("USER %q: %w", rt.User, err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}}
		if _, ok := os.LookupEnv("HOME"); !ok || os.Getenv("HOME") == "/root" {
			if home := homeFor(uid); home != "" {
				cmd.Env = append(cmd.Env, "HOME="+home)
			}
		}
		opts.Log("running as uid=%d gid=%d", uid, gid)
	}

	opts.Log("exec %s %q", bin, argv[1:])
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &Proc{cmd: cmd, done: make(chan struct{}), log: opts.Log}
	go p.reap()
	return p, nil
}

// reap is the single wait4(-1) loop: as PID 1 the process must collect
// orphaned grandchildren too, and a separate cmd.Wait would race with it for
// the main child's status.
func (p *Proc) reap() {
	mainPid := p.cmd.Process.Pid
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			p.finish(0, fmt.Errorf("wait4: %w", err))
			return
		}
		if pid != mainPid {
			continue // reaped an orphan
		}
		switch {
		case ws.Exited():
			p.finish(ws.ExitStatus(), nil)
			return
		case ws.Signaled():
			p.mu.Lock()
			p.sig = ws.Signal()
			p.mu.Unlock()
			p.finish(128+int(ws.Signal()), nil)
			return
		}
	}
}

func (p *Proc) finish(code int, err error) {
	p.mu.Lock()
	p.code, p.err = code, err
	p.mu.Unlock()
	close(p.done)
}

// Signaled reports the signal that killed the main child (0 if it exited on
// its own or is still running).
func (p *Proc) Signaled() syscall.Signal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sig
}

// Pid of the main child.
func (p *Proc) Pid() int { return p.cmd.Process.Pid }

// Done is closed when the main child has exited.
func (p *Proc) Done() <-chan struct{} { return p.done }

// Running reports whether the main child is still alive.
func (p *Proc) Running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// Exit returns the exit code once Done is closed.
func (p *Proc) Exit() (int, error) {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.code, p.err
}

// Signal forwards a signal to the main child.
func (p *Proc) Signal(sig os.Signal) error {
	if !p.Running() {
		return nil
	}
	return p.cmd.Process.Signal(sig)
}

// Stop sends stopSig (SIGTERM when nil), waits up to timeout, then SIGKILLs.
func (p *Proc) Stop(stopSig os.Signal, timeout time.Duration) (int, error) {
	if stopSig == nil {
		stopSig = syscall.SIGTERM
	}
	if !p.Running() {
		return p.Exit()
	}
	_ = p.cmd.Process.Signal(stopSig)
	select {
	case <-p.done:
	case <-time.After(timeout):
		p.log("stop: %v timed out after %s, sending SIGKILL", stopSig, timeout)
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	return p.Exit()
}

// Run is Start + wait, for the simple `run` path.
func Run(rt imagecfg.Runtime, opts Options) (int, error) {
	p, err := Start(rt, opts)
	if err != nil {
		return 0, err
	}
	return p.Exit()
}

// mergeEnv layers the container's environment over the image's ENV, the way
// a container runtime does, except that PATH and HOME from the image win and
// FLEETWIDE_* keys are never passed to the app.
func mergeEnv(image, proc []string) []string {
	m := map[string]string{}
	var order []string
	set := func(kv string) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return
		}
		if _, seen := m[k]; !seen {
			order = append(order, k)
		}
		m[k] = v
	}
	for _, kv := range image {
		set(kv)
	}
	for _, kv := range proc {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "FLEETWIDE_") {
			continue
		}
		if k == "PATH" || k == "HOME" {
			if _, fromImage := m[k]; fromImage {
				continue
			}
		}
		set(kv)
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+m[k])
	}
	return out
}

// resolveUser parses "uid", "uid:gid", "name", "name:group" against the
// unpacked rootfs's /etc/passwd and /etc/group.
func resolveUser(spec string) (uint32, uint32, error) {
	pw, err := os.Open("/etc/passwd")
	if err != nil {
		pw = nil
	} else {
		defer pw.Close()
	}
	var gr io.Reader
	if g, err := os.Open("/etc/group"); err == nil {
		defer g.Close()
		gr = g
	}
	var pwr io.Reader
	if pw != nil {
		pwr = pw
	}
	return passwd.Lookup(pwr, gr, spec)
}

func homeFor(uid uint32) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()
	return passwd.Home(f, uid)
}
