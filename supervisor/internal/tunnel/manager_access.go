//go:build access

package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/fleetwidehq/fleetwide/api/tunnel"
	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/consoleclient"
)

// New returns the real manager: this image was built with the access
// feature, so yamux and the tunnel protocol are linked in.
func New(cfg Config) Manager {
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	return &manager{cfg: cfg, listening: map[int]bool{}}
}

type manager struct {
	cfg Config
	mu  sync.Mutex

	endpoint string
	ports    []int
	cancel   context.CancelFunc // running connection loop
	running  bool

	connected bool
	since     time.Time
	lastErr   string
	listening map[int]bool
	closed    bool
}

// Apply follows the console: connect to the endpoint for these ports, or stop.
func (m *manager) Apply(w *v1.TunnelWanted) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if w == nil || w.Endpoint == "" || len(w.Ports) == 0 {
		m.stopLocked()
		return
	}
	ports := append([]int(nil), w.Ports...)
	sort.Ints(ports)
	same := m.endpoint == w.Endpoint && equalInts(m.ports, ports)
	m.ports = ports
	if same && m.running {
		return
	}
	m.stopLocked()
	m.endpoint = w.Endpoint
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.running = cancel, true
	go m.run(ctx, w.Endpoint)
	go m.probe(ctx)
}

func (m *manager) Status() *v1.TunnelState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.endpoint == "" && !m.connected && m.lastErr == "" {
		return nil
	}
	st := &v1.TunnelState{Connected: m.connected, Since: m.since, Endpoint: m.endpoint, Error: m.lastErr}
	for _, p := range m.ports {
		st.Ports = append(st.Ports, v1.PortState{Port: p, Listening: m.listening[p]})
	}
	return st
}

func (m *manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.stopLocked()
}

func (m *manager) stopLocked() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.running, m.connected, m.endpoint = false, false, ""
	m.since = time.Time{}
}

// run keeps one connection to the proxy alive, reconnecting with jittered backoff.
func (m *manager) run(ctx context.Context, endpoint string) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := m.connectAndServe(ctx, endpoint)
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		m.connected = false
		if err != nil {
			m.lastErr = err.Error()
		}
		m.mu.Unlock()
		if err != nil {
			m.cfg.Log("access tunnel: %v (retrying)", err)
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second // a long-lived session resets the backoff
		}
		wait := backoff + time.Duration(rand.Int63n(int64(backoff/5+1)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// connectAndServe upgrades one mTLS HTTP connection to the tunnel protocol and
// serves multiplexed streams until the session ends.
func (m *manager) connectAndServe(ctx context.Context, endpoint string) error {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	tlsCfg, err := m.tlsConfig(host)
	if err != nil {
		return err
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   false,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		Proxy:               http.ProxyFromEnvironment, // corporate HTTPS_PROXY (CONNECT) works
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+endpoint+tunnel.Path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", tunnel.Protocol)
	req.Header.Set(tunnel.HeaderSupervisor, m.cfg.SupervisorVersion)
	m.mu.Lock()
	ports := append([]int(nil), m.ports...)
	m.mu.Unlock()
	req.Header.Set(tunnel.HeaderPorts, joinInts(ports))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("dial %s: %w", endpoint, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		var ref tunnel.Refusal
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(body, &ref) == nil && ref.Message != "" {
			return fmt.Errorf("proxy refused: %s", ref.Message)
		}
		return fmt.Errorf("proxy answered %s", resp.Status)
	}
	conn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return errors.New("upgrade did not yield a bidirectional connection")
	}
	defer conn.Close()
	ycfg := yamux.DefaultConfig()
	ycfg.EnableKeepAlive, ycfg.KeepAliveInterval, ycfg.ConnectionWriteTimeout = true, 15*time.Second, 10*time.Second
	ycfg.MaxStreamWindowSize = 1 << 20
	ycfg.LogOutput = io.Discard
	sess, err := yamux.Server(conn, ycfg)
	if err != nil {
		return err
	}
	defer sess.Close()
	m.mu.Lock()
	m.connected, m.since, m.lastErr = true, time.Now(), ""
	m.mu.Unlock()
	m.cfg.Log("access tunnel connected to %s for ports %s", endpoint, joinInts(ports))
	go func() {
		<-ctx.Done()
		sess.Close()
	}()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("session closed: %w", err)
		}
		go m.handleStream(stream)
	}
}

// handleStream reads the port preamble, dials the app on loopback, answers with
// a status and pipes bytes both ways. The preamble carries only a port, so a
// stream can never reach anything but this container's own loopback.
func (m *manager) handleStream(stream net.Conn) {
	defer stream.Close()
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	port, err := tunnel.ReadOpen(stream)
	stream.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if !m.allowed(port) {
		tunnel.WriteResult(stream, tunnel.Result{Status: tunnel.PortNotAllowed, Message: fmt.Sprintf("port %d is not exposed by an Access", port)})
		return
	}
	up, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		st := tunnel.Refused
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			st = tunnel.Timeout
		}
		tunnel.WriteResult(stream, tunnel.Result{Status: st, Message: fmt.Sprintf("nothing is listening on port %d yet", port)})
		return
	}
	defer up.Close()
	if err := tunnel.WriteResult(stream, tunnel.Result{Status: tunnel.OK}); err != nil {
		return
	}
	pipe(stream, up)
}

// pipe copies both directions and half-closes each side when the other ends.
func pipe(a net.Conn, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func (m *manager) allowed(port int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.ports {
		if p == port {
			return true
		}
	}
	return false
}

// probe reports whether the app listens on each Access port (every 10s).
func (m *manager) probe(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		m.mu.Lock()
		ports := append([]int(nil), m.ports...)
		m.mu.Unlock()
		res := map[int]bool{}
		for _, p := range ports {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 500*time.Millisecond)
			if err == nil {
				c.Close()
				res[p] = true
			}
		}
		m.mu.Lock()
		m.listening = res
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *manager) tlsConfig(serverName string) (*tls.Config, error) {
	var id *consoleclient.Identity
	if m.cfg.Identity != nil {
		id = m.cfg.Identity()
	}
	if id == nil {
		return nil, errors.New("no identity yet")
	}
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ServerName: serverName, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: m.cfg.InsecureTLS}
	if len(id.CAPEM) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(id.CAPEM)
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinInts(ps []int) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
