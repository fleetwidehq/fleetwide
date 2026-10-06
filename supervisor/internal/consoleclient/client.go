// Package consoleclient talks to the Fleetwide Console: one-time enrollment
// (secret + CSR → client certificate) and mTLS heartbeats.
package consoleclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

// Identity is the enrolled supervisor's credential set.
type Identity struct {
	InstallationID string
	Channel        string
	ConsoleURL     string // console the supervisor enrolled with
	CertPEM        []byte
	KeyPEM         []byte
	CAPEM          []byte
	NotAfter       time.Time // when CertPEM stops opening the mTLS session; zero if unreadable
}

// certNotAfter reads the expiry off a PEM certificate.
func certNotAfter(certPEM []byte) time.Time {
	if b, _ := pem.Decode(certPEM); b != nil {
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			return c.NotAfter
		}
	}
	return time.Time{}
}

// Expired reports whether the certificate no longer opens a session.
func (id *Identity) Expired(now time.Time) bool {
	return !id.NotAfter.IsZero() && now.After(id.NotAfter)
}

// RenewDue reports whether the certificate is within before of expiring.
func (id *Identity) RenewDue(now time.Time, before time.Duration) bool {
	return !id.NotAfter.IsZero() && now.Add(before).After(id.NotAfter)
}

// LoadIdentity reads an identity saved by Save; os.ErrNotExist if absent.
func LoadIdentity(dir string) (*Identity, error) {
	id := &Identity{}
	b, err := os.ReadFile(filepath.Join(dir, "installation"))
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(b)), " ", 2)
	id.InstallationID = parts[0]
	if len(parts) > 1 {
		id.Channel = parts[1]
	}
	for name, dst := range map[string]*[]byte{"cert.pem": &id.CertPEM, "key.pem": &id.KeyPEM, "ca.pem": &id.CAPEM} {
		if *dst, err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "console")); err == nil {
		id.ConsoleURL = strings.TrimSpace(string(b))
	}
	id.NotAfter = certNotAfter(id.CertPEM)
	return id, nil
}

// Save persists the identity (key 0600).
func (id *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	w := func(name string, b []byte, mode os.FileMode) error {
		return os.WriteFile(filepath.Join(dir, name), b, mode)
	}
	if err := w("key.pem", id.KeyPEM, 0o600); err != nil {
		return err
	}
	if err := w("cert.pem", id.CertPEM, 0o644); err != nil {
		return err
	}
	if err := w("ca.pem", id.CAPEM, 0o644); err != nil {
		return err
	}
	if err := w("console", []byte(id.ConsoleURL+"\n"), 0o644); err != nil {
		return err
	}
	return w("installation", []byte(id.InstallationID+" "+id.Channel+"\n"), 0o644)
}

// TLSOptions controls server verification during enrollment.
type TLSOptions struct {
	CAPEM              []byte // Console CA to trust (bootstrap trust); nil = system roots
	CAFingerprint      string // hex SHA-256 of the Console CA cert: pin the served chain to it (from the install token)
	InsecureSkipVerify bool   // dev only
}

// baseTLS builds the client TLS config. Precedence: explicit CA PEM, then a
// CA fingerprint pin (the Console serves its CA in the chain; we find the
// cert matching the pin and verify the leaf against it for serverName), then
// system roots.
func baseTLS(o TLSOptions, serverName string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureSkipVerify}
	if len(o.CAPEM) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(o.CAPEM)
		cfg.RootCAs = pool
		return cfg
	}
	if o.CAFingerprint != "" && !o.InsecureSkipVerify {
		pin := strings.ToLower(strings.TrimSpace(o.CAFingerprint))
		cfg.InsecureSkipVerify = true // we verify ourselves below
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			pool := x509.NewCertPool()
			var leaf *x509.Certificate
			found := false
			for i, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				if i == 0 {
					leaf = c
				}
				sum := sha256.Sum256(raw)
				if hex.EncodeToString(sum[:]) == pin {
					pool.AddCert(c)
					found = true
				}
			}
			if !found || leaf == nil {
				return errors.New("console chain does not contain the pinned CA certificate")
			}
			_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}
	}
	return cfg
}

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Enroll generates a key pair and CSR, exchanges the one-time secret for a
// certificate and returns the identity. The private key never leaves the
// supervisor.
func Enroll(ctx context.Context, base string, tlsOpts TLSOptions, req v1.EnrollRequest) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fleetwide-supervisor"}}, key)
	if err != nil {
		return nil, err
	}
	req.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	base = strings.TrimRight(base, "/")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: baseTLS(tlsOpts, hostOf(base))}}
	var resp v1.EnrollResponse
	if err := post(ctx, hc, base+"/v1/enroll", req, &resp); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	caPEM := []byte(resp.CA)
	if len(tlsOpts.CAPEM) > 0 {
		caPEM = tlsOpts.CAPEM // keep the CA we were told to trust, not the one the server sent
	} else if tlsOpts.CAFingerprint != "" {
		// The CA the server hands back must be the one we pinned.
		if b, _ := pem.Decode(caPEM); b == nil || hex.EncodeToString(sha256Of(b.Bytes)) != strings.ToLower(strings.TrimSpace(tlsOpts.CAFingerprint)) {
			return nil, errors.New("enroll: returned CA does not match the pinned fingerprint")
		}
	}
	return &Identity{
		InstallationID: resp.InstallationID, Channel: resp.Channel, ConsoleURL: base,
		CertPEM: []byte(resp.Certificate), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), CAPEM: caPEM,
		NotAfter: certNotAfter([]byte(resp.Certificate)),
	}, nil
}

func sha256Of(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// FetchAssets is the fetch-only call for init-container / sidecar layouts:
// a deployment key's secret proves fleet membership; nothing is enrolled.
func FetchAssets(ctx context.Context, base string, tlsOpts TLSOptions, req v1.AssetsRequest) (*v1.AssetsResponse, error) {
	base = strings.TrimRight(base, "/")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: baseTLS(tlsOpts, hostOf(base))}}
	var resp v1.AssetsResponse
	if err := post(ctx, hc, base+"/v1/supervisor/assets", req, &resp); err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	return &resp, nil
}

// Client performs mTLS calls.
type Client struct {
	base string
	hc   *http.Client
}

// New builds an mTLS client from an identity.
func New(base string, id *Identity, insecureSkipVerify bool) (*Client, error) {
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	base = strings.TrimRight(base, "/")
	cfg := baseTLS(TLSOptions{CAPEM: id.CAPEM, InsecureSkipVerify: insecureSkipVerify}, hostOf(base))
	cfg.Certificates = []tls.Certificate{cert}
	return &Client{base: base, hc: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}}, nil
}

// Renew asks for a fresh certificate over the current mTLS session, with a
// new key, and returns the identity to save and use from now on. After a
// successful call the console refuses the old certificate, so the caller
// must save and switch before its next request.
func (c *Client) Renew(ctx context.Context, cur *Identity) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fleetwide-supervisor"}}, key)
	if err != nil {
		return nil, err
	}
	var resp v1.RenewResponse
	if err := post(ctx, c.hc, c.base+"/v1/supervisor/renew", v1.RenewRequest{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}, &resp); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	id := *cur
	id.CertPEM = []byte(resp.Certificate)
	id.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if resp.CA != "" {
		id.CAPEM = []byte(resp.CA)
	}
	id.NotAfter = certNotAfter(id.CertPEM)
	return &id, nil
}

// PostLogs pushes a batch of application output; the reply says whether the
// Console still wants more and the last sequence it holds.
func (c *Client) PostLogs(ctx context.Context, lines []v1.LogLine) (*v1.LogsWanted, error) {
	var resp v1.LogsWanted
	if err := post(ctx, c.hc, c.base+"/v1/supervisor/logs", v1.SupervisorLogsRequest{Lines: lines}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PostMetrics pushes scraped application metrics.
func (c *Client) PostMetrics(ctx context.Context, points []v1.MetricPoint) (*v1.MetricsResponse, error) {
	var resp v1.MetricsResponse
	if err := post(ctx, c.hc, c.base+"/v1/supervisor/metrics", v1.MetricsRequest{Points: points}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Heartbeat posts state and returns the Console's desired state.
func (c *Client) Heartbeat(ctx context.Context, req v1.HeartbeatRequest) (*v1.HeartbeatResponse, error) {
	var resp v1.HeartbeatResponse
	if err := post(ctx, c.hc, c.base+"/v1/supervisor/heartbeat", req, &resp); err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	return &resp, nil
}

// ErrUnknownInstallation means the Console no longer knows this certificate.
var ErrUnknownInstallation = errors.New("installation unknown to console")

// ErrSuperseded means this container enrolled again (its identity directory
// was lost) and a newer certificate owns the record; this one re-enrolls.
var ErrSuperseded = errors.New("certificate superseded by another enrollment of this instance")

func post(ctx context.Context, hc *http.Client, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// Only the console's own answer means the record is gone; a bare 404 is a
	// route that does not exist (a console mid-rollout) and is retried.
	if resp.StatusCode == http.StatusNotFound && strings.Contains(url, "/supervisor/") && strings.Contains(string(b), "unknown installation") {
		return ErrUnknownInstallation
	}
	if resp.StatusCode == http.StatusUnauthorized && strings.Contains(url, "/supervisor/") && strings.Contains(string(b), "superseded") {
		return ErrSuperseded
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
