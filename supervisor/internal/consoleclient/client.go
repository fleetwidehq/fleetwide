// Package consoleclient talks to the Fleetwide Console: one-time enrollment
// (secret + CSR → client certificate) and mTLS heartbeats.
package consoleclient

import (
	"bytes"
	"context"
	"crypto"
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
	// Hardware names the hardware identity the certificate key is held by
	// (v1.IdentityTPM), or is empty when the key is KeyPEM. Signer is that
	// key; it is not stored and must be set again after LoadIdentity.
	Hardware string
	Signer   crypto.Signer
}

// Hardware is a device that can prove what it is to the console and holds
// the key of the certificate.
type Hardware interface {
	Provider() string
	Challenge() v1.EnrollChallengeRequest
	Answer(*v1.EnrollChallengeResponse) (*v1.Attestation, error)
	Signer() crypto.Signer
}

// TLSCertificate is the client certificate with its key: the stored one, or
// the one the hardware holds.
func (id *Identity) TLSCertificate() (tls.Certificate, error) {
	if id.Hardware == "" {
		return tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	}
	if id.Signer == nil {
		return tls.Certificate{}, errors.New("the certificate key is held by this device's " + id.Hardware + ", which is not open")
	}
	var cert tls.Certificate
	for rest := id.CertPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		cert.Certificate = append(cert.Certificate, b.Bytes)
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("no certificate")
	}
	cert.PrivateKey = id.Signer
	return cert, nil
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
	if b, err := os.ReadFile(filepath.Join(dir, "hardware")); err == nil {
		id.Hardware = strings.TrimSpace(string(b))
	}
	files := map[string]*[]byte{"cert.pem": &id.CertPEM, "ca.pem": &id.CAPEM}
	if id.Hardware == "" {
		files["key.pem"] = &id.KeyPEM
	}
	for name, dst := range files {
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
	if id.Hardware != "" {
		// the key is in the hardware: there is nothing to store
		os.Remove(filepath.Join(dir, "key.pem"))
		if err := w("hardware", []byte(id.Hardware+"\n"), 0o644); err != nil {
			return err
		}
	} else {
		os.Remove(filepath.Join(dir, "hardware"))
		if err := w("key.pem", id.KeyPEM, 0o600); err != nil {
			return err
		}
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
//
// With hardware the console is first asked for a challenge. Where the fleet
// requires hardware identity, the answer goes with the enrollment and the
// certificate is issued for the key the hardware holds.
func Enroll(ctx context.Context, base string, tlsOpts TLSOptions, req v1.EnrollRequest, hw Hardware) (*Identity, error) {
	base = strings.TrimRight(base, "/")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: baseTLS(tlsOpts, hostOf(base))}}
	var signer crypto.Signer
	hardware := ""
	if hw != nil {
		creq := hw.Challenge()
		creq.AppKey, creq.Secret = req.AppKey, req.Secret
		var ch v1.EnrollChallengeResponse
		err := post(ctx, hc, base+"/v1/enroll/challenge", creq, &ch)
		var ref *Refusal
		switch {
		case err == nil && ch.Use:
			att, err := hw.Answer(&ch)
			if err != nil {
				return nil, fmt.Errorf("enroll: hardware attestation: %w", err)
			}
			req.Attestation, signer, hardware = att, hw.Signer(), hw.Provider()
		case err == nil, errors.Is(err, errNotFound):
			// the fleet asks for no hardware identity, or the console
			// predates it
		case errors.As(err, &ref):
			return nil, fmt.Errorf("enroll: %w", err)
		default:
			return nil, fmt.Errorf("enroll: challenge: %w", err)
		}
	}
	var key *ecdsa.PrivateKey
	if signer == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
		signer = key
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fleetwide-supervisor"}}, signer)
	if err != nil {
		return nil, err
	}
	req.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	var resp v1.EnrollResponse
	if err := post(ctx, hc, base+"/v1/enroll", req, &resp); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	var keyPEM []byte
	if key != nil {
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
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
		CertPEM: []byte(resp.Certificate), KeyPEM: keyPEM, CAPEM: caPEM,
		NotAfter: certNotAfter([]byte(resp.Certificate)),
		Hardware: hardware, Signer: func() crypto.Signer {
			if hardware == "" {
				return nil
			}
			return signer
		}(),
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
	cert, err := id.TLSCertificate()
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
	if cur.Hardware != "" {
		return c.renewHardware(ctx, cur)
	}
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

// renewHardware renews a certificate whose key the hardware holds: the key
// stays, only the certificate is new.
func (c *Client) renewHardware(ctx context.Context, cur *Identity) (*Identity, error) {
	if cur.Signer == nil {
		return nil, errors.New("the certificate key is held by this device's " + cur.Hardware + ", which is not open")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fleetwide-supervisor"}}, cur.Signer)
	if err != nil {
		return nil, err
	}
	var resp v1.RenewResponse
	if err := post(ctx, c.hc, c.base+"/v1/supervisor/renew", v1.RenewRequest{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}, &resp); err != nil {
		return nil, err
	}
	id := *cur
	id.CertPEM = []byte(resp.Certificate)
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

// errNotFound is a route the console does not have.
var errNotFound = errors.New("not found")

// ErrSuperseded means this container enrolled again (its identity directory
// was lost) and a newer certificate owns the record; this one re-enrolls.
var ErrSuperseded = errors.New("certificate superseded by another enrollment of this instance")

// Refusal is an answer the console gave with a reason code: the request was
// understood and turned down.
type Refusal struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"error"`
}

func (r *Refusal) Error() string { return r.Message }

// Codes of an enrollment the console refused for a reason that retrying
// quickly does not change.
const (
	RequirementsUnmet = "requirements_unmet" // the device does not meet the requirements of the app and its fleet
	HardwareRequired  = "hardware_required"  // the fleet requires hardware identity and none was offered
	HardwarePending   = "hardware_pending"   // the device waits for an operator's approval
	HardwareUnknown   = "hardware_unknown"   // the device is not registered on the fleet
	HardwareBlocked   = "hardware_blocked"   // an operator blocked the device
)

// Waits reports whether the refusal stands until someone changes the device,
// the fleet or the deployment.
func (r *Refusal) Waits() bool {
	switch r.Code {
	case RequirementsUnmet, HardwareRequired, HardwarePending, HardwareUnknown, HardwareBlocked:
		return true
	}
	return false
}

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
	if resp.StatusCode == http.StatusNotFound && !strings.Contains(url, "/supervisor/") {
		return errNotFound
	}
	if resp.StatusCode/100 != 2 {
		var ref Refusal
		if json.Unmarshal(b, &ref) == nil && ref.Code != "" {
			ref.Status = resp.StatusCode
			return &ref
		}
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
