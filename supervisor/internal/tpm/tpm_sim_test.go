//go:build tpmsim

// These tests need the TPM simulator, which is built with cgo and OpenSSL:
//
//	CGO_ENABLED=1 go test -tags tpmsim ./internal/tpm/
//
// With FLEETWIDE_TPM_FIXTURE set to a path they also write the evidence
// they produced there, for the console's verifier tests.
package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
)

func open(t *testing.T) *Device {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("simulator: %v", err)
	}
	d, err := newDevice(sim)
	if err != nil {
		sim.Close()
		t.Fatalf("device: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// credential makes a challenge the way the console does.
func credential(t *testing.T, d *Device, secret []byte) (blob, enc []byte) {
	t.Helper()
	ek, err := tpm2.Unmarshal[tpm2.TPMTPublic](d.EKPub())
	if err != nil {
		t.Fatal(err)
	}
	key, err := tpm2.ImportEncapsulationKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := tpm2.Unmarshal[tpm2.TPMTPublic](d.AKPub())
	if err != nil {
		t.Fatal(err)
	}
	name, err := tpm2.ObjectName(ak)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(name.Buffer, d.ak.name.Buffer) {
		t.Fatalf("the name computed from the public area is not the TPM's: %x vs %x", name.Buffer, d.ak.name.Buffer)
	}
	blob, enc, err = tpm2.CreateCredential(rand.Reader, key, name.Buffer, secret)
	if err != nil {
		t.Fatal(err)
	}
	return blob, enc
}

func TestActivateRecoversTheSecret(t *testing.T) {
	d := open(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	blob, enc := credential(t, d, secret)
	got, err := d.Activate(blob, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %x, want %x", got, secret)
	}
	blob[len(blob)-1] ^= 1
	if _, err := d.Activate(blob, enc); err == nil {
		t.Fatal("a tampered credential was opened")
	}
}

func TestKeysAreTheSameEveryTime(t *testing.T) {
	a := open(t)
	ek, ak, key := a.EKPub(), a.AKPub(), a.KeyPub()
	// the same chip, asked again
	a.flush(a.tls)
	a.flush(a.ak)
	b, err := newDevice(a.t)
	if err != nil {
		t.Fatal(err)
	}
	a.ak, a.tls = b.ak, b.tls // for the cleanup
	if !bytes.Equal(ek, b.EKPub()) || !bytes.Equal(ak, b.AKPub()) || !bytes.Equal(key, b.KeyPub()) {
		t.Fatal("the keys must be derived, not random")
	}
	if bytes.Equal(ak, key) {
		t.Fatal("the attestation key and the identity key must differ")
	}
}

func TestSignerSignsACertificateRequest(t *testing.T) {
	d := open(t)
	s := d.Signer()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, s)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the request is not signed by its key: %v", err)
	}
	digest := sha256.Sum256([]byte("hello"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify")
	}
}

func TestQuoteAndCertify(t *testing.T) {
	d := open(t)
	nonce := bytes.Repeat([]byte{7}, 32)
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7}
	quote, sig, values, err := d.Quote(nonce, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != len(pcrs) {
		t.Fatalf("got %d PCR values, want %d", len(values), len(pcrs))
	}
	info, isig, err := d.CertifyKey(nonce)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	blob, enc := credential(t, d, secret)
	cred, err := d.Activate(blob, enc)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, d.Signer())
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("FLEETWIDE_TPM_FIXTURE"); path != "" {
		out, _ := json.MarshalIndent(map[string]any{
			"ek_pub": d.EKPub(), "ak_pub": d.AKPub(), "ak_name": d.ak.name.Buffer, "nonce": nonce, "csr": der,
			"attestation": v1.Attestation{Provider: v1.IdentityTPM, Credential: cred, Quote: quote, QuoteSig: sig, PCRs: values, KeyPub: d.KeyPub(), KeyCertify: info, KeyCertifySig: isig},
		}, "", "  ")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
