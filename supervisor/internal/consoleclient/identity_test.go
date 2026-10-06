package consoleclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inst_x"}, NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A loaded identity knows when its certificate ends, so the supervisor can renew
// a month early and knows when it is already too late.
func TestIdentityExpiry(t *testing.T) {
	dir := t.TempDir()
	in := &Identity{InstallationID: "inst_x", Channel: "stable", CertPEM: selfSigned(t, time.Now().Add(20*24*time.Hour)), KeyPEM: []byte("k"), CAPEM: []byte("ca")}
	if err := in.Save(dir); err != nil {
		t.Fatal(err)
	}
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if id.NotAfter.IsZero() || id.Expired(now) {
		t.Fatalf("20 days left must not be expired: %v", id.NotAfter)
	}
	if !id.RenewDue(now, 30*24*time.Hour) || id.RenewDue(now, 10*24*time.Hour) {
		t.Fatalf("renewal is due inside 30 days and not inside 10: %v", id.NotAfter)
	}
	dead := &Identity{CertPEM: selfSigned(t, now.Add(-time.Hour))}
	dead.NotAfter = certNotAfter(dead.CertPEM)
	if !dead.Expired(now) {
		t.Fatalf("an hour past NotAfter is expired")
	}
	if (&Identity{CertPEM: []byte("junk")}).Expired(now) {
		t.Fatalf("an unreadable certificate is not reported expired (zero NotAfter)")
	}
}
