package registry

import (
	"encoding/base64"
	"testing"
)

func TestDecodeECRToken(t *testing.T) {
	u, p, err := decodeECRToken(base64.StdEncoding.EncodeToString([]byte("AWS:eyJwYXlsb2FkIjoi")))
	if err != nil || u != "AWS" || p != "eyJwYXlsb2FkIjoi" {
		t.Fatalf("%q %q %v", u, p, err)
	}
	if _, _, err := decodeECRToken("%%%"); err == nil {
		t.Fatal("garbage must fail")
	}
	if _, _, err := decodeECRToken(base64.StdEncoding.EncodeToString([]byte("nocolon"))); err == nil {
		t.Fatal("missing password must fail")
	}
}

func TestECRRegion(t *testing.T) {
	for host, want := range map[string]string{
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com":          "eu-west-1",
		"123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com": "us-gov-west-1",
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn":      "cn-north-1",
		"public.ecr.aws": "",
		"ghcr.io":        "",
	} {
		if got := ecrRegion(host); got != want {
			t.Fatalf("%s: %q want %q", host, got, want)
		}
	}
}

// A gcp credential becomes a JSON-key authenticator; an aws one without a
// region for a non-ECR host is refused before any network call.
func TestConsoleKeychainCloudTypes(t *testing.T) {
	k := consoleKeychain{a: Auth{Registry: "europe-docker.pkg.dev", Type: "gar", Secret: `{"type":"service_account","client_email":"x@y","private_key":"-----BEGIN PRIVATE KEY-----\n"}`}}
	if a, err := k.Resolve(resource("europe-docker.pkg.dev")); err != nil || a == nil {
		t.Fatalf("gcp: %v %v", a, err)
	}
	k = consoleKeychain{a: Auth{Registry: "registry.example.com", Type: "ecr", Username: "AKIA", Secret: "s"}}
	if _, err := k.Resolve(resource("registry.example.com")); err == nil {
		t.Fatal("ecr without a region on a non-ECR host must be refused")
	}
}

type resource string

func (r resource) String() string      { return string(r) }
func (r resource) RegistryStr() string { return string(r) }
