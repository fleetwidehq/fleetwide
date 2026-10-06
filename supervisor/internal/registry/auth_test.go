package registry

import (
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func TestECRHostFilter(t *testing.T) {
	for host, want := range map[string]bool{
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com": true, "123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com": true,
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn": true,
		"public.ecr.aws": false, "ghcr.io": false, "index.docker.io": false, "fw-registry:5000": false,
	} {
		if isPrivateECR(host) != want {
			t.Errorf("isPrivateECR(%q) = %v, want %v", host, !want, want)
		}
	}
	// public.ecr.aws must resolve instantly and anonymously (no AWS credential chain)
	ref, _ := name.ParseReference("public.ecr.aws/docker/library/alpine:3.20")
	t0 := time.Now()
	a, err := Keychain(nil).Resolve(ref.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := a.Authorization(); cfg.Username != "" || cfg.Password != "" || cfg.RegistryToken != "" {
		t.Fatalf("public.ecr.aws should be anonymous: %+v", cfg)
	}
	if d := time.Since(t0); d > 500*time.Millisecond {
		t.Fatalf("resolve for public.ecr.aws took %s (AWS credential chain consulted?)", d)
	}
}

func TestConsoleKeychain(t *testing.T) {
	kc := Keychain(&Auth{Registry: "https://registry.corp.internal/", Username: "puller", Secret: "pw"})
	ref, _ := name.ParseReference("registry.corp.internal/team/app:1")
	a, err := kc.Resolve(ref.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := a.Authorization()
	if cfg.Username != "puller" || cfg.Password != "pw" {
		t.Fatalf("expected console credential for matching host, got %+v", cfg)
	}
	// other hosts fall through the chain (anonymous here: no docker config, no cloud)
	other, _ := name.ParseReference("ghcr.io/x/y:1")
	a, _ = kc.Resolve(other.Context())
	if cfg, _ := a.Authorization(); cfg.Username != "" || cfg.Password != "" {
		t.Fatalf("other host must not get the console credential: %+v", cfg)
	}
	// docker hub aliases
	hub := Keychain(&Auth{Registry: "docker.io", Username: "u", Secret: "p"})
	lib, _ := name.ParseReference("library/nginx:1")
	a, _ = hub.Resolve(lib.Context())
	if cfg, _ := a.Authorization(); cfg.Username != "u" {
		t.Fatalf("docker.io alias must match %s: %+v", lib.Context().RegistryStr(), cfg)
	}
	// empty username → bearer token
	tok := consoleKeychain{a: Auth{Registry: "r.example", Secret: "bearer-x"}}
	rr, _ := name.ParseReference("r.example/a:1")
	a, _ = tok.Resolve(rr.Context())
	if cfg, _ := a.Authorization(); cfg.RegistryToken != "bearer-x" {
		t.Fatalf("empty username should yield a registry bearer token: %+v", cfg)
	}
	if a, _ := Keychain(nil).Resolve(rr.Context()); a != authn.Anonymous {
		if cfg, _ := a.Authorization(); cfg.Username != "" {
			t.Fatalf("nil auth must be anonymous for unknown hosts: %+v", cfg)
		}
	}
}
