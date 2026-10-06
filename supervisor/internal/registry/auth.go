package registry

import (
	"context"
	"io"
	"regexp"
	"strings"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
)

// Auth is an explicit credential for one registry host, handed to the Supervisor
// by the Console for a release. Username+Secret is basic auth (GHCR PAT,
// Docker Hub token, Harbor robot, ECR from `get-login-password`, …); an empty
// Username makes Secret a bearer token sent as-is.
type Auth struct {
	Registry string
	Username string // registry: user; aws: access key id
	Secret   string // registry: password or token; aws: secret access key; gcp: service-account JSON
	Type     string // "" or registry: basic/bearer; aws: exchange for an ECR login; gcp: JSON key
	// aws only
	SessionToken string
	RoleARN      string
	Region       string
}

// Keychain returns the credential chain used for every pull:
//
//  1. the Console-supplied credential when its host matches,
//  2. a Docker config (DOCKER_CONFIG or ~/.docker/config.json — mount the
//     customer's docker login or a Kubernetes pull secret there),
//  3. Amazon ECR through the task/instance/IRSA IAM role,
//  4. Google Artifact Registry / GCR through the attached service account.
//
// The first keychain that returns a non-anonymous credential wins.
func Keychain(a *Auth) authn.Keychain {
	chain := []authn.Keychain{}
	if a != nil && a.Secret != "" {
		chain = append(chain, consoleKeychain{a: *a})
	}
	chain = append(chain,
		authn.DefaultKeychain,
		// Only private ECR hosts: public.ecr.aws is pulled anonymously.
		hostKeychain{match: isPrivateECR, kc: authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))},
		google.Keychain, // already limited to gcr.io / *.pkg.dev
	)
	return authn.NewMultiKeychain(chain...)
}

// hostKeychain consults kc only for registries accepted by match.
type hostKeychain struct {
	match func(host string) bool
	kc    authn.Keychain
}

func (h hostKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if !h.match(target.RegistryStr()) {
		return authn.Anonymous, nil
	}
	return h.kc.Resolve(target)
}

var ecrPrivateRE = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr(-fips)?\.[a-z0-9-]+\.amazonaws\.com(\.cn)?(:[0-9]+)?$`)

func isPrivateECR(host string) bool { return ecrPrivateRE.MatchString(host) }

type consoleKeychain struct{ a Auth }

func (k consoleKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if !sameRegistry(k.a.Registry, target.RegistryStr()) {
		return authn.Anonymous, nil
	}
	switch k.a.Type {
	case "ecr":
		// AWS keys, not a login: ask ECR for one (optionally through an
		// assumed role); logins are cached per registry.
		return ecrLogin(context.Background(), k.a, target.RegistryStr())
	case "gar":
		return google.NewJSONKeyAuthenticator(k.a.Secret), nil
	}
	if k.a.Username == "" {
		return authn.FromConfig(authn.AuthConfig{RegistryToken: k.a.Secret}), nil
	}
	return authn.FromConfig(authn.AuthConfig{Username: k.a.Username, Password: k.a.Secret}), nil
}

// sameRegistry compares hosts, treating docker.io / index.docker.io and the
// canonical Docker Hub registry as one.
func sameRegistry(want, got string) bool {
	norm := func(h string) string {
		h = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(h), "https://"), "http://"), "/")
		switch h {
		case "docker.io", "registry-1.docker.io", name.DefaultRegistry:
			return name.DefaultRegistry
		}
		return h
	}
	return norm(want) != "" && norm(want) == norm(got)
}
