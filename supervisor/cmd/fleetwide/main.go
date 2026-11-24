// fleetwide: the vendor CLI.
//
//	fleetwide embed  --app KEY --tag DEST --push        (what the console already knows)
//	fleetwide embed  --dockerfile PATH --tag DEST --push
//	fleetwide bake   … same command, without an app's declared sync paths
//	fleetwide digest [--platform os/arch] [--plain-http] REF
//	fleetwide version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	_ "golang.org/x/crypto/x509roots/fallback"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/buildinfo"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bake", "embed":
		err = cmdBake(os.Args[2:])
	case "digest":
		err = cmdDigest(os.Args[2:])
	case "version":
		fmt.Println("fleetwide", buildinfo.Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fleetwide:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  fleetwide embed --tag DEST [--push] [--output FILE.tar] [--profile slim|telemetry|developer]
      (bake is the same command under its older name)
      Build the Fleetwide supervisor into your image. The result runs your app under the
      supervisor from the first start (offline too) and updates over the air once it can
      reach the console. Push it to any registry (--push, using your docker login / cloud IAM) or
      write a `+"`docker load`"+` tarball (--output) for isolated registries.

      Name the application image in one of three ways:
        --app KEY [--release ID]   take it from the console: the release already knows the
                                   image, its digest and its platform. Needs --api-key (an API
                                   token from Settings → Security); --console only for a
                                   self-hosted console. The image is recorded on the release.
        --local-image NAME         an image in the local Docker daemon.
        --dockerfile PATH          build it with docker first (--context, --build-arg), then bake.
                                   The build is tagged --build-tag NAME and kept; without one
                                   it gets a temporary tag, removed once the bake has read it.
        --image REF                a registry reference, resolved and pinned by digest.

      --platform takes several, comma separated, and pushes one multi-platform tag;
      --all-platforms bakes every platform the source image has.
      --verify runs the result here afterwards and checks the application starts with no key.
      The deployment key is never baked in: pass FLEETWIDE_KEY at run time. The image does
      record which console and app it belongs to, and refuses a key for a different app.

      --tag is the destination reference. --push sends it there with your docker login;
      --output writes it as a tarball instead; give at least one.

      Embedded-runtime apps also need --start embedded|latest (--start-fallback,
      --start-timeout): the supervisor runs as the image's own USER, with no capabilities,
      and keeps the app's declared sync paths in step with each release.

      Other flags: --supervisor-image / --supervisor-binary (override the profile's supervisor),
      --version, --plain-http, --console-ca, --insecure-tls, --json.

  fleetwide digest [--platform linux/arm64] [--plain-http] REF
      Print the platform manifest digest to paste into a private/isolated release.

  fleetwide version`)
}

func remoteOpts(ctx context.Context, p registry.Platform) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(registry.Keychain(nil)),
		remote.WithPlatform(v1.Platform{OS: p.OS, Architecture: p.Arch, Variant: p.Variant}),
	}
}

func parseRef(ref string, insecure bool) (name.Reference, error) {
	var o []name.Option
	if insecure {
		o = append(o, name.Insecure)
	}
	return name.ParseReference(ref, o...)
}

func cmdDigest(args []string) error {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	plat := fs.String("platform", "linux/"+runtime.GOARCH, "os/arch[/variant] of the image to inspect")
	plain := fs.Bool("plain-http", false, "registry speaks plain HTTP")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fleetwide digest REF")
	}
	p, err := registry.ParsePlatform(*plat)
	if err != nil {
		return err
	}
	ref, err := parseRef(fs.Arg(0), *plain)
	if err != nil {
		return err
	}
	desc, err := remote.Get(ref, remoteOpts(context.Background(), p)...)
	if err != nil {
		return err
	}
	// What a release pins: whatever the reference serves. For a
	// multi-platform image that is the index, and every container resolves
	// its own architecture out of it; the digest of one platform's image is
	// printed alongside, for reading rather than pinning.
	fmt.Println(desc.Digest.String())
	if desc.MediaType.IsIndex() {
		if img, err := desc.Image(); err == nil {
			if d, err := img.Digest(); err == nil {
				fmt.Fprintf(os.Stderr, "fleetwide: %s is multi-platform; the %s image inside is %s\n", fs.Arg(0), p, d)
			}
		}
	}
	return nil
}
