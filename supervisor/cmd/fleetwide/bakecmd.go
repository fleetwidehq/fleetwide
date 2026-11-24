package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	gv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	v1 "github.com/fleetwidehq/fleetwide/api/v1"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/bake"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/baked"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/buildinfo"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
)

// Baking puts the supervisor inside a vendor image. The image then runs the
// application on its own — no console, no network — and is adopted as a known
// release when it is given a key.
//
// Three sources:
//
//	--app KEY [--release ID]   bake the release the console knows: it names the
//	                           image, the digest, the platform and the registry
//	                           mode.
//	--local-image NAME         bake an image sitting in the local Docker daemon.
//	--dockerfile PATH          build that Dockerfile first, then bake the result.
//
// --profile picks which supervisor goes in: slim, telemetry or developer.

type bakeSource struct {
	img    gv1.Image
	ref    string // how the application image is referenced, pinned by digest
	digest string
	// indexDigest is set when the reference resolved through a
	// multi-platform index: what a release pins when it serves every
	// architecture.
	indexDigest string
	platform    string
}

// defaultConsole is the hosted console; --console / FLEETWIDE_CONSOLE override it.
const defaultConsole = "https://fleetwide.io"

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func cmdBake(args []string) error {
	fs := flag.NewFlagSet("bake", flag.ExitOnError)
	// where the application image comes from (one of these)
	image := fs.String("image", "", "application image in a registry (tag or digest)")
	localImage := fs.String("local-image", "", "image in the local Docker daemon")
	dockerfile := fs.String("dockerfile", "", "build this Dockerfile with docker, then bake the result")
	buildContext := fs.String("context", ".", "build context for --dockerfile")
	buildTag := fs.String("build-tag", "", "with --dockerfile: tag the built image with this name and keep it (default: a temporary tag, removed afterwards)")
	var buildArgs multiFlag
	fs.Var(&buildArgs, "build-arg", "NAME=VALUE passed to docker build (repeatable)")
	// the console
	consoleURL := fs.String("console", envOr("FLEETWIDE_CONSOLE", defaultConsole), "console base URL; only a self-hosted console needs it (env FLEETWIDE_CONSOLE)")
	apiKey := fs.String("api-key", os.Getenv("FLEETWIDE_API_KEY"), "console API token (env FLEETWIDE_API_KEY)")
	app := fs.String("app", "", "app key: the console supplies the image, digest and platform")
	release := fs.String("release", "", "release id (default: what the app's stable channel points at)")
	consoleCA := fs.String("console-ca", "", "PEM file of the console CA to trust")
	insecureTLS := fs.Bool("insecure-tls", false, "skip console certificate verification (local testing only)")
	// what goes in and where it goes
	profile := fs.String("profile", v1.VariantSlim, "supervisor profile: slim | telemetry | developer")
	supervisorImage := fs.String("supervisor-image", "", "supervisor image to take the supervisor from (default: the profile's published image)")
	var supervisorBinary multiFlag
	fs.Var(&supervisorBinary, "supervisor-binary", "local fleetwide-supervisor binary to bake instead of a supervisor image; for several platforms give one per platform: os/arch=PATH (repeatable)")
	tag := fs.String("tag", "", "destination reference, e.g. registry.example.com/acme/app-fleetwide:1.4.2")
	push := fs.Bool("push", false, "push the baked image to --tag")
	output := fs.String("output", "", "also/instead write a docker-load tarball here")
	plat := fs.String("platform", "linux/"+runtime.GOARCH, "os/arch[/variant], or several separated by commas for a multi-platform image")
	allPlatforms := fs.Bool("all-platforms", false, "bake every platform the source image has")
	verify := fs.Bool("verify", false, "run the baked image locally afterwards and check the application starts")
	version := fs.String("version", "", "release version label (recorded in baked.json)")
	// embedded runtime (the app's runtime on the console decides)
	start := fs.String("start", "", "embedded runtime: embedded (run the embedded app now, sync when the console says) | latest (enroll, sync the assigned release, then start)")
	startFallback := fs.String("start-fallback", "fallback", "with --start latest, when the console is unreachable past --start-timeout: fallback (start the embedded app) | strict (stay down)")
	startTimeout := fs.Duration("start-timeout", 60*time.Second, "with --start latest, how long to wait for the console")
	plain := fs.Bool("plain-http", false, "registries speak plain HTTP (local testing)")
	asJSON := fs.Bool("json", false, "print a JSON summary")
	fs.Parse(args)

	if _, known := v1.VariantFeatures[*profile]; !known {
		return fmt.Errorf("--profile must be slim, telemetry or developer")
	}
	sources := 0
	for _, on := range []bool{*image != "", *localImage != "", *dockerfile != ""} {
		if on {
			sources++
		}
	}
	if sources > 1 {
		return fmt.Errorf("choose one of --image, --local-image or --dockerfile")
	}
	if *tag == "" {
		return fmt.Errorf("--tag is required")
	}
	if !*push && *output == "" {
		return fmt.Errorf("choose --push and/or --output FILE")
	}
	plats, err := parsePlatforms(*plat)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// 1. Ask the console what this release is, when an API token is set.
	// Without one the app key is only a label recorded in baked.json.
	var plan *v1.BakePlan
	var cli *consoleAPI
	if *apiKey != "" {
		if *app == "" {
			return fmt.Errorf("--api-key needs --app (which app this image is for)")
		}
		if *consoleURL == "" {
			return fmt.Errorf("--console must not be empty")
		}
		if cli, err = newConsoleAPI(*consoleURL, *apiKey, *consoleCA, *insecureTLS); err != nil {
			return err
		}
		if plan, err = cli.bakePlan(ctx, *app, *release, *profile); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "fleetwide: %s release %s → %s (%s)\n", plan.AppKey, plan.Version, plan.Image, plan.Platform)
		if sources == 0 {
			*image = plan.Image
		}
	} else if sources == 0 {
		return fmt.Errorf("name the application image: --api-key + --app, --image REF, --local-image NAME or --dockerfile PATH")
	}

	// 2. One platform or several. A multi-platform source is covered whole
	// unless --platform narrows it: each platform gets that architecture's
	// supervisor and its own metadata, and the result is one index.
	platformNamed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "platform" {
			platformNamed = true
		}
	})
	if !*allPlatforms && !platformNamed && *image != "" {
		if have, err := platformsOf(ctx, *image, *plain); err == nil && len(have) > 1 {
			plats = have
			fmt.Fprintf(os.Stderr, "fleetwide: %s is multi-platform (%s); covering all of it — name one with --platform to narrow\n", *image, joinPlatforms(plats))
		}
	}
	if *allPlatforms {
		if *image == "" {
			return fmt.Errorf("--all-platforms needs a registry image (--image or --console + --app)")
		}
		if plats, err = platformsOf(ctx, *image, *plain); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "fleetwide: %s has %s\n", *image, joinPlatforms(plats))
	}
	if len(plats) > 1 {
		if *localImage != "" || *dockerfile != "" {
			return fmt.Errorf("a local image is one platform: bake it with a single --platform")
		}
		if *output != "" {
			return fmt.Errorf("the source covers %s and --output writes one image: name the one you want with --platform", joinPlatforms(plats))
		}
		if !*push {
			return fmt.Errorf("the source covers %s, which can only be pushed as an index (--push), or narrowed with --platform", joinPlatforms(plats))
		}
	}

	dstRef, err := parseRef(*tag, *plain)
	if err != nil {
		return fmt.Errorf("--tag: %w", err)
	}
	supervisorSrc := supervisorSource{image: *supervisorImage, profile: *profile, plain: *plain}
	if supervisorSrc.binaries, err = parseSupervisorBinaries(supervisorBinary, plats); err != nil {
		return err
	}
	if supervisorSrc.image == "" {
		supervisorSrc.image = buildinfo.SupervisorImage(*profile)
		if plan != nil && plan.SupervisorImage != "" {
			supervisorSrc.image = plan.SupervisorImage
		}
	}
	common := bake.Options{Version: *version, AppKey: *app, Variant: *profile, SupervisorVersion: buildinfo.Version}
	if plan != nil {
		common.Version, common.ReleaseID = plan.Version, plan.ReleaseID
		common.Console, common.CAPin = plan.Console, plan.CASHA256
		if common.Console == "" {
			common.Console = strings.TrimSuffix(*consoleURL, "/")
		}
	}
	if *version != "" {
		common.Version = *version
	}
	// The app's runtime decides what is built: an embedded-runtime app gets
	// the supervisor as its USER with the sync paths made writable and the index
	// of everything else; any other app gets the classic baked image.
	var embedOpts *bake.EmbedOptions
	if plan != nil && plan.Runtime == v1.RuntimeEmbedded {
		if *start == "" {
			return fmt.Errorf("%s is an embedded-runtime app: choose --start embedded (run the embedded app at once, sync when the console says) or --start latest (enroll, sync the assigned release, then start)", plan.AppKey)
		}
		if *startFallback != "fallback" && *startFallback != "strict" {
			return fmt.Errorf("--start-fallback must be fallback or strict")
		}
		embedOpts = &bake.EmbedOptions{Options: common, SyncPaths: plan.SyncPaths, AssetPaths: plan.AssetPaths, Start: *start, Fallback: *startFallback, TimeoutS: int(startTimeout.Seconds())}
		fmt.Fprintf(os.Stderr, "fleetwide: embedded runtime — sync paths %s\n", strings.Join(plan.SyncPaths, ", "))
	} else if *start != "" {
		return fmt.Errorf("--start applies to embedded-runtime apps; register %q with runtime embedded and sync paths first", *app)
	}

	// 3. Bake each platform.
	var built []bakedOne
	for _, p := range plats {
		one, err := bakeOne(ctx, p, bakeInputs{
			image: *image, localImage: *localImage, dockerfile: *dockerfile, buildContext: *buildContext, buildTag: *buildTag,
			buildArgs: buildArgs, plain: *plain, plan: plan, supervisor: supervisorSrc, common: common, embed: embedOpts,
		})
		if err != nil {
			return err
		}
		built = append(built, *one)
	}
	if first := built[0]; first.embed != nil {
		fmt.Fprintf(os.Stderr, "fleetwide: made writable for %s: %s\n", first.embed.Info.User, strings.Join(first.embed.Surface, " "))
		fmt.Fprintf(os.Stderr, "fleetwide: index %d bytes (%s), %d sync-path layer(s), metadata layer %s\n", first.embed.IndexBytes, first.embed.Info.IndexSHA256[:19], len(first.embed.Info.SyncLayers), first.embed.MetaLayer[:19])
		for _, w := range first.embed.Warnings {
			fmt.Fprintf(os.Stderr, "fleetwide: warning: %s\n", w)
		}
	}

	// 4. Ship it.
	first := built[0]
	outDigest := first.digest
	if len(built) == 1 {
		if *output != "" {
			if err := tarball.WriteToFile(*output, dstRef, first.img); err != nil {
				return fmt.Errorf("write %s: %w", *output, err)
			}
			fmt.Fprintf(os.Stderr, "fleetwide: wrote %s (docker load -i %s)\n", *output, *output)
		}
		if *push {
			fmt.Fprintf(os.Stderr, "fleetwide: pushing %s\n", dstRef)
			if err := remote.Write(dstRef, first.img, remoteOpts(ctx, first.platform)...); err != nil {
				return fmt.Errorf("push: %w", err)
			}
		}
	} else {
		idx := gv1.ImageIndex(empty.Index)
		idx = mutate.IndexMediaType(idx, types.OCIImageIndex)
		for _, b := range built {
			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
				Add: b.img,
				Descriptor: gv1.Descriptor{Platform: &gv1.Platform{
					OS: b.platform.OS, Architecture: b.platform.Arch, Variant: b.platform.Variant,
				}},
			})
		}
		d, err := idx.Digest()
		if err != nil {
			return err
		}
		outDigest = d.String()
		fmt.Fprintf(os.Stderr, "fleetwide: pushing %s (%s)\n", dstRef, joinPlatforms(plats))
		if err := remote.WriteIndex(dstRef, idx, remoteOpts(ctx, plats[0])...); err != nil {
			return fmt.Errorf("push index: %w", err)
		}
	}

	// 5. Prove it runs, when asked and when it can run here.
	verified := ""
	if *verify {
		if verified, err = verifyBaked(ctx, built, *plain); err != nil {
			return fmt.Errorf("--verify: %w", err)
		}
		fmt.Fprintf(os.Stderr, "fleetwide: verified — %s\n", verified)
	}

	// 6. Tell the console where it went, so the release points at it. An
	// embedded image is published as a release of its own and is not recorded.
	recorded := false
	if cli != nil && plan != nil && *push && embedOpts == nil {
		err := cli.recordBaked(ctx, plan.AppKey, plan.ReleaseID, v1.BakedImage{
			Ref: dstRef.String(), Digest: outDigest, Platform: joinPlatforms(plats),
			Variant: *profile, SupervisorVersion: first.info.SupervisorVersion, BakedAt: time.Now(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "fleetwide: could not record the baked image on the release: %v\n", err)
		} else {
			recorded = true
		}
	}

	info := first.info
	summary := map[string]any{
		"baked_image": dstRef.String(), "baked_digest": outDigest,
		"app_image": info.Image, "app_digest": info.Digest, "platform": joinPlatforms(plats),
		"supervisor": info.SupervisorVersion, "profile": *profile, "recorded": recorded,
	}
	if info.IndexDigest != "" {
		// What a multi-platform release pins: the image was one child of it.
		summary["app_index_digest"] = info.IndexDigest
	}
	if verified != "" {
		summary["verified"] = verified
	}
	if plan != nil {
		summary["app"], summary["release_id"], summary["version"] = plan.AppKey, plan.ReleaseID, plan.Version
	} else {
		hintDigest := info.Digest
		if info.IndexDigest != "" {
			hintDigest = info.IndexDigest // pin the index: one release for every architecture
		}
		summary["release_hint"] = map[string]any{"image": strings.Split(info.Image, "@")[0], "digest": hintDigest, "registry_mode": "private"}
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(summary)
	}
	fmt.Printf("baked   %s\n        %s\n", dstRef, outDigest)
	fmt.Printf("app     %s\n", info.Image)
	fmt.Printf("supervisor %s (%s)\n", info.SupervisorVersion, *profile)
	fmt.Printf("arch    %s\n", joinPlatforms(plats))
	fmt.Printf("\nRun it anywhere:  docker run -d -e FLEETWIDE_KEY=fw1.… %s\n", dstRef)
	if recorded {
		fmt.Printf("The console now points release %s at this image.\n", plan.Version)
	} else if plan == nil {
		fmt.Printf("Publish the app as a release with digest %s so the console adopts what is already running.\n", info.Digest)
	}
	return nil
}

// bakedOne is one platform's result.
type bakedOne struct {
	embed    *bake.EmbedResult // set for an embedded-runtime app
	img      gv1.Image
	info     *baked.Info
	digest   string
	platform registry.Platform
}

// supervisorSource says where the supervisor inside the image comes from.
// parseSupervisorBinaries maps --supervisor-binary to platforms. One bare path is the
// binary for a single-platform bake; for several platforms each one must say
// which it is (os/arch=PATH).
func parseSupervisorBinaries(flags multiFlag, plats []registry.Platform) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	bare := ""
	for _, v := range flags {
		plat, path, qualified := strings.Cut(v, "=")
		if !qualified {
			if bare != "" || len(flags) > 1 {
				return nil, fmt.Errorf("--supervisor-binary: give each one as os/arch=PATH when there is more than one")
			}
			bare = v
			continue
		}
		p, err := registry.ParsePlatform(strings.TrimSpace(plat))
		if err != nil {
			return nil, fmt.Errorf("--supervisor-binary %q: %w", v, err)
		}
		out[p.String()] = strings.TrimSpace(path)
	}
	if bare != "" {
		if len(plats) > 1 {
			return nil, fmt.Errorf("--supervisor-binary is one architecture but this bake covers %s: give one per platform (--supervisor-binary linux/amd64=… --supervisor-binary linux/arm64=…) or use --supervisor-image, which is multi-platform", joinPlatforms(plats))
		}
		out[plats[0].String()] = bare
		return out, nil
	}
	for _, p := range plats {
		if out[p.String()] == "" {
			return nil, fmt.Errorf("--supervisor-binary: nothing given for %s", p)
		}
	}
	return out, nil
}

type supervisorSource struct {
	binaries       map[string]string // platform → local supervisor binary
	image, profile string
	plain          bool
}

type bakeInputs struct {
	image, localImage, dockerfile, buildContext string
	buildTag                                    string
	buildArgs                                   []string
	plain                                       bool
	plan                                        *v1.BakePlan
	supervisor                                  supervisorSource
	common                                      bake.Options
	embed                                       *bake.EmbedOptions
}

// bakeOne resolves the application image and the supervisor for one platform and
// bakes them together.
func bakeOne(ctx context.Context, p registry.Platform, in bakeInputs) (*bakedOne, error) {
	src, err := resolveBakeSource(ctx, p, in.image, in.localImage, in.dockerfile, in.buildContext, in.buildTag, in.buildArgs, in.plain)
	if err != nil {
		return nil, err
	}
	// Bake exactly what the release pins: its platform manifest, or the
	// index it was pinned by when it serves every architecture.
	if in.plan != nil && in.plan.Digest != "" && in.localImage == "" && in.dockerfile == "" {
		if src.digest != in.plan.Digest && src.indexDigest != in.plan.Digest {
			if in.plan.Platform == "" || in.plan.Platform == p.String() {
				return nil, fmt.Errorf("release %s pins %s but the image resolved to %s: bake the release's own image, or pass --release", in.plan.Version, in.plan.Digest, src.digest)
			}
		}
	}
	bo := in.common
	bo.ImageRef, bo.Platform, bo.IndexDigest = src.ref, src.platform, src.indexDigest
	if err := loadSupervisor(ctx, p, in.supervisor, &bo); err != nil {
		return nil, err
	}
	if in.embed != nil {
		eo := *in.embed
		eo.Options = bo
		img, res, err := bake.Embed(src.img, eo)
		if err != nil {
			return nil, err
		}
		d, err := img.Digest()
		if err != nil {
			return nil, err
		}
		info := &baked.Info{Image: res.Info.Image, Digest: res.Info.Digest, IndexDigest: res.Info.IndexDigest, Platform: bo.Platform, AppKey: bo.AppKey, SupervisorVersion: bo.SupervisorVersion, SupervisorVariant: bo.Variant, Console: bo.Console, CASHA256: bo.CAPin, Runtime: res.Info.Process, BakedAt: res.Info.EmbeddedAt}
		return &bakedOne{img: img, info: info, digest: d.String(), platform: p, embed: res}, nil
	}
	img, info, err := bake.Build(src.img, bo)
	if err != nil {
		return nil, err
	}
	d, err := img.Digest()
	if err != nil {
		return nil, err
	}
	return &bakedOne{img: img, info: info, digest: d.String(), platform: p}, nil
}

// loadSupervisor puts the supervisor for this platform into the options.
func loadSupervisor(ctx context.Context, p registry.Platform, a supervisorSource, bo *bake.Options) error {
	if path := a.binaries[p.String()]; path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		bo.Supervisor = b
		fmt.Fprintf(os.Stderr, "fleetwide: supervisor for %s from %s (%d bytes)\n", p, path, len(b))
		return nil
	}
	aref, err := parseRef(a.image, a.plain)
	if err != nil {
		return fmt.Errorf("supervisor image %q: %w", a.image, err)
	}
	fmt.Fprintf(os.Stderr, "fleetwide: supervisor %s (%s profile, %s)\n", aref, a.profile, p)
	ai, err := remote.Image(aref, remoteOpts(ctx, p)...)
	if err != nil {
		return fmt.Errorf("fetch supervisor image: %w", err)
	}
	if bo.SupervisorLayers, err = ai.Layers(); err != nil {
		return err
	}
	if acf, err := ai.ConfigFile(); err == nil {
		if v := acf.Config.Labels["io.fleetwide.supervisor.version"]; v != "" {
			bo.SupervisorVersion = v
		}
	}
	return nil
}

// parsePlatforms reads "linux/arm64" or "linux/arm64,linux/amd64".
func parsePlatforms(spec string) ([]registry.Platform, error) {
	var out []registry.Platform
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := registry.ParsePlatform(part)
		if err != nil {
			return nil, err
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--platform: name at least one os/arch")
	}
	return out, nil
}

// platformsOf lists the platforms a registry image actually has.
func platformsOf(ctx context.Context, image string, plain bool) ([]registry.Platform, error) {
	ref, err := parseRef(image, plain)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(registry.Keychain(nil)))
	if err != nil {
		return nil, err
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("%s is a single image, not a multi-platform index: bake it with --platform", ref)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []registry.Platform
	for _, m := range im.Manifests {
		if m.Platform == nil || m.Platform.OS == "unknown" || m.Platform.Architecture == "unknown" {
			continue // attestation manifests carry no runnable platform
		}
		out = append(out, registry.Platform{OS: m.Platform.OS, Arch: m.Platform.Architecture, Variant: m.Platform.Variant})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no runnable platform", ref)
	}
	return out, nil
}

func joinPlatforms(ps []registry.Platform) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ",")
}

// verifyBaked loads the baked image into the local Docker daemon and runs it
// with no key at all: the application must start from the image alone.
func verifyBaked(ctx context.Context, built []bakedOne, plain bool) (string, error) {
	host, err := registry.ParsePlatform("linux/" + runtime.GOARCH)
	if err != nil {
		return "", err
	}
	var pick *bakedOne
	for i := range built {
		if built[i].platform.OS == "linux" && built[i].platform.Arch == host.Arch {
			pick = &built[i]
		}
	}
	if pick == nil {
		return "", fmt.Errorf("none of the baked platforms (%s) runs on this machine (linux/%s)", joinPlatforms(platformsIn(built)), runtime.GOARCH)
	}
	tmp, err := os.CreateTemp("", "fleetwide-verify-*.tar")
	if err != nil {
		return "", err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	tag := fmt.Sprintf("fleetwide-verify:%d", time.Now().UnixNano())
	ref, err := parseRef(tag, plain)
	if err != nil {
		return "", err
	}
	if err := tarball.WriteToFile(tmp.Name(), ref, pick.img); err != nil {
		return "", err
	}
	if out, err := exec.CommandContext(ctx, "docker", "load", "-i", tmp.Name()).CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker load: %v: %s", err, out)
	}
	defer exec.Command("docker", "rmi", "-f", tag).Run()
	name := fmt.Sprintf("fleetwide-verify-%d", time.Now().UnixNano())
	if out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, tag).CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker run: %v: %s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", name).Run()

	deadline := time.Now().Add(45 * time.Second)
	var logs string
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		b, _ := exec.Command("docker", "logs", name).CombinedOutput()
		logs = string(b)
		running, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
		if strings.TrimSpace(string(running)) != "true" {
			return "", fmt.Errorf("the container exited on its own:\n%s", tail(logs, 20))
		}
		if strings.Contains(logs, "exec ") && strings.Contains(logs, "standalone") {
			return fmt.Sprintf("the baked %s image started %s with no key", pick.platform, firstExec(logs)), nil
		}
	}
	return "", fmt.Errorf("the application did not start within 45s:\n%s", tail(logs, 20))
}

func platformsIn(built []bakedOne) []registry.Platform {
	out := make([]registry.Platform, len(built))
	for i, b := range built {
		out[i] = b.platform
	}
	return out
}

// firstExec pulls the command the supervisor reported starting, for the message.
func firstExec(logs string) string {
	for _, line := range strings.Split(logs, "\n") {
		if i := strings.Index(line, "exec "); i >= 0 {
			return strings.TrimSpace(line[i+5:])
		}
	}
	return "the application"
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// resolveBakeSource turns whichever source was named into an image to bake.
func resolveBakeSource(ctx context.Context, p registry.Platform, image, localImage, dockerfile, buildContext, buildTag string, buildArgs []string, plain bool) (*bakeSource, error) {
	switch {
	case dockerfile != "":
		// --build-tag keeps the built image under a name you chose; without
		// one the image is temporary and removed again after the bake.
		tag, temporary := buildTag, false
		if tag == "" {
			tag, temporary = fmt.Sprintf("fleetwide-build:%d", time.Now().UnixNano()), true
		}
		args := []string{"build", "-f", dockerfile, "-t", tag}
		for _, a := range buildArgs {
			args = append(args, "--build-arg", a)
		}
		args = append(args, buildContext)
		fmt.Fprintf(os.Stderr, "fleetwide: docker %s\n", strings.Join(args, " "))
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("docker build: %w", err)
		}
		src, err := fromDaemon(ctx, tag, p)
		if temporary {
			// The layers are already in hand; the tag is not needed again.
			exec.Command("docker", "rmi", "-f", tag).Run()
		} else {
			fmt.Fprintf(os.Stderr, "fleetwide: built %s (kept)\n", tag)
		}
		return src, err
	case localImage != "":
		return fromDaemon(ctx, localImage, p)
	default:
		ref, err := parseRef(image, plain)
		if err != nil {
			return nil, fmt.Errorf("--image: %w", err)
		}
		fmt.Fprintf(os.Stderr, "fleetwide: fetching %s (%s)\n", ref, p)
		desc, err := remote.Get(ref, remoteOpts(ctx, p)...)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", ref, err)
		}
		indexDigest := ""
		if desc.MediaType.IsIndex() {
			indexDigest = desc.Digest.String()
		}
		img, err := desc.Image()
		if err != nil {
			if indexDigest != "" {
				return nil, fmt.Errorf("%s has no %s image", ref, p)
			}
			return nil, fmt.Errorf("fetch %s: %w", ref, err)
		}
		d, err := img.Digest()
		if err != nil {
			return nil, err
		}
		// An index is descended by platform, but a single-platform image is
		// served whatever platform was asked for: check what actually came
		// back, or the result would claim an architecture it does not have.
		if cf, err := img.ConfigFile(); err == nil && cf.Architecture != "" && cf.OS != "" {
			if got := cf.OS + "/" + cf.Architecture; got != p.OS+"/"+p.Arch {
				return nil, fmt.Errorf("%s is %s, not %s: it has no %s variant", ref, got, p, p)
			}
		}
		return &bakeSource{img: img, ref: ref.Context().Name() + "@" + d.String(), digest: d.String(), indexDigest: indexDigest, platform: p.String()}, nil
	}
}

// fromDaemon reads an image out of the local Docker daemon through
// `docker save`. A locally built image has no registry digest, so the digest
// of the image as saved is recorded instead.
func fromDaemon(ctx context.Context, ref string, p registry.Platform) (*bakeSource, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("--local-image %q: %w", ref, err)
	}
	tmp, err := os.CreateTemp("", "fleetwide-save-*.tar")
	if err != nil {
		return nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	fmt.Fprintf(os.Stderr, "fleetwide: docker save %s\n", r)
	cmd := exec.CommandContext(ctx, "docker", "save", r.String(), "-o", tmp.Name())
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker save %s: %w (is the daemon running and the image built?)", r, err)
	}
	img, err := tarball.ImageFromPath(tmp.Name(), nil)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tmp.Name(), err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	if cf.Architecture != "" && cf.OS != "" {
		if got := cf.OS + "/" + cf.Architecture; got != p.String() {
			return nil, fmt.Errorf("%s is %s but --platform says %s", r, got, p)
		}
	}
	d, err := img.Digest()
	if err != nil {
		return nil, err
	}
	return &bakeSource{img: img, ref: r.String(), digest: d.String(), platform: p.String()}, nil
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// ---- console API ----

type consoleAPI struct {
	base  string
	token string
	hc    *http.Client
}

func newConsoleAPI(base, token, caFile string, insecure bool) (*consoleAPI, error) {
	tc := &tls.Config{InsecureSkipVerify: insecure}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("--console-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--console-ca: no certificate found in %s", caFile)
		}
		tc.RootCAs = pool
	}
	return &consoleAPI{
		base:  strings.TrimSuffix(base, "/"),
		token: token,
		hc:    &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
	}, nil
}

func (c *consoleAPI) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return fmt.Errorf("console %s %s: %s (%d)", method, path, e.Error, resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (c *consoleAPI) bakePlan(ctx context.Context, app, release, profile string) (*v1.BakePlan, error) {
	path := fmt.Sprintf("/v1/apps/%s/bake?profile=%s", app, profile)
	if release != "" {
		path += "&release=" + release
	}
	var out v1.BakePlan
	if err := c.do(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *consoleAPI) recordBaked(ctx context.Context, app, releaseID string, in v1.BakedImage) error {
	return c.do(ctx, "POST", fmt.Sprintf("/v1/apps/%s/releases/%s/baked", app, releaseID), in, nil)
}
