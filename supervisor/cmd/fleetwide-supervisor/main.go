// fleetwide-supervisor: the Fleetwide supervisor's pull → verify → unpack
// → exec → supervise path.
//
//	fleetwide-supervisor inspect IMAGE
//	fleetwide-supervisor unpack  --dest DIR IMAGE
//	fleetwide-supervisor run     [--ready-listen :9100] [--manifest FILE] IMAGE [-- CMD...]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "golang.org/x/crypto/x509roots/fallback" // TLS roots for a FROM scratch image

	v1 "github.com/fleetwidehq/fleetwide/api/v1"

	"github.com/fleetwidehq/fleetwide/supervisor/internal/assets"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/buildinfo"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/consoleclient"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/features"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/fleet"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/imagecfg"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/layercache"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/manifest"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/registry"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/rootfs"
	"github.com/fleetwidehq/fleetwide/supervisor/internal/supervise"
)

var version = buildinfo.Version

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "unpack":
		err = cmdUnpack(os.Args[2:])
	case "run":
		code, err = cmdRun(os.Args[2:])
	case "assets":
		code, err = cmdAssets(os.Args[2:])
	case "supervise":
		code, err = cmdSupervisor(os.Args[2:])
	case "version":
		fmt.Printf("fleetwide-supervisor %s (%s image", version, features.Variant())
		if live := features.Live(); len(live) > 0 {
			fmt.Printf(": %s", strings.Join(live, ", "))
		}
		fmt.Println(")")
	case "healthcheck":
		// Multi-call entry for a Docker HEALTHCHECK: probes the local ready endpoint.
		code = healthcheck(os.Args[2:])
	case "env", "ps":
		// `docker exec <container> /fleetwide-supervisor env`: show the application
		// process(es) the supervisor supervises and their live environment,
		// including console-delivered values a docker exec shell does not see.
		err = cmdEnv(os.Args[1] == "env")
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fleetwide-supervisor:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  fleetwide-supervisor inspect [--platform os/arch] [--plain-http] IMAGE
  fleetwide-supervisor unpack  [--platform os/arch] [--cache DIR] [--plain-http] --dest DIR [--json] IMAGE
  fleetwide-supervisor run     [--platform os/arch] [--cache DIR] [--plain-http] [--manifest FILE]
                          [--ready-listen ADDR] [--json] IMAGE [-- CMD...]
  fleetwide-supervisor supervise [--state DIR] [--ready-listen ADDR] managed mode (Console-driven)
  fleetwide-supervisor assets  [--watch] [--interval 60s]            fetch the fleet's release assets into their
                                                                 unpack directories and exit (init container);
                                                                 --watch keeps them in sync (sidecar). Needs FLEETWIDE_KEY.
  fleetwide-supervisor healthcheck [--addr 127.0.0.1:9100]
  fleetwide-supervisor env | ps     (inside a running container: the app process and its live environment)
  fleetwide-supervisor version

environment (two variables, and no more):
     FLEETWIDE_KEY=fw1.…            deployment key from the console: URL + app key + secret + CA pin.
                                    The key names the deployment; every container using it is one of
                                    its containers, known by the certificate in its state directory
                                    (a volume keeps it across recreations), else by its pod uid or
                                    container id.
     FLEETWIDE_INSTANCE_NAME=<name> optional display name for this container in the console
     Everything else is a flag on "fleetwide-supervisor supervise": --state --cache --console --app-key --secret
     --console-ca --runtime --insecure-tls --ready-listen --platform.
     What the supervisor can do is not configurable: it is whichever image runs (see "version").
registry credentials (tried in order): release credential from the Console; DOCKER_CONFIG or a config.json mounted
     at /root/.docker, /.docker or /fleetwide/docker; Amazon ECR via the IAM role; Google Artifact Registry via the
     attached service account. Images built with "fleetwide bake" start their baked application before enrolling.`)
}

// defaultCache is where the one-shot commands (unpack, run, assets) keep
// layers when no --cache is given.
func defaultCache() string {
	if os.Geteuid() == 0 {
		return "/var/lib/fleetwide/cache"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "fleetwide")
}

func logf(quiet bool) func(string, ...any) {
	if quiet {
		return func(string, ...any) {}
	}
	return func(f string, a ...any) { fmt.Fprintf(os.Stderr, "fleetwide-supervisor: "+f+"\n", a...) }
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	plat := fs.String("platform", registry.HostPlatform().String(), "os/arch[/variant]")
	plain := fs.Bool("plain-http", false, "allow plain-HTTP registries")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("inspect: need exactly one IMAGE")
	}
	p, err := registry.ParsePlatform(*plat)
	if err != nil {
		return err
	}
	img, err := registry.Resolve(context.Background(), fs.Arg(0), p, registry.Options{Insecure: *plain})
	if err != nil {
		return err
	}
	out := struct {
		*registry.Image
		Runtime imagecfg.Runtime `json:"runtime"`
	}{img, imagecfg.FromConfigFile(img.Config)}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func cmdUnpack(args []string) error {
	fs := flag.NewFlagSet("unpack", flag.ExitOnError)
	plat := fs.String("platform", registry.HostPlatform().String(), "os/arch[/variant]")
	cacheDir := fs.String("cache", defaultCache(), "layer cache directory")
	dest := fs.String("dest", "", "destination directory (created if missing)")
	plain := fs.Bool("plain-http", false, "allow plain-HTTP registries")
	asJSON := fs.Bool("json", false, "print a JSON summary on stdout")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	fs.Parse(args)
	if fs.NArg() != 1 || *dest == "" {
		return fmt.Errorf("unpack: need --dest DIR and exactly one IMAGE")
	}
	if filepath.Clean(*dest) == "/" {
		return fmt.Errorf("unpack: refusing --dest /; use `run` for extract-over-root")
	}
	p, err := registry.ParsePlatform(*plat)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dest, 0o755); err != nil {
		return err
	}
	cache, err := layercache.Open(*cacheDir)
	if err != nil {
		return err
	}
	res, err := rootfs.Materialize(context.Background(), fs.Arg(0), rootfs.Options{
		Cache: cache, Platform: p, Root: *dest, Chown: true, Insecure: *plain, Log: logf(*quiet),
	})
	if err != nil {
		return err
	}
	man, err := manifest.Load(*dest, "")
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			*rootfs.Result
			Manifest *manifest.Manifest `json:"manifest"`
		}{res, man})
	}
	fmt.Printf("unpacked %s (%s) into %s: %d files, %d dirs, %d symlinks, %d hardlinks, %d whiteouts, pull %dms, unpack %dms; manifest: %s (health=%s)\n",
		res.Image.Reference, res.Image.Digest[:19], res.Root, res.Stats.Files, res.Stats.Dirs, res.Stats.Symlinks, res.Stats.Hardlinks,
		res.Stats.Whiteouts+res.Stats.Opaques, res.PullMS, res.UnpackMS, man.Source, man.Health.Kind())
	return nil
}

func cmdRun(args []string) (int, error) {
	var over []string
	for i, a := range args {
		if a == "--" {
			over = args[i+1:]
			args = args[:i]
			break
		}
	}
	fs := flag.NewFlagSet("supervise", flag.ExitOnError)
	plat := fs.String("platform", registry.HostPlatform().String(), "os/arch[/variant]")
	cacheDir := fs.String("cache", defaultCache(), "layer cache directory")
	plain := fs.Bool("plain-http", false, "allow plain-HTTP registries")
	manPath := fs.String("manifest", "", "manifest file overriding the one inside the image")
	readyListen := fs.String("ready-listen", "", "serve /fleetwide/ready on this address (e.g. :9100); empty = off")
	asJSON := fs.Bool("json", false, "print unpack summary JSON on stderr before exec")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return 0, fmt.Errorf("run: need exactly one IMAGE")
	}
	log := logf(*quiet)
	p, err := registry.ParsePlatform(*plat)
	if err != nil {
		return 0, err
	}
	cache, err := layercache.Open(*cacheDir)
	if err != nil {
		return 0, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	res, err := rootfs.Materialize(ctx, fs.Arg(0), rootfs.Options{
		Cache: cache, Platform: p, Root: "/", Chown: true, Insecure: *plain, Log: log,
	})
	stop() // from here on, signals are forwarded to the app by the supervisor
	if err != nil {
		return 0, err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "  ")
		enc.Encode(res)
	}
	man, err := manifest.Load("/", *manPath)
	if err != nil {
		return 0, err
	}
	if *readyListen == "" && man.Ready.Listen != "" {
		*readyListen = man.Ready.Listen
	}
	log("manifest: %s name=%q version=%q health=%s strategy=%s", man.Source, man.Name, man.Version, man.Health.Kind(), man.Update.Strategy)

	sup := supervise.New(supervise.Options{
		Runtime:     &res.Runtime,
		Manifest:    man,
		CmdOver:     over,
		ReadyListen: *readyListen,
		Log:         log,
		Info: map[string]any{
			"release":    map[string]any{"reference": res.Image.Reference, "digest": res.Image.Digest, "platform": res.Image.Platform.String()},
			"supervisor": version,
		},
	})
	return sup.Run(context.Background())
}

func healthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9100", "ready endpoint address")
	fs.Parse(args)
	ok, err := probeReady("http://" + *addr + "/fleetwide/ready")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !ok {
		return 1
	}
	return 0
}

// cmdSupervisor is managed mode: the console decides what runs.
func cmdSupervisor(args []string) (int, error) {
	// Two environment variables: the enrollment key, which names the
	// deployment, and an optional display name. Everything else is a flag.
	// The container is known by its certificate, else its pod uid or
	// container id.
	fs := flag.NewFlagSet("supervise", flag.ExitOnError)
	key := fs.String("key", os.Getenv("FLEETWIDE_KEY"), "deployment key from the console (fw1.…; env FLEETWIDE_KEY)")
	name := fs.String("name", os.Getenv("FLEETWIDE_INSTANCE_NAME"), "display name for this container in the console (env FLEETWIDE_INSTANCE_NAME)")
	stateDir := fs.String("state", "/var/lib/fleetwide", "state directory (identity, current release, layer cache)")
	cacheDir := fs.String("cache", "", "layer cache directory (default <state>/cache)")
	readyListen := fs.String("ready-listen", "", "serve /fleetwide/ready here; the console's healthcheck can also ask for it")
	consoleURL := fs.String("console", "", "Console base URL (not needed with --key or once enrolled)")
	appKey := fs.String("app-key", "", "app key, with --console and --secret instead of --key")
	secret := fs.String("secret", "", "one-time enrollment secret, with --console and --app-key")
	consoleCA := fs.String("console-ca", "", "PEM file of the console CA to trust")
	runtime := fs.String("runtime", "", "k8s|swarm|docker|compose (detected when empty)")
	insecureTLS := fs.Bool("insecure-tls", false, "skip console certificate verification (local testing only)")
	skipSpace := fs.Bool("skip-space-check", false, "do not check free space before pulling (where statfs does not show the real limit)")
	plat := fs.String("platform", registry.HostPlatform().String(), "os/arch[/variant]")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	fs.Parse(args)
	p, err := registry.ParsePlatform(*plat)
	if err != nil {
		return 0, err
	}
	dir := *cacheDir
	if dir == "" {
		dir = filepath.Join(*stateDir, "cache")
	}
	cache, err := layercache.Open(dir)
	if err != nil {
		return 0, err
	}
	var caPEM []byte
	if *consoleCA != "" {
		if caPEM, err = os.ReadFile(*consoleCA); err != nil {
			return 0, fmt.Errorf("--console-ca: %w", err)
		}
	}
	ensureDockerConfig(logf(*quiet))
	ctrl := fleet.New(fleet.Config{
		Key: *key, Console: *consoleURL, AppKey: *appKey, Secret: *secret, Name: *name,
		Runtime: *runtime,
		CAPEM:   caPEM, InsecureTLS: *insecureTLS,
		StateDir: *stateDir, Cache: cache, Platform: p, ReadyListen: *readyListen,
		SupervisorVer: version, Log: logf(*quiet), SkipSpaceCheck: *skipSpace,
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return ctrl.Run(ctx)
}

// cmdAssets is the fetch-only mode for init containers and sidecars: fetch
// the fleet's channel assets into their unpack directories (a shared volume)
// and exit, or keep them in sync with --watch. Nothing is enrolled; the
// deployment key alone proves fleet membership.
func cmdAssets(args []string) (int, error) {
	fs := flag.NewFlagSet("assets", flag.ExitOnError)
	key := fs.String("key", os.Getenv("FLEETWIDE_KEY"), "deployment key from the console (fw1.…)")
	stateDir := fs.String("state", "/var/lib/fleetwide", "state directory (layer cache)")
	watch := fs.Bool("watch", false, "keep syncing instead of exiting after the first pass (sidecar mode)")
	every := fs.Duration("interval", 60*time.Second, "check interval with --watch")
	cacheFlag := fs.String("cache", "", "layer cache directory (default <state>/cache)")
	consoleCA := fs.String("console-ca", "", "PEM file of the console CA to trust")
	insecureTLS := fs.Bool("insecure-tls", false, "skip console certificate verification (local testing only)")
	quiet := fs.Bool("quiet", false, "suppress progress on stderr")
	fs.Parse(args)
	log := logf(*quiet)
	t, err := v1.DecodeKey(*key)
	if err != nil {
		return 0, fmt.Errorf("FLEETWIDE_KEY required: %w", err)
	}
	var caPEM []byte
	if *consoleCA != "" {
		if caPEM, err = os.ReadFile(*consoleCA); err != nil {
			return 0, fmt.Errorf("--console-ca: %w", err)
		}
	}
	cacheDir := *cacheFlag
	if cacheDir == "" {
		cacheDir = filepath.Join(*stateDir, "cache")
	}
	cache, err := layercache.Open(cacheDir)
	if err != nil {
		return 0, err
	}
	ensureDockerConfig(log)
	tlsOpts := consoleclient.TLSOptions{CAPEM: caPEM, CAFingerprint: t.CASHA256, InsecureSkipVerify: *insecureTLS}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lastHash := "\x00"
	for {
		resp, err := consoleclient.FetchAssets(ctx, t.ConsoleURL, tlsOpts, v1.AssetsRequest{AppKey: t.AppKey, Secret: t.Secret})
		if err != nil {
			if !*watch {
				return 0, err
			}
			log("%v (retry in %s)", err, *every)
		} else if resp.AssetsHash != lastHash {
			log("fleet %s follows channel %s: %d asset(s)", resp.FleetID, resp.Channel, len(resp.Assets))
			fleet.ResolveAssetAuthEnv(resp.Assets, log)
			results, err := assets.Sync(ctx, resp.Assets, assets.Options{Cache: cache, Log: log})
			for _, r := range results {
				switch {
				case r.Err != nil:
					fmt.Fprintf(os.Stderr, "  %-16s FAILED  %v\n", r.Name, r.Err)
				case r.Changed:
					fmt.Fprintf(os.Stderr, "  %-16s updated %s -> %s\n", r.Name, shortDigest(r.Digest), r.Path)
				default:
					fmt.Fprintf(os.Stderr, "  %-16s current %s\n", r.Name, shortDigest(r.Digest))
				}
			}
			if err != nil {
				if !*watch {
					return 1, nil
				}
			} else {
				lastHash = resp.AssetsHash
			}
		}
		if !*watch {
			return 0, nil
		}
		select {
		case <-ctx.Done():
			return 0, nil
		case <-time.After(*every):
		}
	}
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// ensureDockerConfig points the Docker-config keychain at a mounted
// credentials file when DOCKER_CONFIG is not set. A scratch image has no
// HOME, so the usual ~/.docker lookup would find nothing.
func ensureDockerConfig(log func(string, ...any)) {
	if os.Getenv("DOCKER_CONFIG") != "" {
		return
	}
	for _, dir := range []string{"/root/.docker", "/.docker", "/fleetwide/docker", "/var/lib/fleetwide/docker", "/kaniko/.docker"} {
		if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
			os.Setenv("DOCKER_CONFIG", dir)
			log("registry credentials: using %s/config.json", dir)
			return
		}
	}
}

// cmdEnv lists direct children of PID 1 (the supervised app) with their
// environment read from /proc, which reflects what the supervisor passed at exec.
func cmdEnv(showEnv bool) error {
	if showEnv {
		if b, err := os.ReadFile(supervise.EnvFile); err == nil {
			fmt.Printf("console-delivered environment (%s; also %s and %s/):\n", supervise.EnvFile, supervise.EnvProfile, supervise.EnvDir)
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if line != "" {
					fmt.Println("  " + line)
				}
			}
			if strings.TrimSpace(string(b)) == "" {
				fmt.Println("  (none)")
			}
		} else {
			fmt.Println("console-delivered environment: none yet (no release deployed)")
		}
		fmt.Println("application process(es):")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	found := 0
	for _, e := range entries {
		pid := e.Name()
		if pid[0] < '0' || pid[0] > '9' || pid == "1" || pid == fmt.Sprint(os.Getpid()) {
			continue
		}
		status, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil {
			continue
		}
		var name, ppid string
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "PPid:") {
				ppid = strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			}
		}
		if ppid != "1" {
			continue
		}
		found++
		cmdline, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		fmt.Printf("pid %s  %s  %s\n", pid, name, strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " ")))
		if !showEnv {
			continue
		}
		env, err := os.ReadFile("/proc/" + pid + "/environ")
		if err != nil {
			fmt.Printf("  (live environ not readable from here: the process runs as another user; the values above were passed at exec)\n")
			continue
		}
		for _, kv := range strings.Split(strings.TrimRight(string(env), "\x00"), "\x00") {
			if kv != "" {
				fmt.Println("  " + kv)
			}
		}
	}
	if found == 0 {
		return fmt.Errorf("no application process running under the supervisor")
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
