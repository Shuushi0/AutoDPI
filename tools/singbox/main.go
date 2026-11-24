// Command sing-box is AutoDPI's build of sing-box: the unchanged engine as a
// library, with only what the daemon's configuration uses registered (see
// internal/singbox): the tun, mixed, socks and direct inbounds, the direct and
// socks outbounds, the WireGuard endpoint and the plain, TLS and HTTPS DNS
// transports. The stock command registers every protocol and service, and the
// linker then keeps all of them and their dependencies; here they are never
// referenced, so they are not in the binary.
//
// It takes the commands the daemon, doctor and the tests run:
//
//	sing-box [--disable-color] run -c config.json
//	sing-box check -c config.json
//	sing-box version
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func main() {
	var command, config string
	disableColor := false
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--disable-color":
			disableColor = true
		case (a == "-c" || a == "--config") && i+1 < len(args):
			i++
			config = args[i]
		case strings.HasPrefix(a, "--config="):
			config = strings.TrimPrefix(a, "--config=")
		case !strings.HasPrefix(a, "-") && command == "":
			command = a
		default:
			usage("unknown argument " + a)
		}
	}
	if config == "" {
		config = "config.json"
	}
	if disableColor {
		factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, os.Stderr, "", nil, false)
		if err := factory.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		log.SetStdLogger(factory.Logger())
	}
	var err error
	switch command {
	case "run":
		err = run(config, disableColor)
	case "check":
		err = check(config, disableColor)
	case "version":
		printVersion()
	default:
		usage("unknown command " + command)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage(why string) {
	fmt.Fprintln(os.Stderr, why)
	fmt.Fprintln(os.Stderr, "usage: sing-box [--disable-color] run|check -c config.json | sing-box version")
	os.Exit(2)
}

func printVersion() {
	out := "sing-box version " + C.Version + "\n\n"
	out += "Environment: " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "-tags" && s.Value != "" {
				out += "Tags: " + s.Value + "\n"
			}
		}
	}
	out += "Build: AutoDPI (tun, mixed, socks, direct, wireguard)\n"
	os.Stdout.WriteString(out)
}

// registries holds everything this build can be configured with.
func registries(ctx context.Context) context.Context {
	in := inbound.NewRegistry()
	tun.RegisterInbound(in)
	mixed.RegisterInbound(in)
	socks.RegisterInbound(in)
	direct.RegisterInbound(in) // not in the daemon's configuration: the tests' DNS probe

	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	socks.RegisterOutbound(out)

	ep := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(ep)

	servers := dns.NewTransportRegistry()
	transport.RegisterUDP(servers)
	transport.RegisterTCP(servers)
	transport.RegisterTLS(servers)
	transport.RegisterHTTPS(servers)
	hosts.RegisterTransport(servers)
	local.RegisterTransport(servers)

	return box.Context(ctx, in, out, ep, servers, boxservice.NewRegistry(), certificate.NewRegistry())
}

func create(path string, disableColor bool) (*box.Box, context.CancelFunc, error) {
	base := registries(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config at %s: %w", path, err)
	}
	options, err := json.UnmarshalExtendedContext[option.Options](base, content)
	if err != nil {
		return nil, nil, fmt.Errorf("decode config at %s: %w", path, err)
	}
	if disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(base))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("create service: %w", err)
	}
	return instance, cancel, nil
}

func check(path string, disableColor bool) error {
	instance, cancel, err := create(path, disableColor)
	if err != nil {
		return err
	}
	instance.Close()
	cancel()
	return nil
}

func run(path string, disableColor bool) error {
	instance, cancel, err := create(path, disableColor)
	if err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	// The stock command reloads its configuration on SIGHUP. Nothing in
	// AutoDPI sends it, but unhandled it would kill the process with the
	// capture still set up.
	signal.Ignore(syscall.SIGHUP)
	defer signal.Stop(signals)
	stop := make(chan struct{})
	go func() { <-signals; close(stop) }()

	started := make(chan struct{})
	go func() {
		select {
		case <-stop: // asked to stop while still starting
			cancel()
			closeMonitor(started)
		case <-started:
		}
	}()
	err = instance.Start()
	close(started)
	if err != nil {
		cancel()
		return fmt.Errorf("start service: %w", err)
	}
	debug.FreeOSMemory()

	<-stop
	cancel()
	closed := make(chan struct{})
	go closeMonitor(closed)
	err = instance.Close()
	close(closed)
	if err != nil {
		log.Error("sing-box did not close properly: ", err)
	}
	return nil
}

// closeMonitor ends the process when stopping takes longer than sing-box
// allows itself.
func closeMonitor(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(C.FatalStopTimeout):
		log.Fatal("sing-box did not close!")
	}
}
