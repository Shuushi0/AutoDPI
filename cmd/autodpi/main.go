// autodpi: a local, transparent DPI-bypass service for macOS and Windows.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/audit"
	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/daemon"
	"github.com/Shuushi0/AutoDPI/internal/doctor"
	"github.com/Shuushi0/AutoDPI/internal/embedded"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/lab"
	"github.com/Shuushi0/AutoDPI/internal/logx"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/service"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/supervise"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
	"github.com/Shuushi0/AutoDPI/internal/ui"
)

const usageTR = `autodpi — yerel, şeffaf DPI-bypass servisi

Servis (Windows'ta sudo yerine yönetici terminali; install bir Windows hizmeti kurar):
  sudo autodpi install             root daemon'u kur (uninstall ile kaldır)
  sudo autodpi uninstall [--purge] daemon'u kaldır (--purge: öğrenilen listeler de gider)
  autodpi daemon [--for 2m] [--no-tun] [--test-port N] [--log-file F] [-v]
                                   servisi ön planda çalıştır (--for: süre dolunca kendini kapatır;
                                   --test-port: TUN yerine loopback proxy, root gerekmez)

Kullanım:
  autodpi status                   servisin durumu
  autodpi list [--all]             bu ağın listesi (--all: bütün ağlar)
  autodpi add <alan-adı> [motor]   elle ekle (kalıcı, otomatik silinmez)
  autodpi remove <alan-adı>        listeden çıkar
  autodpi test <host> [--all]      hedefi şimdi doğrula (--all: bütün motorları dene)
  autodpi pause | resume           bypass'ı durdur / sürdür
  autodpi networks                 bilinen ağlar
  autodpi log [-n 50]              olay günlüğü
  autodpi maint <eylem>            bakım (sudo gerekmez): clear-logs | restart | shutdown | flush-dns |
                                   retest | reset-list | reset-all-lists | reconcile
  autodpi update [install | skip]  yeni sürümü denetle (install: şimdi kur; skip: bu sürümü atla)

Tanı:
  autodpi doctor                   ön kontroller
  autodpi ui [--no-open]           tarayıcıda ayar ve durum sayfası
  autodpi lab [host...]            hangi teknik bu ağda hangi hedefi açıyor (root gerekmez, VPN kapalı olmalı)
  autodpi version

Dil sistemi izler; seçmek için AUTODPI_LANG=tr ya da en, veya ayarlardaki "language" (dil).
`

const usageEN = `autodpi — local, transparent DPI-bypass service

Service (on Windows an administrator terminal instead of sudo; install sets up a Windows service):
  sudo autodpi install             install the root daemon (remove it with uninstall)
  sudo autodpi uninstall [--purge] remove the daemon (--purge: the learned lists go too)
  autodpi daemon [--for 2m] [--no-tun] [--test-port N] [--log-file F] [-v]
                                   run the service in the foreground (--for: stops by itself after that long;
                                   --test-port: a loopback proxy instead of the TUN, no root needed)

Use:
  autodpi status                   the service's state
  autodpi list [--all]             this network's list (--all: every network)
  autodpi add <domain> [engine]    add by hand (kept for good, never dropped automatically)
  autodpi remove <domain>          take off the list
  autodpi test <host> [--all]      check a host now (--all: try every engine)
  autodpi pause | resume           switch the bypass off / on
  autodpi networks                 known networks
  autodpi log [-n 50]              event log
  autodpi maint <action>           maintenance (no sudo needed): clear-logs | restart | shutdown | flush-dns |
                                   retest | reset-list | reset-all-lists | reconcile
  autodpi update [install | skip]  look for a newer version (install: install it now; skip: skip this version)

Diagnostics:
  autodpi doctor                   pre-flight checks
  autodpi ui [--no-open]           settings and status page in the browser
  autodpi lab [host...]            which technique opens which target on this network (no root, VPN must be off)
  autodpi version

The language follows the system; set AUTODPI_LANG=tr or en, or "language" in the settings, to choose.
`

func usage() string { return i18n.T(usageTR, usageEN) }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case supervise.GuardCmd:
		os.Exit(supervise.RunGuard(args))
	case "daemon":
		runDaemon(args)
	case "install":
		install(args)
	case "uninstall":
		uninstall(args)
	case "status":
		status()
	case "list":
		list(args)
	case "add":
		add(args)
	case "remove":
		remove(args)
	case "test":
		test(args)
	case "pause", "resume":
		simple(ipc.Request{Cmd: cmd}, map[string]string{"pause": i18n.T("duraklatıldı", "paused"), "resume": i18n.T("sürdürüldü", "resumed")}[cmd])
	case "maint":
		maint(args)
	case "update":
		updateCmd(args)
	case "networks":
		networks()
	case "log":
		logCmd(args)
	case "doctor":
		runDoctor()
	case "lab":
		runLab(args)
	case "ui":
		runUI(args)
	case "config-import":
		// The elevated half of a settings save on Windows (internal/ui saveElevated).
		if len(args) != 1 {
			die(i18n.T("kullanım: autodpi config-import DOSYA", "usage: autodpi config-import FILE"))
		}
		if err := ui.ImportConfig(paths.Default().Config, args[0]); err != nil {
			die("%v", err)
		}
	case "lang":
		// The language the texts are in, for scripts (the Windows menu).
		fmt.Println(i18n.Lang())
	case "version", "--version", "-v":
		fmt.Printf(i18n.T("autodpi %s (%s/%s, yardımcı programlar gömülü: %s)\n", "autodpi %s (%s/%s, helper binaries embedded: %s)\n"),
			daemon.Version, runtime.GOOS, runtime.GOARCH, map[bool]string{true: i18n.T("evet", "true"), false: i18n.T("hayır", "false")}[embedded.Embedded()])
	case "help", "--help", "-h":
		fmt.Print(usage())
	default:
		fmt.Fprintf(os.Stderr, i18n.T("bilinmeyen komut %q\n\n%s", "unknown command %q\n\n%s"), cmd, usage())
		os.Exit(2)
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, i18n.T("hata: ", "error: ")+format+"\n", a...)
	os.Exit(1)
}

// parseFlags parses a command's flags. The flag package's errors and usage
// are English; this prints them in the user's language: the usage and exit 0
// for -h, the error, the usage and exit 2 for a bad flag.
func parseFlags(fs *flag.FlagSet, args []string) {
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	if err == nil {
		return
	}
	if errors.Is(err, flag.ErrHelp) {
		printFlags(os.Stdout, fs)
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, i18n.T("hata: ", "error: ")+flagError(err))
	printFlags(os.Stderr, fs)
	os.Exit(2)
}

var badValueRE = regexp.MustCompile(`^invalid (?:boolean )?value ("[^"]*") for (?:flag )?(-\S+): `)

// flagError says what the flag package's error says.
func flagError(err error) string {
	msg := err.Error()
	for _, p := range []struct{ en, tr string }{
		{"flag provided but not defined: ", "tanımsız seçenek: "},
		{"flag needs an argument: ", "seçenek bir değer ister: "},
		{"bad flag syntax: ", "hatalı seçenek: "},
	} {
		if rest, ok := strings.CutPrefix(msg, p.en); ok {
			return i18n.T(p.tr, p.en) + rest
		}
	}
	if m := badValueRE.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf(i18n.T("%s için geçersiz değer: %s", "invalid value %[2]s for %[1]s"), m[2], m[1])
	}
	return msg
}

// printFlags is the command's usage: its flags with their help texts.
func printFlags(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, i18n.T("kullanım: autodpi %s [seçenekler]\n", "usage: autodpi %s [options]\n"), fs.Name())
	types := map[string]string{"duration": i18n.T("süre", "duration"), "int": i18n.T("sayı", "int"), "string": i18n.T("metin", "string")}
	fs.VisitAll(func(f *flag.Flag) {
		typ, usage := flag.UnquoteUsage(f)
		line := "  -" + f.Name
		if t := types[typ]; t != "" {
			line += " " + t
		} else if typ != "" {
			line += " " + typ
		}
		line += "\n    \t" + usage
		if d := f.DefValue; d != "" && d != "0" && d != "0s" && d != "false" {
			line += fmt.Sprintf(i18n.T(" (varsayılan %s)", " (default %s)"), d)
		}
		fmt.Fprintln(w, line)
	})
}

func self() string {
	exe, err := os.Executable()
	if err != nil {
		die(i18n.T("kendi yolum bulunamadı: %v", "cannot find my own path: %v"), err)
	}
	return exe
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	noTun := fs.Bool("no-tun", false, i18n.T("sistem yakalamasını (TUN) açma; geri kalan her şey çalışır, root gerekmez", "do not capture the system (TUN); everything else runs, no root needed"))
	dur := fs.Duration("for", 0, i18n.T("bu süre sonunda kendini kapat (güvenli deneme)", "stop by itself after this long (a safe trial)"))
	logFile := fs.String("log-file", "", i18n.T("günlük dosyası (boşsa stderr)", "log file (stderr when empty)"))
	verbose := fs.Bool("v", false, i18n.T("ayrıntılı günlük", "verbose log"))
	testPort := fs.Int("test-port", 0, i18n.T("geliştirme: TUN yerine bu loopback portunda aynı kurallarla bir proxy aç (root gerekmez)", "development: a proxy with the same rules on this loopback port instead of the TUN (no root needed)"))
	parseFlags(fs, args)

	var w io.Writer = os.Stderr
	var logFiles []string
	if *logFile != "" {
		logFiles = []string{*logFile, *logFile + ".1"}
		if runtime.GOOS == "darwin" {
			logFiles = append(logFiles, "/var/log/autodpi.crash.log") // = launchd.CrashLog (that package is macOS only)
		}
		rot, err := logx.Open(*logFile, 5<<20)
		if err != nil {
			die(i18n.T("günlük dosyası: %v", "log file: %v"), err)
		}
		defer rot.Close()
		w = rot
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))

	if !sysx.IsRoot() && !*noTun && *testPort == 0 {
		die(i18n.T("TUN için root gerekir: %s ile autodpi daemon ... (root'suz denemek için --no-tun)", "the TUN needs root: autodpi daemon ... with %s (--no-tun to try without root)"), sysx.AdminHint())
	}
	p := paths.Default()
	cfg, err := config.Load(p.Config)
	if err != nil {
		// A broken override file must not turn into a boot-time crash loop.
		log.Error("config ignored, using defaults", "err", err)
		cfg = config.Default()
	}
	for _, w := range cfg.Warnings {
		log.Warn("config", "note", w)
	}
	daemon.TuneRuntime()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	body := func(ctx context.Context) error {
		return daemon.New(cfg, p, self(), log).Run(ctx, daemon.Options{
			NoTun: *noTun, MaxRuntime: *dur, TestPort: *testPort, LogFiles: logFiles, Supervised: service.Supervised(),
		})
	}
	// On Windows, when the Service Control Manager started us, service.Run
	// reports to it and turns Stop/Shutdown into the end of ctx.
	if err := service.Run(ctx, body); err != nil {
		if errors.Is(err, daemon.ErrRestart) {
			log.Info("daemon stopped for restart")
			os.Exit(75) // non-zero: launchd starts it again (the SCM saw service.Run end in error)
		}
		log.Error("daemon stopped", "err", err)
		die("%v", err)
	}
}

func install(args []string) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	parseFlags(fs, args)
	if !embedded.Embedded() {
		die(i18n.T("bu derleme yardımcı ikili dosyaları içermiyor; kurulum için scripts/build.sh ile üretilen dist/autodpi kullanın", "this build does not embed the helper binaries; install the dist/autodpi that scripts/build.sh produces"))
	}
	p := paths.Default()
	if err := service.Install(p, self()); err != nil {
		die("%v", err)
	}
	fmt.Println(i18n.T("kuruldu. Durum için: autodpi status   ·   günlük: ", "installed. State: autodpi status   ·   log: ") + service.LogPath(p))
	switch err := service.InstallTray(p, self()); {
	case err == nil:
		fmt.Println(i18n.T("tepsi simgesi kuruldu: her oturum açılışında başlar; şimdi açmak için Başlat menüsünde AutoDPI", "tray icon installed: it starts at every sign-in; open AutoDPI from the Start menu to start it now"))
	case !errors.Is(err, service.ErrTrayAbsent):
		fmt.Fprintf(os.Stderr, i18n.T("uyarı: tepsi simgesi kurulamadı (servis kuruldu ve çalışıyor): %v\n", "warning: the tray icon was not installed (the service is installed and running): %v\n"), err)
	}
}

func uninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, i18n.T("öğrenilen listeleri de sil", "delete the learned lists too"))
	parseFlags(fs, args)
	if err := service.Uninstall(paths.Default(), *purge); err != nil {
		die("%v", err)
	}
	fmt.Println(i18n.T("kaldırıldı.", "removed."))
}

// ---- client commands -------------------------------------------------------

func call(req ipc.Request, out any, timeout time.Duration) {
	if err := ipc.Call(paths.Default().Sock, req, out, timeout); err != nil {
		die("%v", err)
	}
}

func simple(req ipc.Request, done string) {
	call(req, nil, 10*time.Second)
	fmt.Println(done)
}

// maintDone is what each maintenance action prints when it went through.
func maintDone(action string) string {
	start := "sudo launchctl kickstart system/com.autodpi.daemon"
	if runtime.GOOS == "windows" {
		start = i18n.T("yönetici PowerShell'de Start-Service AutoDPI", "Start-Service AutoDPI in an administrator PowerShell")
	}
	return map[string]string{
		"clear-logs":      i18n.T("günlükler ve olay kaydı temizlendi", "logs and the event journal cleared"),
		"restart":         i18n.T("servis yeniden başlatılıyor (~10 sn)", "the service is restarting (~10 s)"),
		"shutdown":        i18n.T("servis kapatılıyor; tekrar açmak için: ", "the service is shutting down; to start it again: ") + start,
		"flush-dns":       i18n.T("DNS önbelleği temizlendi", "DNS cache flushed"),
		"retest":          i18n.T("listedeki kayıtlar arka planda yeniden sınanıyor", "the listed entries are being re-tested in the background"),
		"reset-list":      i18n.T("bu ağın otomatik öğrenilen listesi silindi (elle eklenenler kaldı)", "this network's automatically learned list was deleted (manual entries stay)"),
		"reset-all-lists": i18n.T("tüm ağların otomatik öğrenilen listesi silindi (elle eklenenler kaldı)", "every network's automatically learned list was deleted (manual entries stay)"),
		"reconcile":       i18n.T("yakalama yeniden değerlendiriliyor", "the capture is being re-evaluated"),
	}[action]
}

func maint(args []string) {
	var done string
	var ok bool
	if len(args) == 1 {
		done = maintDone(args[0])
		ok = done != ""
	}
	if !ok {
		die(i18n.T("kullanım: ", "usage: ") + "autodpi maint " + strings.Join(ipc.MaintActions, " | "))
	}
	call(ipc.Request{Cmd: "maint", Action: args[0]}, nil, 20*time.Second)
	fmt.Println(done)
}

func updateCmd(args []string) {
	action := "check"
	if len(args) == 1 && (args[0] == "install" || args[0] == "skip" || args[0] == "check") {
		action = args[0]
	} else if len(args) != 0 {
		die(i18n.T("kullanım: ", "usage: ") + "autodpi update [" + strings.Join(ipc.UpdateActions, " | ") + "]")
	}
	var u daemon.UpdateStatus
	call(ipc.Request{Cmd: "update", Action: action}, &u, 45*time.Second)
	switch {
	case action == "install":
		fmt.Printf(i18n.T("%s indiriliyor ve kuruluyor; servis birazdan yeniden başlayacak\n", "downloading and installing %s; the service restarts shortly\n"), u.Latest)
	case action == "skip":
		fmt.Println(i18n.T("bu sürüm bir daha duyurulmayacak", "this version will not be announced again"))
	case u.Error != "":
		die(i18n.T("güncelleme denetlenemedi: %s", "the update check failed: %s"), u.Error)
	case u.Latest == "":
		fmt.Printf(i18n.T("autodpi %s güncel\n", "autodpi %s is up to date\n"), u.Current)
	default:
		fmt.Printf(i18n.T("yeni sürüm: %s (kurulu %s)\n  %s\n", "new version: %s (installed %s)\n  %s\n"), u.Latest, u.Current, u.URL)
		switch {
		case !u.Supported:
			fmt.Println(i18n.T("  bu kurulum kendini güncelleyemiyor; yeni sürümü elle kurun", "  this install cannot update itself; install the new version by hand"))
		case u.Auto && !u.Skipped && !u.Failed:
			fmt.Println(i18n.T("  uygun bir anda kendiliğinden kurulacak; hemen kurmak için: autodpi update install", "  it installs by itself at a quiet moment; to install it now: autodpi update install"))
		default:
			fmt.Println(i18n.T("  kurmak için: autodpi update install", "  to install it: autodpi update install"))
		}
	}
}

func stateLabel(state string) string {
	return map[string]string{
		daemon.StateActive:   i18n.T("AKTİF", "ACTIVE"),
		daemon.StateStandby:  i18n.T("BEKLEMEDE", "STANDBY"),
		daemon.StatePaused:   i18n.T("DURAKLATILDI", "PAUSED"),
		daemon.StateOffline:  i18n.T("ÇEVRİMDIŞI", "OFFLINE"),
		daemon.StateError:    i18n.T("HATA", "ERROR"),
		daemon.StateStarting: i18n.T("BAŞLIYOR", "STARTING"),
	}[state]
}

// verdictLabel is a test verdict (verdict.Kind's name) as `test` prints it.
func verdictLabel(v string) string {
	if l := map[string]string{
		"clean":       i18n.T("ENGEL YOK", "CLEAN"),
		"blocked":     i18n.T("ENGELLİ", "BLOCKED"),
		"unfixed":     i18n.T("ENGELLİ, HİÇBİR MOTOR AÇAMIYOR", "UNFIXED"),
		"unreachable": i18n.T("ULAŞILAMIYOR", "UNREACHABLE"),
		"unknown":     i18n.T("BELİRSİZ", "UNKNOWN"),
		"suspect":     i18n.T("ŞÜPHELİ", "SUSPECT"),
	}[v]; l != "" {
		return l
	}
	return strings.ToUpper(v)
}

// sourceLabel is a list entry's source as `list` prints it.
func sourceLabel(s string) string {
	switch s {
	case "auto":
		return i18n.T("otomatik", "auto")
	case "manual":
		return i18n.T("elle", "manual")
	}
	return s
}

func status() {
	var s daemon.Status
	call(ipc.Request{Cmd: "status"}, &s, 10*time.Second)
	fmt.Printf(i18n.T("autodpi %s · pid %d · çalışma süresi %s\n", "autodpi %s · pid %d · up %s\n"), s.Version, s.PID, s.Uptime)
	st := stateLabel(s.State)
	if st == "" {
		st = s.State
	}
	line := st
	if s.SingBoxPID > 0 {
		line += fmt.Sprintf(" — sing-box pid %d", s.SingBoxPID)
	}
	if s.Detail != "" {
		line += " — " + s.Detail
	}
	fmt.Printf(i18n.T("Durum:     %s\n", "State:     %s\n"), line)
	label := s.Network.Label
	if label == "" {
		label = i18n.T("(henüz belirlenmedi)", "(not identified yet)")
	}
	fmt.Printf(i18n.T("Ağ:        %s [%s]\n", "Network:   %s [%s]\n"), label, s.Network.Key)
	fmt.Printf(i18n.T("Liste:     %d kayıt\n", "List:      %d entries\n"), s.Entries)
	fmt.Printf(i18n.T("Açık:      %d alan adı (art arda direkt açıldı; hafif yoldan geçer, bellekte tutulur)\n",
		"Open:      %d names (opened directly several times in a row; take the light path, kept in memory)\n"), s.Open)
	fmt.Printf(i18n.T("Motorlar:  %s\n", "Engines:   %s\n"), strings.Join(s.Engines, " > "))
	o := s.Observer
	fmt.Printf(i18n.T("Gözlemci:  %d bağlantı: %d direkt, %d yedek motorla açıldı, %d gözlenmeden geçti\n",
		"Observer:  %d connections: %d direct, %d opened by a fallback engine, %d passed unobserved\n"),
		o.Conns, o.Direct, o.Fallback, o.Passthrough)
	if u := s.Update; u != nil && u.Latest != "" && !u.Skipped {
		fmt.Printf(i18n.T("Güncelleme: %s hazır (autodpi update)\n", "Update:    %s is out (autodpi update)\n"), u.Latest)
	}
	for _, f := range s.Findings {
		if f.Severity != audit.Info {
			fmt.Printf(i18n.T("Denetim:   [%s] %s\n", "Audit:     [%s] %s\n"), f.Code, f.Title)
		}
	}
}

func list(args []string) {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, i18n.T("bütün ağlar", "every network"))
	parseFlags(fs, args)
	var r daemon.ListResult
	call(ipc.Request{Cmd: "list", All: *all}, &r, 10*time.Second)
	if len(r.Networks) == 0 {
		fmt.Println(i18n.T("(liste yok)", "(no list)"))
		return
	}
	for _, n := range r.Networks {
		cur := ""
		if n.Current {
			cur = i18n.T(" (şu anki)", " (current)")
		}
		fmt.Printf(i18n.T("Ağ: %s [%s]%s\n", "Network: %s [%s]%s\n"), n.Label, n.Key, cur)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, i18n.T("ALAN ADI\tMOTOR\tKAYNAK\tEKLENDİ", "DOMAIN\tENGINE\tSOURCE\tADDED"))
		for _, e := range n.Entries {
			eng := e.Engine
			if eng == "" {
				eng = i18n.T("(ilk motor)", "(first engine)")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Domain, eng, sourceLabel(e.Source), e.Added.Local().Format("2006-01-02 15:04"))
		}
		tw.Flush()
		fmt.Println()
	}
}

func add(args []string) {
	if len(args) < 1 || len(args) > 2 {
		die(i18n.T("kullanım: autodpi add <alan-adı> [motor]", "usage: autodpi add <domain> [engine]"))
	}
	req := ipc.Request{Cmd: "add", Domain: args[0]}
	if len(args) == 2 {
		req.Engine = args[1]
	}
	var r struct {
		Added  bool   `json:"added"`
		Domain string `json:"domain"`
	}
	call(req, &r, 10*time.Second)
	if r.Added {
		fmt.Printf(i18n.T("eklendi: %s\n", "added: %s\n"), r.Domain)
	} else {
		fmt.Printf(i18n.T("zaten kapsanıyor: %s\n", "already covered: %s\n"), r.Domain)
	}
}

func remove(args []string) {
	if len(args) != 1 {
		die(i18n.T("kullanım: autodpi remove <alan-adı>", "usage: autodpi remove <domain>"))
	}
	simple(ipc.Request{Cmd: "remove", Domain: args[0]}, i18n.T("çıkarıldı: ", "removed: ")+args[0])
}

func test(args []string) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	all := fs.Bool("all", false, i18n.T("bütün motorları dene", "try every engine"))
	// Allow the host before or after the flag.
	var host string
	var rest []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-"):
			rest = append(rest, a)
		case host == "":
			host = a
		default:
			die(i18n.T("tek bir host verilebilir (%q fazla): autodpi test <host> [--all]", "one host only (%q is extra): autodpi test <host> [--all]"), a)
		}
	}
	parseFlags(fs, rest)
	if host == "" {
		die(i18n.T("kullanım: ", "usage: ") + "autodpi test <host> [--all]")
	}
	var r daemon.TestResult
	call(ipc.Request{Cmd: "test", Host: host, All: *all}, &r, 3*time.Minute)
	fmt.Printf("%s → %s", r.Host, verdictLabel(r.Verdict))
	if r.Engine != "" {
		fmt.Printf(i18n.T(" (motor: %s)", " (engine: %s)"), r.Engine)
	}
	fmt.Println()
	for i, d := range r.Direct {
		fmt.Printf(i18n.T("  direkt #%d:  %s\n", "  direct #%d:  %s\n"), i+1, d)
	}
	if r.Control != "" {
		fmt.Printf(i18n.T("  kontrol (nötr SNI): %s\n", "  control (neutral SNI): %s\n"), r.Control)
	}
	// In the ladder's order, as the daemon reports it; any others by name.
	names := make([]string, 0, len(r.Engines))
	seen := map[string]bool{}
	for _, n := range r.Order {
		if _, ok := r.Engines[n]; ok && !seen[n] {
			names, seen[n] = append(names, n), true
		}
	}
	var others []string
	for n := range r.Engines {
		if !seen[n] {
			others = append(others, n)
		}
	}
	sort.Strings(others)
	for _, name := range append(names, others...) {
		fmt.Printf(i18n.T("  motor %-8s %s\n", "  engine %-8s %s\n"), name+":", r.Engines[name])
	}
}

func networks() {
	var ns []store.NetworkInfo
	call(ipc.Request{Cmd: "networks"}, &ns, 10*time.Second)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("AĞ\tANAHTAR\tKAYIT\tSON GÖRÜLME", "NETWORK\tKEY\tENTRIES\tLAST SEEN"))
	for _, n := range ns {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", n.Label, n.Key, n.Entries, n.Seen.Local().Format("2006-01-02 15:04"))
	}
	tw.Flush()
}

func logCmd(args []string) {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	n := fs.Int("n", 50, i18n.T("kaç olay", "how many events"))
	parseFlags(fs, args)
	var js []daemon.JournalEntry
	call(ipc.Request{Cmd: "log", N: *n}, &js, 10*time.Second)
	for _, j := range js {
		fmt.Printf("%s  %-9s %-28s %s\n", j.Time.Local().Format("15:04:05"), j.Kind, j.Subject, j.Detail)
	}
}

func runDoctor() {
	bad := 0
	for _, c := range doctor.Run(paths.Default()) {
		mark := "✓"
		if !c.OK {
			mark = "✗"
			if c.Info {
				mark = "·"
			} else {
				bad++
			}
		}
		fmt.Printf("%s %-26s %s\n", mark, c.Name, c.Detail)
	}
	if bad > 0 {
		os.Exit(1)
	}
}

func runLab(args []string) {
	fs := flag.NewFlagSet("lab", flag.ContinueOnError)
	force := fs.Bool("force", false, i18n.T("VPN açık olsa da ölç", "measure even with a VPN on"))
	parseFlags(fs, args)
	hosts := fs.Args()
	if len(hosts) == 0 {
		hosts = []string{"discord.com", "gateway.discord.gg", "roblox.com", "www.google.com"}
	}
	bins, err := embedded.Prepare(embedded.UserDir(paths.Default().Bin))
	if err != nil {
		die("%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := lab.Run(ctx, lab.Options{Hosts: hosts, Bins: bins, Self: self(), Out: os.Stdout, Force: *force}); err != nil {
		die("%v", err)
	}
}
