package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/service"
	"github.com/Shuushi0/AutoDPI/internal/ui"
)

// runUI serves the local settings page on 127.0.0.1 and opens it in the browser.
func runUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	noOpen := fs.Bool("no-open", false, i18n.T("tarayıcıyı açma, yalnızca adresi yazdır", "do not open the browser, print the address only"))
	parseFlags(fs, args)

	p := paths.Default()
	srv := ui.New(ui.NewToken(), p.Config, func(req ipc.Request, out any, timeout time.Duration) error {
		return ipc.Call(p.Sock, req, out, timeout)
	}, ui.SaveFile)
	// The compact view's start button for an installed service that is not
	// running (after the view's own shut-down button, say). Not for a scratch
	// AUTODPI_HOME: the button would start the installed service, not that one.
	if p.System && service.Describe() != "" {
		srv.Tray = map[string]func() error{"start-service": ui.StartService}
	}
	ln, url, err := srv.Listen()
	if err != nil {
		die(i18n.T("arayüz dinlenemedi: %v", "the page cannot listen: %v"), err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	fmt.Printf(i18n.T("Arayüz: %s\nDurdurmak için Ctrl-C.\n", "Page: %s\nCtrl-C stops it.\n"), url)
	if !*noOpen {
		name, args := browserCommand(runtime.GOOS, url)
		_ = exec.Command(name, args...).Start()
	}
	if err := srv.Serve(ln); err != nil {
		die(i18n.T("arayüz: %v", "page: %v"), err)
	}
}

// browserCommand opens url in the default browser. Windows has no
// /usr/bin/open; rundll32 hands the URL to its registered handler (cmd /c
// start would split it at &), by absolute path so PATH cannot substitute it.
func browserCommand(goos, url string) (string, []string) {
	if goos == "windows" {
		exe := "rundll32.exe"
		if root := os.Getenv("SystemRoot"); root != "" {
			exe = filepath.Join(root, "System32", exe)
		}
		return exe, []string{"url.dll,FileProtocolHandler", url}
	}
	return "/usr/bin/open", []string{url}
}
