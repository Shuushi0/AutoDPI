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
	withService := fs.Bool("with-service", false, i18n.T("servis durunca bu da kapansın (deneme çalıştırması için)", "stop when the service stops (for a trial run)"))
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
	if *withService {
		// A trial run opens the page beside a service that lives for five
		// minutes. Left to itself the page's process stayed behind, hidden,
		// until the computer was shut down: "it keeps running after I closed
		// it". It ends once the service it was opened for is gone, however
		// that came about (time up, stopped, its window closed).
		go func() {
			defer stop()
			if !serviceGone(ctx, func() error {
				return ipc.Call(p.Sock, ipc.Request{Cmd: "status"}, nil, 5*time.Second)
			}, 5*time.Second) {
				return
			}
			fmt.Println(i18n.T("Servis durdu; arayüz de kapanıyor.", "The service has stopped; the page stops too."))
		}()
	}

	fmt.Printf(i18n.T("Arayüz: %s\nDurdurmak için Ctrl-C.\n", "Page: %s\nCtrl-C stops it.\n"), url)
	if !*noOpen {
		name, args := browserCommand(runtime.GOOS, url)
		_ = exec.Command(name, args...).Start()
	}
	if err := srv.Serve(ln); err != nil {
		die(i18n.T("arayüz: %v", "page: %v"), err)
	}
}

// serviceGone waits until the service is gone and reports true; false when
// ctx ended first. Gone: status says "not running" three times in a row,
// after it had answered at least once, or it never answers for a minute. A
// service that is merely busy, or one this user may not reach, is there.
func serviceGone(ctx context.Context, status func() error, every time.Duration) bool {
	seen, down := false, 0
	started := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		switch err := status(); {
		case err == nil || ipc.Kind(err) != ipc.KindDown:
			seen, down = true, 0
		case seen:
			if down++; down >= 3 {
				return true
			}
		case time.Since(started) > 12*every:
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
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
