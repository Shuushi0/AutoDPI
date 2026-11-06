//go:build windows

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestArea5CommandLineQuoting(t *testing.T) {
	got := commandLine(`C:\Program Data\AutoDPI\autodpi.exe`, "daemon", "--log-file", `C:\Program Data\AutoDPI\x.log`)
	want := `"C:\Program Data\AutoDPI\autodpi.exe" daemon --log-file "C:\Program Data\AutoDPI\x.log"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func run(t *testing.T, body func(context.Context) error) (chan svc.ChangeRequest, chan svc.Status, chan [2]any) {
	req, st := make(chan svc.ChangeRequest, 4), make(chan svc.Status, 16)
	res := make(chan [2]any, 1)
	h := &handler{parent: context.Background(), body: body}
	go func() {
		ssec, errno := h.Execute(nil, req, st)
		res <- [2]any{ssec, errno}
	}()
	return req, st, res
}

func TestArea5ExecuteStopCancelsBody(t *testing.T) {
	req, st, res := run(t, func(ctx context.Context) error { <-ctx.Done(); return nil })
	if s := <-st; s.State != svc.StartPending {
		t.Fatalf("first status %v", s.State)
	}
	if s := <-st; s.State != svc.Running || s.Accepts&svc.AcceptStop == 0 || s.Accepts&svc.AcceptShutdown == 0 {
		t.Fatalf("second status %+v", s)
	}
	req <- svc.ChangeRequest{Cmd: svc.Stop}
	if s := <-st; s.State != svc.StopPending || s.WaitHint == 0 {
		t.Fatalf("stop status %+v", s)
	}
	select {
	case r := <-res:
		if r[1].(uint32) != 0 {
			t.Fatalf("clean stop must exit 0, got %v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Execute did not return after Stop")
	}
}

func TestArea5ExecuteBodyFailureIsNonZero(t *testing.T) {
	_, _, res := run(t, func(context.Context) error { return errors.New("boom") })
	select {
	case r := <-res:
		if r[1].(uint32) == 0 {
			t.Fatal("daemon failure must exit non-zero so recovery actions fire")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no return")
	}
}

func TestArea5CopyExec(t *testing.T) {
	d := t.TempDir()
	src, dst := filepath.Join(d, "a.exe"), filepath.Join(d, "b.exe")
	os.WriteFile(src, []byte("one"), 0o755)
	if err := copyExec(src, dst); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(src, []byte("two"), 0o755)
	if err := copyExec(src, dst); err != nil { // replace existing
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "two" {
		t.Fatalf("dst = %q", b)
	}
	if err := copyExec(dst, dst); err != nil { // same file, differing case
		t.Fatal(err)
	}
	if _, err := os.Stat(dst + ".new"); err == nil {
		t.Fatal("temp file left behind")
	}
}

func TestArea5DescribeUnelevated(t *testing.T) {
	// Must not panic or hang whether or not the service exists.
	t.Logf("Describe() = %q", Describe())
}
