//go:build !windows

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/verdict"
)

// call asks d as a client would, in English unless r names a language (the
// errors are in the client's language).
func call(t *testing.T, d *Daemon, r ipc.Request) (map[string]any, error) {
	t.Helper()
	if r.Lang == "" {
		r.Lang = "en"
	}
	out, err := d.handle(context.Background(), r)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m, nil
}

func TestAPIAddRemove(t *testing.T) {
	d, f := rig(t, Options{})
	for _, tc := range []struct {
		req  ipc.Request
		want string
	}{
		{ipc.Request{Cmd: "add", Domain: "not a domain"}, "invalid domain"},
		{ipc.Request{Cmd: "add", Domain: "x.example.net", Engine: "nope"}, "unknown engine"},
		{ipc.Request{Cmd: "frobnicate"}, "unknown command"},
	} {
		if _, err := call(t, d, tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err %v, want %q", tc.req, err, tc.want)
		}
	}
	// Errors come in the client's language, the sentinel one too.
	if _, err := call(t, d, ipc.Request{Cmd: "frobnicate", Lang: "tr"}); err == nil || !strings.Contains(err.Error(), "bilinmeyen komut") {
		t.Errorf("Turkish client: %v", err)
	}
	f.set(func(f *fakeSys) { f.net = netid.Info{} })
	if _, err := call(t, d, ipc.Request{Cmd: "add", Domain: "x.example.net"}); err != errNoNetwork {
		t.Fatalf("add before the network is known: %v", err)
	}
	if _, err := d.reply(context.Background(), ipc.Request{Cmd: "add", Domain: "x.example.net", Lang: "tr"}); err == nil || err.Error() != "ağ henüz belirlenmedi" {
		t.Fatalf("add before the network is known, Turkish client: %v", err)
	}
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:15897", Label: "AS15897", Online: true} })

	r, err := call(t, d, ipc.Request{Cmd: "add", Domain: "*.Blocked.Example.NET.", Engine: "ciadpi"})
	if err != nil || r["added"] != true || r["domain"] != "blocked.example.net" {
		t.Fatalf("add: %v %v", r, err)
	}
	if e, ok := d.st.Match("asn:15897", "blocked.example.net"); !ok || e.Source != store.SourceManual || e.Engine != "ciadpi" {
		t.Fatalf("manual entry: %+v", e)
	}
	if r, _ := call(t, d, ipc.Request{Cmd: "add", Domain: "blocked.example.net", Engine: "ciadpi"}); r["added"] != false {
		t.Fatal("second identical add reported a change")
	}
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "example.net"}); err == nil {
		t.Fatal("removing a name that is not an entry must fail")
	}
	if r, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "Blocked.Example.net"}); err != nil || r["removed"] != true {
		t.Fatalf("remove: %v %v", r, err)
	}
}

func TestAPIListCurrentFirst(t *testing.T) {
	d, _ := rig(t, Options{})
	_, _ = d.st.Touch("asn:1", "other")
	_, _ = d.st.Touch("asn:15897", "AS15897")
	out, err := d.handle(context.Background(), ipc.Request{Cmd: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if l := out.(ListResult); len(l.Networks) != 1 || !l.Networks[0].Current {
		t.Fatalf("list without --all: %+v", l)
	}
	_, _ = d.st.Touch("asn:1", "other") // seen later: sorts first by recency
	out, _ = d.handle(context.Background(), ipc.Request{Cmd: "list", All: true})
	if l := out.(ListResult); len(l.Networks) != 2 || l.Networks[0].Key != "asn:15897" {
		t.Fatalf("list --all must put the current network first: %+v", l.Networks)
	}
}

func TestAPIPauseResumeKicks(t *testing.T) {
	d, _ := rig(t, Options{})
	if _, err := call(t, d, ipc.Request{Cmd: "pause"}); err != nil || !d.st.Paused() {
		t.Fatal("pause not stored")
	}
	select {
	case <-d.kick:
	default:
		t.Fatal("pause did not wake the engage loop")
	}
	_, _ = call(t, d, ipc.Request{Cmd: "resume"})
	if d.st.Paused() {
		t.Fatal("resume not stored")
	}
}

func TestAPILogLimit(t *testing.T) {
	d, _ := rig(t, Options{})
	for i := 0; i < journalMax+20; i++ {
		d.note("test", fmt.Sprint(i), "")
	}
	for _, tc := range []struct{ n, want int }{{0, 50}, {-1, 50}, {10, 10}, {journalMax, journalMax}, {1000, journalMax}} {
		out, _ := d.handle(context.Background(), ipc.Request{Cmd: "log", N: tc.n})
		j := out.([]JournalEntry)
		if len(j) != tc.want {
			t.Errorf("log -n %d returned %d entries, want %d", tc.n, len(j), tc.want)
		}
		if len(j) > 0 && j[len(j)-1].Subject != fmt.Sprint(journalMax+19) {
			t.Errorf("log -n %d does not end with the newest entry", tc.n)
		}
	}
}

func TestAPITestAndStatus(t *testing.T) {
	d, f := rig(t, Options{})
	d.obs = observer.New(observer.Options{})
	f.set(func(f *fakeSys) {
		f.checkFn = func(key, host string) verdict.Verdict {
			if key != "asn:15897" {
				return verdict.Verdict{Kind: verdict.Unknown}
			}
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok"}}
		}
	})
	if _, err := call(t, d, ipc.Request{Cmd: "test", Host: "10.0.0.1"}); err == nil {
		t.Fatal("an IP is not a host to test")
	}
	r, err := call(t, d, ipc.Request{Cmd: "test", Host: "Discord.com"})
	if err != nil || r["verdict"] != "blocked" || r["engine"] != "tlsrec" || r["host"] != "discord.com" {
		t.Fatalf("test: %v %v", r, err)
	}
	engage(t, d, f)
	s := d.status()
	if s.State != StateActive || s.SingBoxPID != 4242 || s.Entries != 0 || s.Network.Key != "asn:15897" {
		t.Fatalf("status: %+v", s)
	}
}

// `test` reports the engines in ladder order, not map order.
func TestAPITestEnginesInLadderOrder(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict {
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi", Engines: map[string]string{"ciadpi": "ok", "tlsrec": "reset", "gone": "x"}}
		}
	})
	r, err := call(t, d, ipc.Request{Cmd: "test", Host: "discord.com", All: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(r["order"]); got != "[tlsrec ciadpi]" {
		t.Fatalf("order = %s", got)
	}
}
