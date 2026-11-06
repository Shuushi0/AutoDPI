//go:build !windows

package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// fakeReleases serves a release list with one release, v, for this platform.
func fakeReleases(t *testing.T, v string) *httptest.Server {
	p := update.Platform()
	if p == "" {
		t.Skip("no releases are published for this platform")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asset := func(n string) map[string]any {
			return map[string]any{"name": n, "browser_download_url": "http://x/" + n}
		}
		json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": "v" + v, "html_url": "https://github.com/x/releases/v" + v, "body": "notes",
			"assets": []any{asset(p + v + ".zip"), asset("SHA256SUMS"), asset("SHA256SUMS.sig")},
		}})
	}))
	t.Cleanup(srv.Close)
	old := update.API
	update.API = srv.URL
	t.Cleanup(func() { update.API = old })
	return srv
}

func TestUpdateCheckAndSkip(t *testing.T) {
	d, _ := rig(t, Options{})
	srv := fakeReleases(t, "99.0.0")
	d.upd = newUpdater(d)
	d.upd.http = srv.Client()

	m, err := call(t, d, ipc.Request{Cmd: "update", Action: "check"})
	if err != nil {
		t.Fatal(err)
	}
	if m["latest"] != "99.0.0" || m["url"] != "https://github.com/x/releases/v99.0.0" || m["auto"] != true {
		t.Fatalf("check: %v", m)
	}
	// Run by hand, not by a service manager: it can only announce.
	if m["supported"] != false {
		t.Fatalf("an unsupervised daemon says it can update itself: %v", m)
	}
	if _, err := call(t, d, ipc.Request{Cmd: "update", Action: "install"}); err == nil || !strings.Contains(err.Error(), "cannot update itself") {
		t.Fatalf("install without a service manager: %v", err)
	}
	if st := d.upd.status(); st.Latest != "99.0.0" || st.Notes != "notes" {
		t.Fatalf("status does not carry the update: %+v", st)
	}

	if m, _ = call(t, d, ipc.Request{Cmd: "update", Action: "skip"}); m["skipped"] != true {
		t.Fatalf("skip: %v", m)
	}
	// The choice outlives a restart.
	if u := newUpdater(d); !u.status().Skipped {
		t.Fatal("the skipped version was forgotten")
	}
	if _, err := call(t, d, ipc.Request{Cmd: "update", Action: "nope"}); err == nil {
		t.Fatal("an unknown action went through")
	}
}

func TestUpdateSettingsAreReadAfresh(t *testing.T) {
	d, _ := rig(t, Options{})
	d.p.Config = filepath.Join(d.p.Support, "config.json")
	u := newUpdater(d)
	if auto, hours := u.settings(); !auto || hours != 24 {
		t.Fatalf("defaults: auto %v, hours %d", auto, hours)
	}
	os.WriteFile(d.p.Config, []byte(`{"auto_update": false, "update_check_hours": 0}`), 0o644)
	if auto, hours := u.settings(); auto || hours != 0 {
		t.Fatalf("after the page saved: auto %v, hours %d", auto, hours)
	}
}

func TestUpdateHidesAnOlderLatest(t *testing.T) {
	d, _ := rig(t, Options{})
	u := newUpdater(d)
	u.st.Latest = &update.Release{Version: Version}
	if s := u.status(); s.Latest != "" {
		t.Fatalf("the running version shows as an update: %+v", s)
	}
}
