package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/audit"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/store"
)

func auditRig() (*Daemon, *bytes.Buffer) {
	var buf bytes.Buffer
	return &Daemon{log: slog.New(slog.NewTextHandler(&buf, nil)), auditKick: make(chan struct{}, 1)}, &buf
}

var nrptProblem = audit.Finding{Code: "dns-rule-loopback", Severity: audit.Problem, Title: "25 names do not resolve", Detail: "close the tool"}

// What a report is read for: the code, the title and the advice are in the log,
// once, however often the audit runs.
func TestFindingsReachTheLogOnce(t *testing.T) {
	d, log := auditRig()
	d.applyAudit([]audit.Finding{nrptProblem}, true)
	d.applyAudit([]audit.Finding{nrptProblem}, true)
	text := log.String()
	if n := strings.Count(text, "msg=audit"); n != 1 {
		t.Fatalf("%d lines:\n%s", n, text)
	}
	for _, want := range []string{"dns-rule-loopback", "severity=problem", "25 names", "close the tool"} {
		if !strings.Contains(text, want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
}

func TestACleanAuditIsLoggedSoAReportShowsItRan(t *testing.T) {
	d, log := auditRig()
	d.applyAudit(nil, false)
	d.applyAudit(nil, false)
	d.applyAudit(nil, true)
	text := log.String()
	if n := strings.Count(text, "msg=audit"); n != 2 {
		t.Fatalf("%d lines:\n%s", n, text)
	}
	if !strings.Contains(text, "compared with DoH") {
		t.Errorf("no line says the resolvers were compared:\n%s", text)
	}
}

func TestAFixedProblemIsLoggedAsClean(t *testing.T) {
	d, log := auditRig()
	d.applyAudit([]audit.Finding{nrptProblem}, true)
	log.Reset()
	d.applyAudit(nil, true)
	if !strings.Contains(log.String(), "clean") {
		t.Fatalf("%s", log.String())
	}
	if len(d.findings) != 0 {
		t.Fatalf("findings kept: %+v", d.findings)
	}
}

func TestStatusDetailShowsTheFirstProblemOnly(t *testing.T) {
	warn := audit.Finding{Code: "dns-listener", Severity: audit.Warn, Title: "a warning"}
	cases := []struct {
		detail string
		fs     []audit.Finding
		want   string
	}{
		{"", nil, ""},
		{"", []audit.Finding{warn}, ""},
		{"", []audit.Finding{warn, nrptProblem}, nrptProblem.Title},
		{"waiting", []audit.Finding{nrptProblem}, "waiting · " + nrptProblem.Title},
		{"waiting", []audit.Finding{warn}, "waiting"},
	}
	for _, c := range cases {
		if got := statusDetail(c.detail, c.fs); got != c.want {
			t.Errorf("statusDetail(%q): %q, want %q", c.detail, got, c.want)
		}
	}
}

func TestBecomingActiveRunsTheAuditAgain(t *testing.T) {
	d, _ := auditRig()
	d.setState(StateStarting, "")
	if len(d.auditKick) != 0 {
		t.Fatal("kicked before the capture was active")
	}
	d.setState(StateActive, "")
	if len(d.auditKick) != 1 {
		t.Fatal("not kicked on becoming active")
	}
	<-d.auditKick
	d.setState(StateActive, "")
	if len(d.auditKick) != 0 {
		t.Fatal("kicked while staying active")
	}
}

func TestAuditComparesOnlyUnderACapture(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{StateActive, StateStandby} {
		d, _ := auditRig()
		d.st = st
		d.sys.network = func() netid.Info { return netid.Info{Key: "asn:1"} }
		d.state = state
		var compared bool
		d.sys.audit = func(_ context.Context, _ []string, compare bool) []audit.Finding {
			compared = compare
			return nil
		}
		d.runAudit(context.Background())
		if compared != (state == StateActive) {
			t.Errorf("state %s: compared = %v", state, compared)
		}
	}
}
