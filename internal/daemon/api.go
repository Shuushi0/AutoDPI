package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/audit"
	"github.com/Shuushi0/AutoDPI/internal/domain"
	"github.com/Shuushi0/AutoDPI/internal/embedded"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/store"
)

type JournalEntry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail,omitempty"`
}

const journalMax = 300

// The journal (what `autodpi log` and the apps show) holds only repaired
// connections, changes of the blocked list and the service's own events
// (state, network, capture, DNS, pause and resume, maintenance). Everything
// else is logOnly; connections that simply work are not recorded anywhere.

// logOnly writes to the daemon log but not to the journal.
func (d *Daemon) logOnly(kind, subject, detail string) {
	d.log.Info(kind, "subject", subject, "detail", detail)
}

func (d *Daemon) note(kind, subject, detail string) {
	d.mu.Lock()
	d.journal = append(d.journal, JournalEntry{Time: time.Now(), Kind: kind, Subject: subject, Detail: detail})
	if len(d.journal) > journalMax {
		d.journal = d.journal[len(d.journal)-journalMax:]
	}
	d.mu.Unlock()
	d.log.Info(kind, "subject", subject, "detail", detail)
}

type Status struct {
	Version    string          `json:"version"`
	PID        int             `json:"pid"`
	State      string          `json:"state"`
	Detail     string          `json:"detail,omitempty"`
	Uptime     string          `json:"uptime"`
	SingBoxPID int             `json:"singbox_pid,omitempty"`
	Network    netid.Info      `json:"network"`
	Entries    int             `json:"entries"`
	Open       int             `json:"open"` // names currently open (direct-only) on this network; memory only
	Engines    []string        `json:"engines"`
	Observer   observer.Stats  `json:"observer"`
	Embedded   bool            `json:"embedded"`
	Update     *UpdateStatus   `json:"update,omitempty"`
	Findings   []audit.Finding `json:"findings,omitempty"` // the system audit's latest result
}

type NetworkList struct {
	Key     string        `json:"key"`
	Label   string        `json:"label"`
	Current bool          `json:"current"`
	Entries []store.Entry `json:"entries"`
}

type ListResult struct {
	Networks []NetworkList `json:"networks"`
}

type TestResult struct {
	Host    string            `json:"host"`
	Verdict string            `json:"verdict"`
	Engine  string            `json:"engine,omitempty"`
	Direct  []string          `json:"direct"`
	Control string            `json:"control,omitempty"`
	Engines map[string]string `json:"engines,omitempty"`
	Order   []string          `json:"order,omitempty"` // the engines of Engines in ladder order
}

func (d *Daemon) status() Status {
	d.mu.Lock()
	state, detail, pid, findings := d.state, d.detail, d.sbPID, d.findings
	d.mu.Unlock()
	net := d.sys.network()
	var upd *UpdateStatus
	if d.upd != nil {
		u := d.upd.status()
		upd = &u
	}
	return Status{
		Version: Version, PID: os.Getpid(), State: state, Detail: statusDetail(detail, findings),
		Uptime:     time.Since(d.started).Round(time.Second).String(),
		SingBoxPID: pid, Network: net, Entries: len(d.st.List(net.Key)), Open: d.openCount(),
		Engines: d.engineNames(), Observer: d.obs.Stats(), Embedded: embedded.Embedded(),
		Update: upd, Findings: findings,
	}
}

// reply answers a control-socket request: handle, with its sentinel errors in
// the client's language.
func (d *Daemon) reply(ctx context.Context, r ipc.Request) (any, error) {
	out, err := d.handle(ctx, r)
	if errors.Is(err, errNoNetwork) {
		err = errors.New(r.T("ağ henüz belirlenmedi", "no network identified yet"))
	}
	return out, err
}

func (d *Daemon) handle(ctx context.Context, r ipc.Request) (any, error) {
	switch r.Cmd {
	case "status":
		return d.status(), nil

	case "list":
		cur := d.sys.network().Key
		var out ListResult
		for _, n := range d.st.Networks() {
			if !r.All && n.Key != cur {
				continue
			}
			out.Networks = append(out.Networks, NetworkList{Key: n.Key, Label: n.Label, Current: n.Key == cur, Entries: d.st.List(n.Key)})
		}
		sort.SliceStable(out.Networks, func(i, j int) bool { return out.Networks[i].Current && !out.Networks[j].Current })
		return out, nil

	case "open-reset":
		return d.openReset()

	case "networks":
		return d.st.Networks(), nil

	case "add":
		host, ok := domain.Normalize(r.Domain)
		if !ok {
			return nil, fmt.Errorf(r.T("geçersiz alan adı %q", "invalid domain %q"), r.Domain)
		}
		if r.Engine != "" && !d.hasEngine(r.Engine) {
			return nil, fmt.Errorf(r.T("bilinmeyen motor %q (servisin motorları: %v)", "unknown engine %q (have %v)"), r.Engine, d.engineNames())
		}
		net := d.sys.network()
		if net.Key == "" {
			return nil, errNoNetwork
		}
		if _, err := d.st.Touch(net.Key, net.Label); err != nil {
			return nil, err
		}
		added, err := d.st.Add(net.Key, store.Entry{Domain: host, Engine: r.Engine, Source: store.SourceManual})
		if err != nil {
			return nil, err
		}
		if added {
			d.note("listed", host, "manual")
		}
		return map[string]any{"added": added, "domain": host, "network": net.Key}, nil

	case "remove":
		net := d.sys.network()
		removed, err := d.st.Remove(net.Key, r.Domain)
		if err != nil {
			return nil, err
		}
		if !removed {
			return nil, fmt.Errorf(r.T("%q bu ağın listesinde bir kayıt değil (bir sonek kaydı tam adıyla çıkarılır)", "%q is not an entry of this network (suffix entries must be removed by their exact name)"), r.Domain)
		}
		d.note("removed", r.Domain, "manual")
		return map[string]any{"removed": true}, nil

	case "test":
		host, ok := domain.Normalize(r.Host)
		if !ok {
			return nil, fmt.Errorf(r.T("geçersiz host %q", "invalid host %q"), r.Host)
		}
		v := d.sys.check(ctx, d.sys.network().Key, host, nil, r.All)
		res := TestResult{Host: host, Verdict: v.Kind.String(), Engine: v.Engine, Engines: v.Engines}
		for _, p := range v.Direct {
			res.Direct = append(res.Direct, p.String())
		}
		if v.Control.Took > 0 {
			res.Control = v.Control.String()
		}
		for _, name := range d.engineNames() {
			if _, ok := v.Engines[name]; ok {
				res.Order = append(res.Order, name)
			}
		}
		return res, nil

	case "pause", "resume":
		if err := d.st.SetPaused(r.Cmd == "pause"); err != nil {
			return nil, err
		}
		d.note(r.Cmd, "", "")
		d.kickReconcile()
		return map[string]any{"paused": r.Cmd == "pause"}, nil

	case "maint":
		return d.maint(r)

	case "update":
		if d.upd == nil {
			return nil, errors.New(r.T("servis henüz başlıyor", "the service is still starting"))
		}
		return d.upd.request(ctx, r)

	case "log":
		n := r.N
		if n <= 0 {
			n = 50
		}
		n = min(n, journalMax) // asking for more than is kept gets all of it
		d.mu.Lock()
		defer d.mu.Unlock()
		j := d.journal
		if len(j) > n {
			j = j[len(j)-n:]
		}
		return append([]JournalEntry(nil), j...), nil
	}
	return nil, fmt.Errorf(r.T("bilinmeyen komut %q", "unknown command %q"), r.Cmd)
}

func (d *Daemon) hasEngine(name string) bool {
	for _, e := range d.engines {
		if e.Name == name {
			return true
		}
	}
	return false
}
