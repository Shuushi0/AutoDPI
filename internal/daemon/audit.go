package daemon

import (
	"context"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/audit"
)

const (
	auditEvery = 15 * time.Minute
	// auditSettle lets a fresh capture and the flushed DNS cache settle first.
	auditSettle = 5 * time.Second
	auditLimit  = 45 * time.Second
)

// auditLoop keeps the findings current: at start, once a capture is active,
// after a network change, and now and then for a tool installed meanwhile.
func (d *Daemon) auditLoop(ctx context.Context) {
	d.kickAudit()
	t := time.NewTicker(auditEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.auditKick:
			select {
			case <-time.After(auditSettle):
			case <-ctx.Done():
				return
			}
		}
		d.runAudit(ctx)
	}
}

func (d *Daemon) kickAudit() {
	select {
	case d.auditKick <- struct{}{}:
	default:
	}
}

func (d *Daemon) runAudit(ctx context.Context) {
	if d.sys.audit == nil {
		return
	}
	var watched []string
	for _, e := range d.st.List(d.sys.network().Key) {
		watched = append(watched, e.Domain)
	}
	d.mu.Lock()
	active := d.state == StateActive
	d.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, auditLimit)
	defer cancel()
	// The resolvers are compared only under a capture: that is the situation
	// users are in, and without one a captive network fails both paths anyway.
	fs := d.sys.audit(cctx, watched, active)
	if ctx.Err() == nil {
		d.applyAudit(fs, active)
	}
}

// applyAudit stores the findings for status and writes them to the log whenever
// they change. "clean" is written too: a report must show that the audit ran,
// or an empty log says nothing.
func (d *Daemon) applyAudit(fs []audit.Finding, compared bool) {
	clean := "clean, resolvers not compared"
	if compared {
		clean = "clean, system resolver compared with DoH"
	}
	var sig strings.Builder
	for _, f := range fs {
		sig.WriteString(f.Code + "|" + f.Title + "\n")
	}
	if sig.Len() == 0 {
		sig.WriteString(clean)
	}
	d.mu.Lock()
	changed := d.auditSig != sig.String()
	d.findings, d.auditSig = fs, sig.String()
	d.mu.Unlock()
	if !changed {
		return
	}
	if len(fs) == 0 {
		d.logOnly("audit", "", clean)
	}
	for _, f := range fs {
		d.log.Info("audit", "subject", f.Code, "severity", string(f.Severity), "title", f.Title, "detail", f.Detail)
	}
}

// statusDetail adds the audit's first problem to the state's detail. Every app
// shows that line, and with such a problem "active" alone would mislead: sites
// fail while the service reports nothing wrong.
func statusDetail(detail string, fs []audit.Finding) string {
	h := audit.Headline(fs)
	switch {
	case h == "":
		return detail
	case detail == "":
		return h
	}
	return detail + " · " + h
}
