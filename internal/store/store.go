// Package store keeps the learned block lists, one per network, on disk.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/domain"
)

// version 2 dropped the seed list, the per-entry "verified" flag and the
// persistent clean list (see Migration).
const version = 2

// Entry sources.
const (
	SourceAuto   = "auto"
	SourceManual = "manual"
)

type Entry struct {
	Domain  string    `json:"domain"`
	Host    string    `json:"host,omitempty"`   // the host seen blocked; re-tests probe it
	Engine  string    `json:"engine,omitempty"` // empty = first engine of the ladder
	Source  string    `json:"source"`
	Added   time.Time `json:"added"`
	Checked time.Time `json:"checked,omitzero"`
	// OK counts the consecutive re-tests where the real path worked without
	// help. (The JSON name is the one version 1 used, so old files still read.)
	OK int `json:"clean,omitempty"`
}

type Network struct {
	Label   string            `json:"label,omitempty"`
	Created time.Time         `json:"created"`
	Seen    time.Time         `json:"seen"`
	Entries map[string]*Entry `json:"entries"`
}

type data struct {
	Version  int                 `json:"version"`
	Paused   bool                `json:"paused,omitempty"`
	Networks map[string]*Network `json:"networks"`
}

// Migration describes what Open did to an older state file.
type Migration struct {
	From         int    // version found on disk; 0 when nothing was migrated
	DroppedClean int    // clean-list hosts discarded (they are learned again in memory)
	SeedsKept    int    // seed entries kept, now ordinary automatic entries
	Backup       string // copy of the old file
}

type Store struct {
	mu     sync.RWMutex
	path   string
	d      data
	notify chan struct{}
	mig    Migration
}

// Migration reports what Open converted, if anything.
func (s *Store) Migration() Migration { return s.mig }

// Open loads path, starting empty when it does not exist. A file that fails to
// parse is moved aside rather than blocking start-up. A version 1 file is
// copied to path+".v1" and rewritten as version 2.
func Open(path string) (*Store, error) {
	s := &Store{path: path, d: data{Version: version, Networks: map[string]*Network{}}, notify: make(chan struct{}, 1)}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var d data
	if err := json.Unmarshal(b, &d); err != nil {
		_ = os.Rename(path, fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix()))
		return s, nil
	}
	if d.Networks == nil {
		d.Networks = map[string]*Network{}
	}
	for k, n := range d.Networks {
		if n == nil { // only a hand-edited file has these; they would crash every reader
			delete(d.Networks, k)
			continue
		}
		if n.Entries == nil {
			n.Entries = map[string]*Entry{}
		}
		for dom, e := range n.Entries {
			if e == nil {
				delete(n.Entries, dom)
			}
		}
	}
	old := d.Version
	if old >= version {
		s.d = d
		return s, nil
	}

	// Version 1: seeds become ordinary automatic entries (a re-test drops them
	// once the real path works twice in a row), the verified flag and the clean
	// list are gone. The old file is kept as it was.
	var legacy struct {
		Networks map[string]*struct {
			Clean map[string]json.RawMessage `json:"clean"`
		} `json:"networks"`
	}
	_ = json.Unmarshal(b, &legacy)
	for _, n := range legacy.Networks {
		if n != nil {
			s.mig.DroppedClean += len(n.Clean)
		}
	}
	for _, n := range d.Networks {
		for _, e := range n.Entries {
			if e.Source == "seed" {
				e.Source = SourceAuto
				s.mig.SeedsKept++
			}
		}
	}
	s.mig.From, s.mig.Backup = max(old, 1), path+".v1"
	if err := writeFile(s.mig.Backup, b); err != nil {
		return nil, fmt.Errorf("back up the old state file: %w", err)
	}
	d.Version = version
	s.d = d
	s.mu.Lock()
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Changed delivers a coalesced signal after every mutation.
func (s *Store) Changed() <-chan struct{} { return s.notify }

func (s *Store) bump() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// snapshotLocked copies the data, so a change whose save fails can be undone.
func (s *Store) snapshotLocked() data {
	c := data{Version: s.d.Version, Paused: s.d.Paused, Networks: make(map[string]*Network, len(s.d.Networks))}
	for k, n := range s.d.Networks {
		nn := *n
		nn.Entries = make(map[string]*Entry, len(n.Entries))
		for h, e := range n.Entries {
			ee := *e
			nn.Entries[h] = &ee
		}
		c.Networks[k] = &nn
	}
	return c
}

// commitLocked saves a change made since snap. When the save fails the data
// goes back to snap, so neither memory nor the rule-sets run ahead of the file
// and the caller's error means nothing changed. listChanged signals the
// rule-set writer, after the save only.
func (s *Store) commitLocked(snap data, listChanged bool) error {
	if err := s.saveLocked(); err != nil {
		s.d = snap
		return err
	}
	if listChanged {
		s.bump()
	}
	return nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(s.path, b)
}

// writeFile replaces path atomically with data (mode 0600).
func writeFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *Store) Paused() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.d.Paused
}

func (s *Store) SetPaused(p bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snapshotLocked()
	s.d.Paused = p
	return s.commitLocked(snap, false)
}

// Touch makes sure the network exists and records that it was seen just now.
// It reports whether the network was created.
func (s *Store) Touch(key, label string) (created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snapshotLocked()
	n := s.d.Networks[key]
	if n == nil {
		n = &Network{Created: time.Now(), Entries: map[string]*Entry{}}
		s.d.Networks[key] = n
		created = true
	}
	if label != "" {
		n.Label = label
	}
	n.Seen = time.Now()
	if err := s.commitLocked(snap, false); err != nil {
		return false, err
	}
	return created, nil
}

// Add lists e.Domain (reduced to its registrable domain unless Source is
// manual) on the network. It reports whether the list changed.
//
//   - An automatic entry is a no-op when any entry already covers the domain.
//     It replaces the narrower automatic entries it covers, never manual ones.
//   - A manual entry is stored even under an automatic parent (the parent may
//     be removed by a re-test, the user's entry stays). It upgrades an existing
//     entry for the same domain in place, replaces the automatic entries below
//     it and the manual ones that pin the same engine, and is a no-op under a
//     broader manual entry.
func (s *Store) Add(key string, e Entry) (bool, error) {
	host, ok := domain.Normalize(e.Domain)
	if !ok {
		return false, fmt.Errorf("invalid domain %q", e.Domain)
	}
	if e.Source != SourceManual {
		e.Source = SourceAuto
		if host, ok = domain.Registrable(host); !ok {
			return false, fmt.Errorf("invalid domain %q", e.Domain)
		}
	}
	if h, ok := domain.Normalize(e.Host); ok && domain.Covers(host, h) {
		e.Host = h
	} else {
		e.Host = ""
	}
	e.Domain = host
	if e.Added.IsZero() {
		e.Added = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.d.Networks[key]
	if n == nil {
		return false, fmt.Errorf("unknown network %q", key)
	}
	snap := s.snapshotLocked()
	if !addLocked(n, e) {
		return false, nil
	}
	if err := s.commitLocked(snap, true); err != nil {
		return false, err
	}
	return true, nil
}

// addLocked applies Add's rules to a normalised entry.
func addLocked(n *Network, e Entry) bool {
	host := e.Domain
	if e.Source != SourceManual {
		if coveringLocked(n, host) != nil {
			return false
		}
		for d, cur := range n.Entries {
			if domain.Covers(host, d) && cur.Source != SourceManual {
				delete(n.Entries, d)
			}
		}
		cp := e
		n.Entries[host] = &cp
		return true
	}
	if cur := n.Entries[host]; cur != nil {
		if cur.Source == SourceManual && cur.Engine == e.Engine {
			return false
		}
		cur.Source, cur.Engine, cur.OK = SourceManual, e.Engine, 0
		return true
	}
	if cur := coveringLocked(n, host); cur != nil && cur.Source == SourceManual {
		return false // the user's own broader entry already does it
	}
	for d, cur := range n.Entries {
		if domain.Covers(host, d) && (cur.Source != SourceManual || cur.Engine == e.Engine) {
			delete(n.Entries, d)
		}
	}
	cp := e
	n.Entries[host] = &cp
	return true
}

// coveringLocked returns the entry that decides host: a manual one if any
// covers it (the user's choice of engine wins), otherwise the broadest.
func coveringLocked(n *Network, host string) *Entry {
	var best *Entry
	for d, e := range n.Entries {
		if !domain.Covers(d, host) {
			continue
		}
		switch {
		case best == nil:
			best = e
		case (e.Source == SourceManual) != (best.Source == SourceManual):
			if e.Source == SourceManual {
				best = e
			}
		case len(d) < len(best.Domain):
			best = e
		}
	}
	return best
}

// Remove deletes an exact entry.
func (s *Store) Remove(key, host string) (bool, error) {
	host, _ = domain.Normalize(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.d.Networks[key]
	if n == nil || n.Entries[host] == nil {
		return false, nil
	}
	snap := s.snapshotLocked()
	delete(n.Entries, host)
	if err := s.commitLocked(snap, true); err != nil {
		return false, err
	}
	return true, nil
}

// ClearAuto deletes the automatically learned entries of network key (every
// network when all is set) and reports how many went. Manual entries are the
// user's own and stay.
func (s *Store) ClearAuto(key string, all bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snapshotLocked()
	n := 0
	for k, nw := range s.d.Networks {
		if !all && k != key {
			continue
		}
		for h, e := range nw.Entries {
			if e.Source != SourceManual {
				delete(nw.Entries, h)
				n++
			}
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := s.commitLocked(snap, true); err != nil {
		return 0, err
	}
	return n, nil
}

// Match returns a copy of the entry covering host on the network, if any. The
// host is normalised first (case, trailing dot), so any spelling of a name
// matches.
func (s *Store) Match(key, host string) (Entry, bool) {
	if h, ok := domain.Normalize(host); ok {
		host = h
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.d.Networks[key]
	if n == nil {
		return Entry{}, false
	}
	if e := coveringLocked(n, host); e != nil {
		return *e, true
	}
	return Entry{}, false
}

// Get returns a copy of the entry for exactly this domain.
func (s *Store) Get(key, host string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n := s.d.Networks[key]; n != nil && n.Entries[host] != nil {
		return *n.Entries[host], true
	}
	return Entry{}, false
}

// Edit runs fn on the entry for exactly this domain, under the store's lock, so
// what fn decides is based on the entry as it is now and nothing can change it
// meanwhile. fn may modify the entry; returning true deletes it instead. The
// result is persisted. found is false (and fn not called) when there is no such
// entry.
func (s *Store) Edit(key, host string, fn func(e *Entry) (remove bool)) (found, removed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.d.Networks[key]
	if n == nil || n.Entries[host] == nil {
		return false, false, nil
	}
	snap := s.snapshotLocked()
	e := n.Entries[host]
	engine := e.Engine
	if fn(e) {
		delete(n.Entries, host)
		if err := s.commitLocked(snap, true); err != nil {
			return true, false, err
		}
		return true, true, nil
	}
	// A new engine puts it in another rule-set.
	return true, false, s.commitLocked(snap, e.Engine != engine)
}

// Update applies fn to the entry for an exact domain and persists the result.
func (s *Store) Update(key, host string, fn func(*Entry)) error {
	_, _, err := s.Edit(key, host, func(e *Entry) bool { fn(e); return false })
	return err
}

// List returns the network's entries sorted by domain.
func (s *Store) List(key string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.d.Networks[key]
	if n == nil {
		return nil
	}
	out := make([]Entry, 0, len(n.Entries))
	for _, e := range n.Entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// ByEngine groups the network's domains by engine for rule-set generation;
// engine names not present in known fall back to def.
func (s *Store) ByEngine(key string, known []string, def string) map[string][]string {
	isKnown := map[string]bool{}
	for _, k := range known {
		isKnown[k] = true
	}
	out := map[string][]string{}
	for _, e := range s.List(key) {
		eng := e.Engine
		if !isKnown[eng] {
			eng = def
		}
		out[eng] = append(out[eng], e.Domain)
	}
	return out
}

type NetworkInfo struct {
	Key     string    `json:"key"`
	Label   string    `json:"label"`
	Seen    time.Time `json:"seen"`
	Entries int       `json:"entries"`
}

func (s *Store) Networks() []NetworkInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NetworkInfo, 0, len(s.d.Networks))
	for k, n := range s.d.Networks {
		out = append(out, NetworkInfo{Key: k, Label: n.Label, Seen: n.Seen, Entries: len(n.Entries)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seen.After(out[j].Seen) })
	return out
}

// PruneEmpty deletes provisional networks (gateway keys, "gw:...") that hold no
// entries: an attachment whose AS number was never learned (a captive portal, a
// network without internet) otherwise stays in the state file and in
// `networks` for good. Stable (asn:) networks are kept even when empty. It
// reports how many were removed.
func (s *Store) PruneEmpty() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snapshotLocked()
	n := 0
	for k, nw := range s.d.Networks {
		if strings.HasPrefix(k, "gw:") && len(nw.Entries) == 0 {
			delete(s.d.Networks, k)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := s.commitLocked(snap, false); err != nil {
		return 0, err
	}
	return n, nil
}

// Rekey folds network from into to (creating it if needed), used when a
// provisional gateway-based key is replaced by a stable ISP-level one. Entries
// merge by Add's rules, the user's own first, so a manual entry is never
// downgraded by an automatic one.
func (s *Store) Rekey(from, to string) error {
	if from == to {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.d.Networks[from]
	if src == nil {
		return nil
	}
	snap := s.snapshotLocked()
	dst := s.d.Networks[to]
	if dst == nil {
		s.d.Networks[to] = src
	} else {
		for _, manual := range []bool{true, false} {
			for _, e := range src.Entries {
				if (e.Source == SourceManual) == manual {
					addLocked(dst, *e)
				}
			}
		}
		if src.Seen.After(dst.Seen) {
			dst.Seen = src.Seen
		}
		if dst.Label == "" {
			dst.Label = src.Label
		}
	}
	delete(s.d.Networks, from)
	return s.commitLocked(snap, true)
}
