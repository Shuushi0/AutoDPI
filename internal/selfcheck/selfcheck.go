// Package selfcheck asks this build, on this machine, the one question the
// build machine cannot answer for it: do the helper programs it carries start
// here, and does its sing-box accept the configurations its daemon writes?
// Nothing is captured and no network is used.
package selfcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/embedded"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

// ErrBroken marks a verdict: a helper ran and showed that this copy cannot
// work here (it exits with an error, or refuses a configuration). A check that
// could not be carried out (no room to extract the helpers, no answer while
// antivirus scans them) is an error without it: that may pass.
var ErrBroken = errors.New("this copy does not work on this computer")

// Sweep removes what earlier runs left in base when they were cut short (a
// closed window, the updater's time limit): about 20 MB each.
func Sweep(base string, olderThan time.Duration) {
	ents, _ := os.ReadDir(base)
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), Prefix) {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) >= olderThan {
			_ = os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}
}

// Prefix starts the name of every work directory, for Sweep.
const Prefix = ".selftest-"

// Run extracts the helpers into dir (created, and removed again) and checks
// them, writing one line per step to out. The first failure is returned.
func Run(ctx context.Context, dir string, out io.Writer) error {
	_ = os.RemoveAll(dir)
	defer os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	bins, err := embedded.Prepare(filepath.Join(dir, "bin"))
	if err != nil {
		return fmt.Errorf("helper programs: %w", err)
	}
	rules := filepath.Join(dir, "run")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		return err
	}

	v, err := run(ctx, bins.SingBox, "version")
	if err != nil || !strings.Contains(v, "sing-box version") {
		return verdict(err, "sing-box does not start: %v", nonNil(err, v))
	}
	fmt.Fprintln(out, "ok  "+firstLine(v))

	if v, err = run(ctx, bins.Ciadpi, "--version"); err != nil || strings.TrimSpace(v) == "" {
		// Output alone is not enough: a program that cannot load prints its
		// loader's error and exits with a failure.
		return verdict(err, "ciadpi does not start: %v", nonNil(err, "no output"))
	}
	fmt.Fprintln(out, "ok  ciadpi "+firstLine(v))

	cases, err := singbox.Contract(rules)
	if err != nil {
		return err
	}
	for i, c := range cases {
		f := filepath.Join(dir, fmt.Sprintf("config-%d.json", i))
		if err := os.WriteFile(f, c.Config, 0o600); err != nil {
			return err
		}
		// Without colors: the message ends up in a status line and a log,
		// where the escape codes are noise and count towards the length it
		// is cut to.
		if msg, err := run(ctx, bins.SingBox, "--disable-color", "check", "-c", f); err != nil {
			return verdict(err, "sing-box refuses the configuration for %s: %s (%v)", c.Name, reason(msg), err)
		}
		fmt.Fprintln(out, "ok  configuration: "+c.Name)
	}
	// And the other way round: a configuration that cannot work must be
	// refused. A check that accepts everything (a helper that does not really
	// build what it is given) would have said "ok" to all of the above.
	if len(cases) > 0 {
		var m map[string]any
		if err := json.Unmarshal(cases[0].Config, &m); err != nil {
			return err
		}
		// A rule-set file that is not there: decoding the file does not
		// notice, building the box does.
		if route, ok := m["route"].(map[string]any); ok {
			if sets, ok := route["rule_set"].([]any); ok && len(sets) > 0 {
				if set, ok := sets[0].(map[string]any); ok {
					set["path"] = filepath.Join(dir, "no-such-rule-set.json")
				}
			}
		}
		bad, _ := json.Marshal(m)
		f := filepath.Join(dir, "config-refuse.json")
		if err := os.WriteFile(f, bad, 0o600); err != nil {
			return err
		}
		if _, err := run(ctx, bins.SingBox, "--disable-color", "check", "-c", f); err == nil {
			return fmt.Errorf("%w: sing-box accepts a configuration it has to refuse, so its checks mean nothing", ErrBroken)
		} else if errors.Is(err, errNoAnswer) {
			return fmt.Errorf("sing-box did not answer: %v", err)
		}
		fmt.Fprintln(out, "ok  a broken configuration is refused")
	}
	return nil
}

// errNoAnswer is a helper that did not finish in time or could not be started
// at all: nothing was learned about it.
var errNoAnswer = errors.New("no answer")

// perCommand is how long one helper gets. A first run of a new program can
// spend most of it being scanned.
var perCommand = 30 * time.Second

func run(ctx context.Context, exe string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, perCommand)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	background(cmd)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		err = fmt.Errorf("%w in %s", errNoAnswer, perCommand)
	case err != nil && !errors.As(err, &exit):
		err = fmt.Errorf("%w: %v", errNoAnswer, err) // it never ran
	case err != nil && exit.ExitCode() < 0:
		// Ended by a signal: something stopped it, it did not fail by itself.
		err = fmt.Errorf("%w: %v", errNoAnswer, err)
	case err != nil && runtime.GOOS == "windows" && strings.TrimSpace(buf.String()) == "":
		// Windows has no signals: a program ended from outside (a security
		// program that did not like the new file) leaves an ordinary exit
		// code. What tells it from a helper that failed by itself is that
		// those say why; one that ends without a word was most likely ended.
		// Called a verdict, this marked a good release as broken for good.
		err = fmt.Errorf("%w: it ended without a word (%v); a security program may have stopped it", errNoAnswer, err)
	}
	return buf.String(), err
}

// Hide keeps a command this program runs from opening a console window.
func Hide(cmd *exec.Cmd) { background(cmd) }

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// reason is the end of what sing-box said, which is where the cause is:
// "FATAL[0000] decode config at C:\...\config-3.json: inbounds[0]: unknown
// field" names the file first. Without color codes, its own level and clock,
// and cut from the front when long.
func reason(msg string) string {
	s := lastLine(ansi.ReplaceAllString(msg, ""))
	if i := strings.Index(s, "] "); i >= 0 && i < 16 && strings.Contains(s[:i], "[") {
		s = s[i+2:]
	}
	const most = 160
	for len([]rune(s)) > most {
		i := strings.Index(s, ": ")
		if i < 0 || i+2 >= len(s) {
			break
		}
		s = s[i+2:]
	}
	if r := []rune(s); len(r) > most {
		s = "…" + string(r[len(r)-most+1:])
	}
	return s
}

// verdict is the error for a failed step: ErrBroken when the helper ran and
// failed, plain when it gave no answer.
func verdict(cause error, format string, a ...any) error {
	err := fmt.Errorf(format, a...)
	if errors.Is(cause, errNoAnswer) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrBroken, err)
}

func nonNil(err error, text string) error {
	if err != nil {
		return err
	}
	return errors.New(strings.TrimSpace(text))
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(s)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}
