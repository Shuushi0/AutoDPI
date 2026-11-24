// Package winscripts holds checks of the Windows launcher scripts that can run
// on macOS/Linux: file encoding and line endings always, and with PowerShell 7
// available (AUTODPI_PWSH or pwsh on PATH) parsing plus a few behaviours run
// against stubs of the Windows-only commands. PowerShell 7 is not Windows
// PowerShell 5.1: what passes here still needs a run on Windows.
package winscripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func pwsh(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("AUTODPI_PWSH"); p != "" {
		return p
	}
	if p, err := exec.LookPath("pwsh"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	if p := filepath.Join(home, ".local/share/powershell-7.7.0/pwsh"); fileExists(p) {
		return p
	}
	t.Skip("no PowerShell 7 here (set AUTODPI_PWSH)")
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func runPS(t *testing.T, dir, script, stdin string, env ...string) string {
	t.Helper()
	f := filepath.Join(dir, "harness.ps1")
	if err := os.WriteFile(f, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(pwsh(t), "-NoProfile", "-File", f)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func abs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Windows PowerShell 5.1 reads a BOM-less script in the ANSI code page, and
// cmd.exe mis-parses labels in LF-only batch files.
func TestEncodingAndLineEndings(t *testing.T) {
	for _, f := range []string{"autodpi-menu.ps1", "../restore-network.ps1"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		nonASCII := bytes.ContainsFunc(b, func(r rune) bool { return r > 0x7f })
		if nonASCII && !bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
			t.Errorf("%s has non-ASCII text but no UTF-8 BOM", f)
		}
	}
	for _, f := range []string{"AutoDPI.cmd", "AutoDPI Panel.cmd"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if n, crlf := bytes.Count(b, []byte("\n")), bytes.Count(b, []byte("\r\n")); n != crlf {
			t.Errorf("%s: %d of %d lines end in CRLF", f, crlf, n)
		}
		if bytes.ContainsFunc(b, func(r rune) bool { return r > 0x7f }) {
			t.Errorf("%s has non-ASCII bytes: cmd.exe reads it in the OEM code page", f)
		}
	}
}

// No parse errors and nothing PowerShell 7 added to the grammar.
func TestScriptsParseWithoutPS7Syntax(t *testing.T) {
	dir := t.TempDir()
	out := runPS(t, dir, `
foreach ($f in $args) {}
foreach ($f in @('`+abs(t, "autodpi-menu.ps1")+`','`+abs(t, "../restore-network.ps1")+`')) {
  $tok = $null; $err = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
  foreach ($e in $err) { "PARSE-ERROR $f $($e.Extent.StartLineNumber): $($e.Message)" }
  foreach ($k in $tok) { if ($k.Kind -in 'QuestionDot','QuestionLBracket','QuestionQuestion','QuestionQuestionEquals','AndAnd','OrOr') { "PS7-TOKEN $f $($k.Extent.StartLineNumber): $($k.Text)" } }
  if ($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TernaryExpressionAst] -or $args[0] -is [System.Management.Automation.Language.PipelineChainAst] }, $true).Count) { "PS7-SYNTAX $f" }
}
'done'`, "")
	if !strings.Contains(out, "done") || strings.Contains(out, "PARSE-ERROR") || strings.Contains(out, "PS7-") {
		t.Fatalf("parse check:\n%s", out)
	}
}

// The emergency brake runs from inside the menu loop's try block. A command
// that cannot start (the installed autodpi.exe blocked by an antivirus or
// Smart App Control) is then a terminating error for the whole brake script:
// nothing after it runs. Run by itself it carries on.
func TestEmergencyBrakeFromTheMenuSurvivesABlockedProgram(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sr", "System32")
	pd := filepath.Join(dir, "pd", "AutoDPI")
	for _, d := range []string{sys, pd} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(sys, "whoami.exe"), []byte("#!/bin/sh\necho 'Mandatory Label\\High Mandatory Level S-1-16-12288'\n"), 0o755)
	// Present but not runnable, the way a blocked program is.
	_ = os.WriteFile(filepath.Join(pd, "autodpi.exe"), []byte("\x7fELF-not-a-program"), 0o755)
	src, err := os.ReadFile("../restore-network.ps1")
	if err != nil {
		t.Fatal(err)
	}
	brake := strings.Replace(string(src), "[Environment]::GetFolderPath('CommonApplicationData')", "'"+filepath.Join(dir, "pd")+"'", 1)
	if err := os.WriteFile(filepath.Join(dir, "restore-network.ps1"), []byte(brake), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runPS(t, dir, `
$global:did = @()
function sc.exe { $global:did += "sc $args" }
function cmd.exe { $global:did += "cmd $args" }
function Stop-Service { $global:did += 'Stop-Service' }
function Get-Service { }
function Get-CimInstance { }
function Clear-DnsClientCache { $global:did += 'flush' }
function Find-NetRoute { }
# The menu's loop body (autodpi-menu.ps1): try { ... '0' { & restore-network.ps1 } } catch { HATA }
try { & (Join-Path $PWD 'restore-network.ps1') } catch { 'MENU-CATCH: ' + $_.Exception.Message }
'DID: ' + ($global:did -join ' | ')`, "", "SystemRoot="+filepath.Join(dir, "sr"))
	if !strings.Contains(out, "Stop-Service") || !strings.Contains(out, "flush") {
		t.Fatalf("the brake stopped before stopping anything:\n%s", out)
	}
}

// Under Constrained Language Mode (App Control / AppLocker script
// enforcement; Smart App Control in enforcement mode is an App Control
// policy) [IO.Path]::GetPathRoot fails in the unelevated pre-flight. The
// script-level trap then "continues" behind the whole if-block, i.e. into the
// administrator part of the script, without administrator rights and without
// a UAC prompt: the full menu runs in the unelevated window.
func TestUnelevatedMenuNeverRunsTheMenuItself(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sr", "System32")
	if err := os.MkdirAll(sys, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sys, "whoami.exe"), []byte("#!/bin/sh\necho 'Mandatory Label\\Medium Mandatory Level S-1-16-8192'\n"), 0o755)
	_ = os.WriteFile(filepath.Join(sys, "subst.exe"), []byte("#!/bin/sh\n"), 0o755)
	menu := filepath.Join(dir, "autodpi-menu.ps1")
	b, _ := os.ReadFile("autodpi-menu.ps1")
	_ = os.WriteFile(menu, b, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "autodpi.exe"), []byte("x"), 0o755)
	out := runPS(t, dir, `
function Start-Process { 'RELAUNCHED-ELEVATED ' + ($args -join ' ') }
function Get-Service { }
function Get-CimInstance { }
function Read-Host { $global:n++; if ($global:n -gt 3) { exit 9 }; 'Q' }
function Clear-Host { }
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
& '`+menu+`'`, "Q\n", "SystemRoot="+filepath.Join(dir, "sr"))
	if strings.Contains(out, "=== AutoDPI ===") {
		t.Fatalf("an unelevated window under Constrained Language Mode ran the menu itself (no UAC, no administrator rights):\n%s", out)
	}
}

// When the desktop cannot be written (Controlled Folder Access, a redirected
// desktop that is offline) the report must survive somewhere the message names.
func TestReportFallbackPointsAtFilesThatExist(t *testing.T) {
	dir := t.TempDir()
	desk := filepath.Join(dir, "desk")
	if err := os.Mkdir(desk, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(desk, 0o755) })
	_ = os.WriteFile(filepath.Join(dir, "fake.sh"), []byte("#!/bin/sh\necho fake $*\n"), 0o755)
	out := runPS(t, dir, `
$ast = [System.Management.Automation.Language.Parser]::ParseFile('`+abs(t, "autodpi-menu.ps1")+`', [ref]$null, [ref]$null)
foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in 'T','Save-Output','Save-Report' }, $true)) { . ([scriptblock]::Create($f.Extent.Text)) }
$script:TR = $false
$exe = Join-Path $PWD 'fake.sh'
function cmd.exe { 'ver' }
function sc.exe { 'sc' }
function netsh { 'proxy' }
$CallerDesktop = '`+desk+`'
$msg = Save-Report 6>&1 | Out-String
$msg
if ($msg -match 'files are here: (.+)') { $p = $Matches[1].Trim(); if (Test-Path -LiteralPath $p) { 'FALLBACK-EXISTS' } else { 'FALLBACK-MISSING ' + $p } }
elseif ($msg -match 'Report ready') { 'ZIPPED' }`, "")
	if strings.Contains(out, "FALLBACK-MISSING") {
		t.Fatalf("the report is gone and the message points at a folder that does not exist:\n%s", out)
	}
}

// The trial (7) ran in the foreground and held the menu until it ended: the
// panel could not be opened (3) and nothing showed what the trial was doing.
// It now runs beside the menu and opens the panel itself, once the service
// answers and while it is still running; afterwards nothing of it is left.
func trialHarness(t *testing.T, hasExited string) string {
	t.Helper()
	return trialHarnessWith(t, hasExited, "")
}

// startFails, when not empty, is what Start-Process does instead of starting
// the service (a program a security product refuses to run).
func trialHarnessWith(t *testing.T, hasExited, startFails string) string {
	t.Helper()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "fake.sh"), []byte("#!/bin/sh\necho \"$*\" >> \""+filepath.Join(dir, "calls.txt")+"\"\nexit 0\n"), 0o755)
	out := runPS(t, dir, `
$ast = [System.Management.Automation.Language.Parser]::ParseFile('`+abs(t, "autodpi-menu.ps1")+`', [ref]$null, [ref]$null)
foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in 'T','Start-Trial','Stop-Trial','Stop-Panel' }, $true)) { . ([scriptblock]::Create($f.Extent.Text)) }
$script:TR = $false
$exe = Join-Path $PWD 'fake.sh'
$script:reads = 0
$script:clock = [datetime]'2026-01-01'
$script:events = @()
function Start-Process {
    `+startFails+`
    $script:events += 'daemon: ' + (($args | ForEach-Object { $_ }) -join ' ')
    $o = New-Object psobject
    $o | Add-Member NoteProperty Id 4242
    $o | Add-Member ScriptProperty HasExited { $script:reads++; `+hasExited+` }
    $o
}
function Start-Sleep { $script:clock = $script:clock.AddSeconds(30) } # time passes without waiting
function Get-Date { $script:clock }
function Get-Process { }
function Get-CimInstance {
    [pscustomobject]@{ ProcessId = 777; CommandLine = '"C:\x y\autodpi.exe" ui --no-open --with-service' }
    [pscustomobject]@{ ProcessId = 778; CommandLine = '"C:\a ui b\autodpi.exe" daemon --for 5m' } # not a page
}
function Stop-Process { $script:events += 'kill: ' + (($args | ForEach-Object { $_ }) -join ' ') }
function Open-Panel { $script:events += "panel (daemon checked $script:reads times, trial=$($args -contains '-Trial'))"; $true }
Start-Trial 6>&1 | Out-String
'EVENTS: ' + ($script:events -join ' | ')`, "")
	calls, _ := os.ReadFile(filepath.Join(dir, "calls.txt"))
	return out + "\nCALLS: " + string(calls)
}

func TestTrialOpensThePanelWhileItRuns(t *testing.T) {
	out := trialHarness(t, "$script:reads -gt 6") // ends by itself after a few looks
	for _, want := range []string{"daemon: ", "--for 5m", "deneme.log", "panel (daemon checked", "trial=True", "Trial over", "3  Open the control panel again", "status"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q is missing:\n%s", want, out)
		}
	}
	if i, j := strings.Index(out, "daemon: "), strings.Index(out, "panel ("); i < 0 || j < i {
		t.Fatalf("the panel was not opened after the service was started:\n%s", out)
	}
	if strings.Contains(out, "kill: -Id 4242") {
		t.Fatalf("a service that ended by itself was killed:\n%s", out)
	}
	if !strings.Contains(out, "kill: -Id 777") {
		t.Fatalf("the page opened for the trial was left running:\n%s", out)
	}
}

// A service that does not end (the old program could hang on its way out):
// the trial does not wait for it without end, and does not leave it behind.
func TestTrialThatDoesNotStopIsEnded(t *testing.T) {
	out := trialHarness(t, "$false")
	for _, want := range []string{"did not stop by itself", "kill: -Id 4242", "kill: -Id 777", "Trial over"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q is missing:\n%s", want, out)
		}
	}
}

// A folder whose name has " ui " in it does not make a service a page server.
func TestTrialEndsOnlyThePage(t *testing.T) {
	out := trialHarness(t, "$script:reads -gt 6")
	if !strings.Contains(out, "kill: -Id 777") || strings.Contains(out, "kill: -Id 778") {
		t.Fatalf("the page (777) must be ended and the service in \"a ui b\" (778) must not:\n%s", out)
	}
}

// A program that cannot be run at all (blocked) is said so: no panel, no five
// minutes of waiting for a trial that never started.
func TestTrialThatCannotStartSaysSo(t *testing.T) {
	for name, fail := range map[string]string{
		"error":   `throw 'This program is blocked by group policy.'`,
		"nothing": `Write-Error 'blocked' -ErrorAction SilentlyContinue; return`,
	} {
		out := trialHarnessWith(t, "$false", fail)
		if !strings.Contains(out, "could not be started") {
			t.Fatalf("%s: no message:\n%s", name, out)
		}
		for _, not := range []string{"panel (", "The trial is running", "Trial over", "kill: "} {
			if strings.Contains(out, not) {
				t.Fatalf("%s: %q after a start that failed:\n%s", name, not, out)
			}
		}
	}
}
