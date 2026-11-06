# Changelog

## 0.1.1 — 2026-11-06

**System audit**

- AutoDPI now checks what else on the computer decides where names resolve: DNS rules left by other tools
  (NRPT on Windows, `/etc/resolver` on macOS), other local DNS servers, the DNS of network adapters and
  hosts entries. It also compares the system resolver with encrypted DNS. A problem shows on the status line
  in every app, and `autodpi doctor`, `autodpi status` and the log name it. It changes nothing by itself.
- Windows support reports now include `dns.txt`, written without the program itself, so it is there even
  when the service cannot run.

**Fixes**

- After a network change a blocked site could stay closed for up to ten minutes. Connections cut by the
  capture restarting were taken for the server's refusal.
- Flows that no path could open are now written to the log, so a report shows why a site does not open.
- While a network waited for a login, or the service waited to retry, the log got a new line for every
  attempt. The same reason is now written once.
- The update banner no longer pushes the version line and "Check for updates" out of the Windows tray
  window, which is also a little taller.
- The result of a check for updates now shows right above its button, on the web page and in the apps.

**Documents**

- A longer legal notice and disclaimer in the READMEs.
- The project's copyright now reads Shuushi0, and the documents no longer name specific sites.

## 0.1.0 — 2026-11-03

First public release.

**Service**

- A system-wide background service for macOS (launchd daemon) and Windows (Windows service) that gets
  around SNI-based DPI blocking and DNS poisoning without a VPN account.
- All traffic goes through a sing-box TUN. Sites already known to be blocked on the current network go
  straight to an engine; any other TCP/443 connection tries the real path first, and on a reset or an
  injected reply the observer replays the same ClientHello through an engine, so the very first attempt
  opens. The site is then validated and listed.
- Engines, in a configurable order: `tlsrec` (the ClientHello split into two TLS records), `ciadpi`
  (byedpi's desync chain) and `tlsspoof` (a decoy ClientHello first; root only).
- Learning per network, keyed by the ISP's AS number, stored as registrable domains. Only a reset, an
  injected reply or a clean close right after the ClientHello counts as a block; a link that only times out is looked at again later and never
  listed on the first try. Listed sites are re-tested periodically and leave the list once they open
  directly again; sites that open directly several times in a row take a light path.
- DNS: while active, the system resolver points at 1.1.1.1, which the TUN answers over DoH with two
  racing resolvers; the original setting is saved and restored. QUIC is refused only for listed sites,
  and IPv6 is captured only when the network has it. Local and internal names (`.lan`, `.corp`,
  single-word names, `local_domains`) are answered by the network's own DNS.
- `escalate_on_silence` lets a flow that only times out try every engine (networks that drop packets
  silently).
- Fail-open: helpers die with the daemon, the capture is released when its health checks keep failing,
  and re-engaging backs off. While another VPN tunnel, or on Windows GoodbyeDPI or zapret, is running,
  the service waits in standby.
- Pause and resume, and a clean shutdown that the service manager respects until the next start or
  boot.

**Updates**

- The service looks for a newer release once a day (`update_check_hours`), checks its signature and,
  with `auto_update` (on by default), installs it once the connection is idle; a new version that does
  not come up properly is rolled back. With automatic updates off, the apps and the page announce it
  with Update, Notes and Skip.
- Settings → Updates on the page; Check for updates in the menu bar app and the tray window;
  `autodpi update` on the command line.

**Apps**

- macOS menu bar app: state-colored shield; a popover with the state, pause/resume, the network,
  counters, recent events and the learned list with search; opens the settings page; shuts the service
  down or quits; starts a stopped service under the administrator prompt.
- Windows tray app, installed with the service: the same shield in the notification area, a popup with
  the same content as the macOS popover (WebView2), a right-click menu, autostart at sign-in, and
  "hide the icon" with a way back through the Start menu.
- Settings page (`autodpi ui`): Overview, List, Settings, Maintenance and Log tabs. Add or remove sites,
  edit the engine order and the settings (saved under an administrator prompt or UAC), run maintenance
  (refresh the capture, flush DNS, re-test, restart, clear logs, reset lists) and filter the journal.
  The tray popup is its compact view.

**Command line**

- `install`, `uninstall [--purge]`, `status`, `list [--all]`, `add`, `remove`, `test [--all]`,
  `pause`, `resume`, `networks`, `log`, `maint <action>`, `update`, `ui`, `doctor`, `lab`, `version`.

**Windows**

- `AutoDPI.cmd` opens a menu (install, status, control panel, pause and resume, network lab, a
  five-minute trial, report, uninstall, emergency brake, stopping GoodbyeDPI or zapret);
  `AutoDPI Panel.cmd` opens the settings page.
- `restore-network.ps1` (and `restore-network.sh` on macOS) is the emergency brake: it stops everything
  and puts DNS back.

**Languages**

- English and Turkish everywhere: the command line, the apps, the page, the Windows menu and the
  emergency brakes. The system's language decides; the `language` setting or `AUTODPI_LANG` overrides
  it.

**Build**

- One self-contained binary per platform with sing-box 1.14.4 (a slim build from pinned source) and
  byedpi 0.17.3 embedded and checksum-verified; `scripts/release.sh` builds both archives,
  `SHA256SUMS` and its signature `SHA256SUMS.sig`.
