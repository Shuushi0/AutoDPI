# AutoDPI

A small background service for macOS and Windows that gets around **SNI-based DPI blocking and DNS
poisoning**, system-wide, without a VPN account. It notices when a connection is blocked, repairs that
very connection, remembers the site for the network you are on, and sends later connections the working
way. Browsers, any app: it works at the network layer.

Türkçe: [README.tr.md](README.tr.md)

## Install

Download the archive for your system from the [Releases page](https://github.com/Shuushi0/AutoDPI/releases)
(or build it, see below).

**macOS (Apple Silicon, macOS 13+)**

```bash
unzip autodpi-macos-arm64-*.zip && cd autodpi-macos-arm64-*
xattr -dr com.apple.quarantine .        # the binaries are not notarized
sudo ./autodpi install                  # root launchd daemon, starts at boot
autodpi status
cp -R AutoDPI.app /Applications/ && open /Applications/AutoDPI.app   # optional menu bar app
```

Remove it with `sudo autodpi uninstall [--purge]` (`--purge` also deletes the learned lists).

**Windows 10 (1803 or later) or 11, 64-bit**: extract the whole zip to a folder and double-click
`AutoDPI.cmd`. It asks for administrator rights and opens a menu: install, status and list, control
panel, pause and resume, a network lab, a five-minute trial without installing, a report for bug
reports, uninstall and the emergency brake. In an administrator terminal `.\autodpi.exe install` and `.\autodpi.exe uninstall
[--purge]` do the same as the menu's install and uninstall. A step-by-step walk through the menu is in
[docs/windows-test.md](docs/windows-test.md) (Turkish). The tray window uses the Edge WebView2 runtime
(part of Windows 11 and current Windows 10); without it the settings page opens in the browser instead.

Turn another VPN (for example Cloudflare WARP) off first: while a tunnel owns the traffic the service
waits in standby by itself and engages once it is gone. The same goes for GoodbyeDPI and zapret on
Windows: they rewrite the same packets, so the service waits until they are closed (key G of the menu
stops them).

## The apps

- **macOS menu bar app** (`AutoDPI.app`): a shield in the menu bar, colored by the state. A click opens
  a popover with the state and a pause button, the current network, counters (list, direct, fallback
  engine), the recent events and the learned list with a search field. "Open Settings" opens the
  settings page; the power button shuts the service down (and quits) or quits only the app. When the
  service is stopped the popover offers to start it (administrator password).
- **Windows tray app** (`autodpi-tray.exe`, set up by `install`): the same shield in the notification
  area. A click opens a small window with the same content as the macOS popover; a right-click offers
  pause and resume, the settings page, starting the service, hiding the icon and quitting. It starts at
  every sign-in; "hide the icon" keeps the service running without it until AutoDPI is opened from the
  Start menu.
- **Settings page** (`autodpi ui`, or `AutoDPI Panel.cmd` on Windows): a local page in the browser,
  reachable from this computer only. Its tabs:
  - *Overview*: the state and what it means for traffic, a traffic bar (direct, via engine, passed
    through), the network, the engine order, the service, the newest list entries and events.
  - *List*: the learned sites of this network or of all networks, with search, source filter and
    sorting; add a site by hand or remove one.
  - *Settings*: engine order, decoy SNI, language, re-test interval, hedge delay, DNS takeover and QUIC
    blocking. Saving asks for administrator permission; restart the service to apply it.
  - *Maintenance*: refresh the capture, flush DNS, re-test the list, reset open names, restart the
    service, clear the logs, reset this network's or every network's learned list.
  - *Log*: the event journal, filtered by kind or searched.

## Language

Everything you read comes in English and Turkish: the command line, the apps, the page and the Windows
menu. The system's language decides (Turkish when it is Turkish, English otherwise). To choose, set
**Language** on the settings page (`"language": "tr"` or `"en"` in `config.json`), or set
`AUTODPI_LANG=tr|en` for one command.

## Use

```
autodpi status                 state, network, counters
autodpi list [--all]           blocked sites learned for this network (--all: every network)
autodpi add <domain> [engine]  add by hand (kept for good)    autodpi remove <domain>
autodpi test <host> [--all]    check a host now; --all tries every engine
autodpi pause | resume         switch the bypass off and on
autodpi networks               known networks
autodpi log [-n 50]            repaired and listed sites, state changes
autodpi maint <action>         clear-logs | restart | shutdown | flush-dns | retest |
                               reset-list | reset-all-lists | reconcile (no sudo needed)
autodpi update [install|skip]  look for a newer version (install: now; skip: skip this version)
autodpi ui [--no-open]         the settings page in the browser
autodpi doctor | lab           diagnostics, including other tools' DNS rules (lab: which technique opens what on this network)
```

Emergency brake: `./restore-network.sh` in the macOS folder, or on Windows `restore-network.ps1` in the
folder (key 0 of the `AutoDPI.cmd` menu), stops everything and puts DNS back. In the source tree they
are in `scripts/`.

## How it works

```
app ─► sing-box TUN ─┬─ blocked site on this network ─► engine ─► internet
       (all traffic)  └─ any other TCP/443 ─► observer ─ tries the real path first;
                                                          on a reset or fake reply replays the same
                                                          ClientHello through an engine (first attempt opens),
                                                          then validates and lists the site
```

- **Engines**, tried in order: `tlsrec` (splits the ClientHello into two TLS records), `ciadpi` (byedpi desync chain), `tlsspoof` (decoy ClientHello, root only).
- **Learning is per network** (keyed by the ISP's AS number), stored as registrable domains. A site that
  opens directly several times in a row is cached in memory and passes through a light path; if it is
  blocked later, a retry opens it and it is listed. Only a reset or an injected reply counts as a block,
  so a stalled link never lists anything.
- **DNS**: while active the system resolver points at 1.1.1.1, which the TUN answers over DoH (two
  resolvers, with failover); your original setting is saved and restored on stop. QUIC is refused only
  for listed sites so their apps fall back to TCP. IPv6 is captured only when the network has it.
- **Fail-open**: helper processes die with the daemon, the capture is released if its health checks keep
  failing, and re-engaging backs off. Real use is about 70 MB and ~2 % of one core.

## Updates

The service looks for a newer release on GitHub once a day. It downloads it, checks the release's
signature (an installed copy accepts only archives signed with the project's key) and installs it once
the connection is idle; the service restarts for a few seconds. A new version that does not come up
properly is replaced by the previous one, which then does not install it again by itself. With
automatic updates off, the menu bar app, the tray window and the page announce the new version with
Update, Notes and Skip buttons. Both settings are in Settings → Updates on the page and apply without
a restart; the menu bar app and the tray window have Check for updates under the version line.

## Configuration

Optional `config.json` next to the state file (`/Library/Application Support/AutoDPI/` on macOS,
`%ProgramData%\AutoDPI\` on Windows), or the settings page. Restart the service to apply
(`autodpi maint restart`, or Maintenance on the page).

| key | default | meaning |
|---|---|---|
| `engines` | `["tlsrec","ciadpi","tlsspoof"]` | engine order |
| `doh_servers` | `["1.1.1.1","1.0.0.1"]` | DoH resolvers (IP addresses) |
| `dns_takeover` | `true` | point the system resolver at the TUN |
| `block_quic` | `true` | refuse QUIC for listed sites |
| `escalate_on_silence` | `false` | let a flow that only times out try every engine (networks that drop packets silently) |
| `local_domains` | `[]` | extra domain suffixes answered by the network's own DNS (company or school networks); `.local`, `.lan`, `.corp`, `.internal` and single-word names always are |
| `retest_hours` | `3` | how often listed sites are re-checked |
| `spoof_sni` | `www.google.com` | decoy name for `tlsspoof` |
| `auto_update` | `true` | install a newer version by itself once the connection is idle; off, it is only announced |
| `update_check_hours` | `24` | how often to look for a newer version; `0`: only when asked |
| `language` | (the system's) | `"tr"` or `"en"`: the language of the command line, the apps and the page |
| `hedge_ms`, `first_byte_ms`, `max_conn`, `ciadpi_args`, `ipv4_only`, `warp_profile` | | advanced |

## Build from source

Needs Go, the Xcode Command Line Tools (clang and swiftc) and curl, on an Apple Silicon Mac. Everything
the daemon embeds is pinned and checksum-verified: sing-box 1.14.4 is built from source with only the
needed tags (`tools/singbox`), byedpi 0.17.3 from its release tarball.

```bash
scripts/release.sh 0.1.1        # dist/release/*.zip for macOS and Windows (cross-built) + SHA256SUMS
go test -race ./...             # tests; scripts/dev/e2e-notun.sh runs the whole pipeline without root
```

`scripts/fetch-bins.sh`, `build.sh`, `build-app.sh` and the `*-windows.sh` scripts do the steps separately.

## Limits

TCP/443 only (UDP-only blocks such as voice calls are not handled); IPv6-only networks are not
supported; with ECH the SNI is invisible; the macOS build is Apple Silicon only, the Windows build
amd64 only. This is a root daemon: read the code before running it.

## Legal notice and disclaimer

**Server and data.** AutoDPI runs on your own device. The project operates no server: your traffic does
not pass through the project, and your browsing, site lists and usage data are not sent to it. The app
connects to the sites you open, to Cloudflare (1.1.1.1, 1.0.0.1) for DNS, to your network's DNS servers
for connection checks, and to GitHub for updates. A support report is created only on your computer and
is never sent by itself. It can hold domain names, DNS rules, hosts entries and local network addresses;
look inside before you share it.

**Purpose.** It is meant for personal use and for getting around network-level censorship of lawful
content. Do not use it for anything illegal, for unauthorized access to other people's accounts or
systems, or to harm or overload network infrastructure. AutoDPI asks for no account details and logs in
to no network or service on your behalf.

**Risks.** Getting around filters may break the terms of the network you connect to, such as a dormitory,
campus, workplace or public Wi-Fi. That can lead to restricted access, a suspended account or disciplinary
action. Access to some content may be blocked by a court or administrative order. Checking the law where
you are and the terms of your network is up to you.

**Not a VPN.** AutoDPI does not encrypt your traffic, hide your IP address or make you anonymous. Your
network and internet provider can still see which servers you connect to.

**Disclaimer.** Use is entirely your own decision and responsibility. The software comes "as is" with no
warranty; it does not promise that a site will open or that a connection will be uninterrupted or secure.
As far as the law allows, its authors accept no liability for direct or indirect damage, data loss,
service interruption or sanctions arising from its use (GPL-3.0, sections 15 and 16). This text is not
legal advice.

## License

Copyright (C) 2026 Shuushi0.

GPL-3.0-or-later, see [LICENSE](LICENSE). The release binaries bundle sing-box (GPL-3.0-or-later),
byedpi (MIT) and a few Go modules; see [THIRD_PARTY.md](THIRD_PARTY.md).
