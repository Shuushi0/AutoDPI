# AutoDPI menu for Windows: everything docs/windows-test.md walks through, one key each.
# Started by AutoDPI.cmd (double-click), or with -Panel by "AutoDPI Panel.cmd"
# to open only the control panel; asks for administrator rights itself.
# Saved as UTF-8 with BOM so Windows PowerShell 5.1 reads the Turkish text.
param([switch]$Panel, [switch]$Relaunched, [string]$CallerSid = '', [string]$CallerDesktop = '')
# Not 'Stop': Windows PowerShell 5.1 would then turn every line autodpi.exe
# writes to stderr into a terminating error.
$ErrorActionPreference = 'Continue'
# Whatever goes wrong below is shown and the script carries on: the window
# must never just disappear.
trap {
    Write-Host ''
    Write-Host ('HATA / ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    if ($_.InvocationInfo) { Write-Host $_.InvocationInfo.PositionMessage }
    continue
}

# Texts come in pairs, T 'Türkçe' 'English'. Until autodpi.exe answers (it
# applies the settings' language too) the display language decides.
$script:TR = (Get-UICulture).TwoLetterISOLanguageName -eq 'tr'
function T([string]$trText, [string]$enText) { if ($script:TR) { $trText } else { $enText } }
function Wait-Close { Read-Host (T 'Kapatmak için Enter' 'Press Enter to close') | Out-Null }

# Elevated means the high integrity level (S-1-16-12288) in the token. whoami
# says so in every language mode; the .NET check does not work everywhere.
$admin = [bool](& "$env:SystemRoot\System32\whoami.exe" /groups | Select-String -SimpleMatch 'S-1-16-12288')
if (-not $admin) { try {
    # Inside a try: where the language mode is restricted (Smart App Control,
    # an AppLocker policy) a statement in here can fail, and the trap at the
    # top would then carry on PAST this block, into the menu, without
    # administrator rights.
    # What the administrator window could not show is shown here, before it is
    # opened: that window closes at once when it cannot even read this file.
    if ($Relaunched) {
        Write-Host (T 'Yönetici penceresi de yönetici hakları almadı. Yönetici bir hesapla deneyin.' 'The elevated window did not get administrator rights either. Try with an administrator account.') -ForegroundColor Red
        Wait-Close; exit 3
    }
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'autodpi.exe'))) {
        Write-Host ((T 'autodpi.exe bu klasörde yok: ' 'autodpi.exe is not in this folder: ') + $PSScriptRoot) -ForegroundColor Red
        Write-Host (T 'Zip''in tamamını bir klasöre çıkarıp AutoDPI.cmd''yi oradan çalıştırın.' 'Extract the whole zip to a folder and run AutoDPI.cmd from there.')
        Wait-Close; exit 3
    }
    # An elevated window has its own logon session and does not see this
    # user's mapped network drives or subst drives.
    $root = [IO.Path]::GetPathRoot($PSCommandPath)
    $remote = $root.StartsWith('\\')
    if (-not $remote) {
        $drv = Get-PSDrive -Name $root.Substring(0, 1) -PSProvider FileSystem -ErrorAction SilentlyContinue
        $remote = [bool]($drv -and "$($drv.DisplayRoot)" -like '\\*') -or
            [bool]((& "$env:SystemRoot\System32\subst.exe") -match ('^' + [regex]::Escape($root.Substring(0, 2)) + '\\'))
    }
    if ($remote) {
        Write-Host (T 'Bu klasör bir ağ ya da subst sürücüsünde; yönetici penceresi orayı göremez. Klasörü masaüstüne kopyalayıp oradan çalıştırın.' 'This folder is on a network or subst drive, which the administrator window cannot see. Copy the folder to the desktop and run it from there.') -ForegroundColor Red
        Wait-Close; exit 3
    }
    # The administrator may be another account (a standard user typing an
    # administrator's password): the report then belongs on THIS user's
    # desktop, and the tray icon is not started as that other account.
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Relaunched',
        '-CallerSid', ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value),
        '-CallerDesktop', "`"$([Environment]::GetFolderPath('Desktop'))`"")
    if ($Panel) { $relaunch += '-Panel' }
    try {
        $p = Start-Process powershell.exe -Verb RunAs -PassThru -ErrorAction Stop -ArgumentList $relaunch
    } catch {
        Write-Host (T 'Yönetici izni verilmedi; AutoDPI yönetici olmadan kurulamaz.' 'Administrator permission was not given; AutoDPI cannot be installed without it.') -ForegroundColor Red
        Wait-Close; exit 3
    }
    Write-Host (T 'AutoDPI yönetici penceresinde açıldı; bu pencere onunla birlikte kapanır.' 'AutoDPI opened in the administrator window; this window closes with it.')
    # This window stays to report how that one ended. WaitForExit, not -Wait:
    # -Wait would also wait for the hidden settings-page process it starts.
    $null = $p.Handle
    $p.WaitForExit()
    $code = $p.ExitCode
    if ($code -ne 0 -and $code -ne 3) {
        # -1073741510: closed with the X or Ctrl+C, which needs no error line.
        if ($code -ne -1073741510) { Write-Host ((T 'Yönetici penceresi bir hatayla kapandı, kod ' 'The administrator window ended with an error, code ') + $code) -ForegroundColor Red }
        Write-Host (T 'İnternet bozulduysa AutoDPI.cmd''yi yeniden açıp 0 (Acil fren) seçin.' 'If the internet broke, open AutoDPI.cmd again and choose 0 (emergency brake).')
        Wait-Close
    }
    exit 0
} catch { Write-Host ('HATA / ERROR: ' + $_.Exception.Message) -ForegroundColor Red; Wait-Close; exit 3 } }
$script:SameUser = ($CallerSid -eq '') -or ($CallerSid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)

Set-Location -LiteralPath $PSScriptRoot
# Files extracted from a downloaded zip carry the "from the internet" mark;
# drop it so SmartScreen does not stop autodpi.exe on every start.
Get-ChildItem -LiteralPath $PSScriptRoot -File | Unblock-File -ErrorAction SilentlyContinue
# autodpi.exe writes UTF-8; without this PowerShell reads captured output
# (reports, the network lab) in the OEM code page and garbles the Turkish.
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

$exe = Join-Path $PSScriptRoot 'autodpi.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host ((T 'autodpi.exe bu klasörde yok: ' 'autodpi.exe is not in this folder: ') + $PSScriptRoot) -ForegroundColor Red
    Write-Host (T 'Zip''in tamamını bir klasöre çıkarıp AutoDPI.cmd''yi oradan çalıştırın.' 'Extract the whole zip to a folder and run AutoDPI.cmd from there.')
    Wait-Close
    exit 3
}
# A program Windows refuses to run (Smart App Control, an application control
# policy, an antivirus) fails here first. Say what it is and keep the menu:
# the report (8), the brake (0) and G do not need it.
try { $lang = & $exe lang 2>$null } catch {
    $lang = $null
    Write-Host ((T 'autodpi.exe çalıştırılamadı: ' 'autodpi.exe could not run: ') + $_.Exception.Message) -ForegroundColor Red
    Write-Host (T 'Bunu çoğunlukla Windows Akıllı Uygulama Denetimi (Smart App Control), bir uygulama denetimi ilkesi ya da antivirüs yapar. 8 ile rapor alabilirsiniz.' 'This is usually Windows Smart App Control, an application control policy or an antivirus. Key 8 still collects a report.') -ForegroundColor Yellow
    Wait-Close
}
if ($lang) { $script:TR = "$lang".Trim() -eq 'tr' }

function Show-State {
    $svc = Get-Service -Name AutoDPI -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host (T 'Servis: KURULU DEĞİL' 'Service: NOT INSTALLED') -ForegroundColor Yellow
    } elseif ($svc.Status -eq 'Running') {
        Write-Host (T 'Servis: ÇALIŞIYOR' 'Service: RUNNING') -ForegroundColor Green
    } else {
        Write-Host ((T 'Servis: ' 'Service: ') + $svc.Status) -ForegroundColor Yellow
    }
    if ((Get-Conflicts).Running) {
        Write-Host (T 'UYARI: GoodbyeDPI/zapret açık. AutoDPI onunla birlikte çalışmaz, bekler. G ile durdurun.' 'WARNING: GoodbyeDPI/zapret is running. AutoDPI does not work next to it and waits. Press G to stop it.') -ForegroundColor Red
    }
}

# Other DPI tools rewriting the same packets through WinDivert. Next to them
# the service stays in standby (and browsers would get ERR_SSL_PROTOCOL_ERROR).
function Get-Conflicts {
    $procs = @(Get-Process -Name goodbyedpi, winws -ErrorAction SilentlyContinue)
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -match 'goodbyedpi|winws' })
    $running = $procs.Count -gt 0 -or @($svcs | Where-Object State -eq 'Running').Count -gt 0
    [pscustomobject]@{ Procs = $procs; Services = $svcs; Running = $running }
}

function Stop-Conflicts {
    $c = Get-Conflicts
    if (-not $c.Running -and $c.Services.Count -eq 0) {
        Write-Host (T 'GoodbyeDPI ya da zapret bulunamadı.' 'Neither GoodbyeDPI nor zapret was found.')
        return
    }
    foreach ($s in $c.Services) {
        Stop-Service -Name $s.Name -Force -NoWait -ErrorAction SilentlyContinue # -NoWait: a service stuck in "stop pending" would hold the menu for ever
        Set-Service -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host ((T 'Hizmet durduruldu, açılışta da başlamayacak: ' 'Service stopped, and it will not start at boot: ') + $s.Name)
        Write-Host ((T '  (geri açmak için: ' '  (to turn it back on: ') + "Set-Service $($s.Name) -StartupType Automatic; Start-Service $($s.Name))")
    }
    $c.Procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    if ((Get-Conflicts).Running) {
        Write-Host (T 'Hâlâ çalışıyor: GoodbyeDPI/zapret penceresini elle kapatın.' 'Still running: close the GoodbyeDPI/zapret window by hand.') -ForegroundColor Red
    } else {
        Write-Host (T 'GoodbyeDPI/zapret kapalı. AutoDPI birkaç saniye içinde kendiliğinden devreye girer.' 'GoodbyeDPI/zapret is closed. AutoDPI takes over by itself within a few seconds.') -ForegroundColor Green
    }
}

# Stop-Panel ends the hidden page servers ("autodpi.exe ui ..."). The word has
# to be the first argument: a service started from a folder whose name has
# " ui " in it is not a page server.
function Stop-Panel {
    Get-CimInstance Win32_Process -Filter "Name='autodpi.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match '^\s*("[^"]+"|[^\s"]\S*)\s+ui(\s|$)' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# Open-Panel serves the control page from a hidden "autodpi ui" process and
# opens it in the browser. One panel at a time: the page lives as long as that
# process, so an older one is replaced.
function Open-Panel([switch]$Trial) {
    if (-not $Trial -and -not (Get-Service -Name AutoDPI -ErrorAction SilentlyContinue)) {
        Write-Host (T 'Servis kurulu değil: panel açılır ama durum ve liste boş kalır. Önce menüde 1 ile kurun.' 'The service is not installed: the panel opens but state and list stay empty. Install it first with 1.') -ForegroundColor Yellow
    }
    Stop-Panel
    Start-Sleep -Milliseconds 300
    Remove-Item (Join-Path $env:TEMP 'autodpi-panel-*.txt') -ErrorAction SilentlyContinue
    $out = Join-Path $env:TEMP ("autodpi-panel-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    # For a trial the page goes when the service does (--with-service):
    # nothing of the trial stays behind.
    $uiArgs = @('ui', '--no-open')
    if ($Trial) { $uiArgs += '--with-service' }
    Start-Process $exe -ArgumentList $uiArgs -WindowStyle Hidden -RedirectStandardOutput $out
    $url = $null
    for ($i = 0; $i -lt 50 -and -not $url; $i++) {
        Start-Sleep -Milliseconds 100
        $m = Select-String -Path $out -Pattern 'http://127\.0\.0\.1:\d+/\?t=[0-9a-f]+' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($m) { $url = $m.Matches[0].Value }
    }
    if (-not $url) {
        Write-Host (T 'Kontrol paneli başlatılamadı.' 'The control panel did not start.') -ForegroundColor Red
        return $false
    }
    # Through Explorer, so the browser does not start with administrator rights.
    if ($script:SameUser) {
        Start-Process explorer.exe -ArgumentList "`"$url`""
        Write-Host (T 'Kontrol paneli tarayıcıda açıldı. Açılmadıysa bu adresi tarayıcıya yapıştırın:' 'The control panel opened in the browser. If it did not, paste this address into the browser:') -ForegroundColor Green
    } else {
        # Another account's desktop: its browser cannot be started from here.
        Write-Host (T 'Kontrol paneli hazır. Bu adresi tarayıcıya yapıştırın:' 'The control panel is ready. Paste this address into the browser:') -ForegroundColor Green
    }
    Write-Host "  $url"
    Write-Host (T 'Panel arka planda çalışır; yeniden açtığınızda yenisiyle değişir, bilgisayar kapanınca durur.' 'The panel runs in the background; opening it again replaces it, and it stops when the computer shuts down.')
    return $true
}

# Start-Trial runs the service for five minutes without installing it, and
# opens the control panel beside it. The trial used to run in the foreground:
# the menu was held until it ended, so 3 could not be pressed and there was no
# panel in which to see what the trial did (which sites it opened, which it
# listed). The service runs in this window's own console, so closing the
# window ends it as before; Q ends it early and gives the network back.
function Start-Trial {
    $log = Join-Path (Split-Path -Parent $exe) 'deneme.log' # next to autodpi.exe, as before
    # A program that may not run at all (blocked by a security product) is
    # said so here, not announced as a trial that then never happens.
    $p = $null
    $why = ''
    try {
        $p = Start-Process $exe -ArgumentList 'daemon', '--for', '5m', '-v', '--log-file', "`"$log`"" -NoNewWindow -PassThru -ErrorAction Stop
    } catch { $why = "$_" }
    if (-not $p) {
        Write-Host ((T 'Deneme başlatılamadı: autodpi.exe çalıştırılamıyor (bir güvenlik programı engelliyor olabilir). ' 'The trial could not be started: autodpi.exe cannot be run (a security program may be blocking it). ') + $why) -ForegroundColor Red
        return
    }
    # Windows PowerShell 5.1 forgets the process unless its handle was asked
    # for: it would then look it up by number again, and a number is reused.
    $null = $p.Handle
    Write-Host (T 'Deneme başlıyor…' 'The trial is starting…')
    # The panel is opened once the service answers (a few seconds; longer
    # when a security product scans the programs on their first start).
    $up = $false
    for ($i = 0; $i -lt 120 -and -not $up -and -not $p.HasExited; $i++) {
        Start-Sleep -Milliseconds 500
        try { & $exe status *> $null; $up = ($LASTEXITCODE -eq 0) } catch { $up = $false }
    }
    if ($p.HasExited) {
        Write-Host ((T 'Deneme başlayamadı. Nedeni şu dosyada: ' 'The trial did not start. The reason is in: ') + $log) -ForegroundColor Red
        return
    }
    Open-Panel -Trial | Out-Null
    Write-Host ''
    Write-Host (T 'Deneme sürüyor: açılmayan siteleri şimdi tarayıcıda deneyin. 5 dakika sonra kendiliğinden biter.' 'The trial is running: try the sites that do not open in the browser now. It ends by itself after 5 minutes.') -ForegroundColor Cyan
    Write-Host (T '  3  Kontrol panelini yeniden aç      Q  Denemeyi şimdi bitir' '  3  Open the control panel again      Q  End the trial now')
    # Five minutes and the service's own time to wind down; past that it is
    # not waited for any longer.
    $deadline = (Get-Date).AddSeconds(5 * 60 + 45)
    while (-not $p.HasExited -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $stop = $false
        $panel = $false
        # The menu's own keys that make sense while a trial runs: 3 opens the
        # panel again (a closed tab), Q ends the trial. No keyboard to read
        # (input redirected) is no reason to end it.
        try {
            while ([Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true)
                if ($k.Key -eq 'Q') { $stop = $true } elseif ($k.KeyChar -eq '3') { $panel = $true }
            }
        } catch { }
        if ($panel -and -not $stop) { Open-Panel -Trial | Out-Null }
        if ($stop) {
            try { & $exe maint shutdown *> $null } catch { }
            for ($i = 0; $i -lt 60 -and -not $p.HasExited; $i++) { Start-Sleep -Milliseconds 500 }
            break
        }
    }
    Stop-Trial $p
    Write-Host (T 'Deneme bitti. Şimdi bir site açıp internetin normal çalıştığını kontrol edin.' 'Trial over. Now open a site and check that the internet works normally.') -ForegroundColor Green
}

# Stop-Trial makes sure nothing of a trial is left running: the service if it
# did not end by itself (ending it ends its helpers, and the capture with
# them), any helper that outlived it all the same, and the page opened for it.
function Stop-Trial($p) {
    if ($p -and -not $p.HasExited) {
        Write-Host (T 'Servis kendiliğinden durmadı; sonlandırılıyor.' 'The service did not stop by itself; ending it.') -ForegroundColor Yellow
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { }
        Start-Sleep -Seconds 1
    }
    $bin = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AutoDPI\bin\'
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($bin, 'OrdinalIgnoreCase') } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Stop-Panel
    # sing-box adds a Windows Firewall rule for itself and never removes it;
    # a trial leaves the firewall as it found it. Matched by program path.
    if ($env:SystemRoot) {
        try { & (Join-Path $env:SystemRoot 'System32\netsh.exe') advfirewall firewall delete rule name=all ('program=' + $bin + 'sing-box.exe') *> $null } catch { }
    }
}

# Save-Output writes what a collector prints into one file of the report. A
# collector that cannot run (autodpi.exe blocked, a cmdlet missing on this
# Windows) leaves its error in that file instead of ending the whole report.
function Save-Output([string]$Dir, [string]$Name, [scriptblock]$Script) {
    $f = Join-Path $Dir $Name
    try { & $Script *> $f } catch { ('FAILED: ' + $_.Exception.Message) | Out-File -FilePath $f -Append }
}

function Save-Report {
    # The desktop of whoever started the menu, also when the administrator
    # window runs as another account.
    $desktop = if ($CallerDesktop -and (Test-Path -LiteralPath $CallerDesktop)) { $CallerDesktop } else { [Environment]::GetFolderPath('Desktop') }
    $zip = Join-Path $desktop 'autodpi-rapor.zip'
    # A fresh folder every time, outside the desktop: files of an earlier
    # report never ride along in the new zip.
    $o = Join-Path ([IO.Path]::GetTempPath()) ('autodpi-rapor-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $o | Out-Null
    try {
        Save-Output $o 'winver.txt'  { cmd.exe /c ver }
        Save-Output $o 'version.txt' { & $exe version }
        Save-Output $o 'doctor.txt'  { & $exe doctor }
        Save-Output $o 'status.txt'  { & $exe status }
        Save-Output $o 'list.txt'    { & $exe list }
        Save-Output $o 'log.txt'     { & $exe log }
        Save-Output $o 'sc.txt'      { sc.exe query AutoDPI }
        foreach ($f in @("$env:ProgramData\AutoDPI\autodpi.log", "$PSScriptRoot\deneme.log", "$PSScriptRoot\lab.txt")) {
            if (Test-Path -LiteralPath $f) { Copy-Item -LiteralPath $f -Destination $o -Force -ErrorAction SilentlyContinue }
        }
        Save-Output $o 'events.txt' {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue |
                Where-Object Message -match 'AutoDPI' | Format-List TimeCreated, Message
        }
        # Defender: only detections that touch AutoDPI's own files (a quarantined
        # helper stops the service). The rest of the machine's history stays out.
        $mine = 'autodpi|sing-box|ciadpi|wintun'
        Save-Output $o 'defender.txt' {
            Get-MpThreatDetection -ErrorAction SilentlyContinue |
                Where-Object { ($_.Resources -join ' ') -match $mine } |
                ForEach-Object {
                    [pscustomobject]@{
                        Time          = $_.InitialDetectionTime
                        Threat        = (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName
                        ActionSuccess = $_.ActionSuccess
                        Files         = ($_.Resources | Where-Object { $_ -match $mine }) -join '; '
                    }
                } | Format-List
        }
        # What else decides how names resolve, read here and not by autodpi.exe,
        # so it is in the report even when the program itself cannot run.
        # Process names only: a path can hold the user's name.
        Save-Output $o 'dns.txt' {
            '--- NRPT'
            Get-DnsClientNrptRule -ErrorAction SilentlyContinue | ForEach-Object { '{0} -> {1}' -f ($_.Namespace -join ','), ($_.NameServers -join ',') }
            '--- hosts'
            Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
            '--- DNS servers'
            Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object ServerAddresses | ForEach-Object { '{0} ({1}): {2}' -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ',') }
            '--- port 53'
            $listen = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue) + @(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue)
            $listen | ForEach-Object { '{0} pid {1} {2}' -f $_.LocalAddress, $_.OwningProcess, (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }
            '--- adapters'
            Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object { '{0}: {1}' -f $_.Name, $_.InterfaceDescription }
            '--- metrics'
            Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected -ErrorAction SilentlyContinue | Sort-Object InterfaceMetric | ForEach-Object { '{0}: {1}' -f $_.InterfaceAlias, $_.InterfaceMetric }
            '--- WinHTTP proxy'
            netsh winhttp show proxy
        }
        try {
            Compress-Archive -Force -Path "$o\*" -DestinationPath $zip -ErrorAction Stop
            Write-Host ((T 'Rapor hazır: ' 'Report ready: ') + $zip) -ForegroundColor Green
        } catch {
            # The files are worth more than the zip: leave them as a folder.
            $keep = Join-Path $desktop 'autodpi-rapor'
            Copy-Item -LiteralPath $o -Destination $keep -Recurse -Force -ErrorAction SilentlyContinue
            # The copy failed too: what was collected stays where it is,
            # instead of being deleted below as the only copy there is.
            if (-not (Test-Path -LiteralPath $keep)) { $keep = $o; $o = $null }
            Write-Host ((T 'Zip yapılamadı; dosyalar burada: ' 'Could not zip; the files are here: ') + $keep) -ForegroundColor Yellow
        }
    } finally {
        if ($o) { Remove-Item -Recurse -Force $o -ErrorAction SilentlyContinue }
    }
}

if ($Panel) {
    # 3: the message was shown and waited on here; the .cmd does not pause again.
    if (-not (Open-Panel)) { Read-Host (T 'Kapatmak için Enter' 'Press Enter to close') | Out-Null; exit 3 }
    Start-Sleep -Seconds 5
    exit
}

while ($true) {
    # The trap above is not enough in here: after an error it carries on
    # behind the statement that failed, and seen from the top of the script
    # that statement is this whole loop. The menu would end and the window
    # with it. (The body is not indented: a here-string's closing '@ must
    # stay in the first column.)
    try {
    Clear-Host
    Write-Host '=== AutoDPI ===' -ForegroundColor Cyan
    Show-State
    if ($script:TR) {
        Write-Host @'

  1  Kur / güncelle ve başlat
  2  Durum ve engelli site listesi
  3  Kontrol panelini aç (tarayıcı)
  4  Duraklat
  5  Sürdür
  6  Ağ ölçümü (kurmadan, birkaç dakika)
  7  Deneme çalıştırması (kurmadan; panel açılır, 5 dakika sonra kendiliğinden kapanır)
  8  Rapor topla (masaüstüne autodpi-rapor.zip)
  9  Kaldır (her şeyi siler)
  0  Acil fren (internet bozulduysa)
  G  GoodbyeDPI / zapret'i durdur
  Q  Çıkış

'@
    } else {
        Write-Host @'

  1  Install / update and start
  2  State and the list of blocked sites
  3  Open the control panel (browser)
  4  Pause
  5  Resume
  6  Network lab (without installing, a few minutes)
  7  Trial run (without installing; opens the panel, stops by itself after 5 minutes)
  8  Collect a report (autodpi-rapor.zip on the desktop)
  9  Uninstall (deletes everything)
  0  Emergency brake (if the internet broke)
  G  Stop GoodbyeDPI / zapret
  Q  Quit

'@
    }
    $c = (Read-Host (T 'Seçim' 'Choice')).Trim().ToUpper()
    Write-Host ''
    switch ($c) {
        '1' {
            & $exe install
            # The tray icon runs as the signed-in user, not as administrator:
            # Explorer starts it unelevated.
            $tray = Join-Path $env:ProgramData 'AutoDPI\autodpi-tray.exe'
            if (Test-Path -LiteralPath $tray) {
                if ($script:SameUser) { Start-Process explorer.exe -ArgumentList "`"$tray`"" }
                else { Write-Host (T 'Tepsi simgesi bir sonraki oturum açılışınızda gelir (ya da Başlat menüsünden AutoDPI).' 'The tray icon appears at your next sign-in (or open AutoDPI from the Start menu).') }
            }
            Start-Sleep -Seconds 3
            & $exe status
        }
        '2' { & $exe status; Write-Host ''; & $exe list }
        '3' { Open-Panel | Out-Null }
        '4' { & $exe pause }
        '5' { & $exe resume }
        '6' { & $exe lab | Tee-Object -FilePath (Join-Path $PSScriptRoot 'lab.txt') }
        '7' {
            if (Get-Service -Name AutoDPI -ErrorAction SilentlyContinue) {
                Write-Host (T 'Servis kurulu; deneme yalnızca kurulumdan önce yapılır (önce 9 ile kaldırın).' 'The service is installed; the trial is for before installing (uninstall with 9 first).') -ForegroundColor Yellow
            } else {
                Start-Trial
            }
        }
        '8' { Save-Report }
        '9' {
            # Everything goes, the learned lists too: ask first.
            $ok = Read-Host (T 'AutoDPI ve öğrenilen listeler silinsin mi? Onaylamak için E yazın' 'Delete AutoDPI and the learned lists? Type Y to confirm')
            if ("$ok".Trim() -match '^(e|evet|y|yes)$') {
                & $exe uninstall --purge
            } else {
                Write-Host (T 'Vazgeçildi, hiçbir şey silinmedi.' 'Cancelled; nothing was deleted.')
            }
        }
        '0' { & (Join-Path $PSScriptRoot 'restore-network.ps1') }
        'G' { Stop-Conflicts }
        'Q' { exit }
        default { Write-Host (T 'Geçersiz seçim.' 'Invalid choice.') }
    }
    } catch {
        Write-Host ''
        Write-Host ('HATA / ERROR: ' + $_.Exception.Message) -ForegroundColor Red
        if ($_.InvocationInfo) { Write-Host $_.InvocationInfo.PositionMessage }
    }
    Write-Host ''
    Read-Host (T 'Menüye dönmek için Enter' 'Press Enter to return to the menu')
}
