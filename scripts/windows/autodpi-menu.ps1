# AutoDPI menu for Windows: everything docs/windows-test.md walks through, one key each.
# Started by AutoDPI.cmd (double-click), or with -Panel by "AutoDPI Panel.cmd"
# to open only the control panel; asks for administrator rights itself.
# Saved as UTF-8 with BOM so Windows PowerShell 5.1 reads the Turkish text.
param([switch]$Panel)
$ErrorActionPreference = 'Continue'

# Texts come in pairs, T 'Türkçe' 'English'. Until autodpi.exe answers (it
# applies the settings' language too) the display language decides.
$script:TR = (Get-UICulture).TwoLetterISOLanguageName -eq 'tr'
function T([string]$trText, [string]$enText) { if ($script:TR) { $trText } else { $enText } }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    try {
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        if ($Panel) { $relaunch += '-Panel' }
        Start-Process powershell.exe -Verb RunAs -ErrorAction Stop -ArgumentList $relaunch
    } catch {
        Write-Host (T 'Yönetici izni verilmedi; AutoDPI yönetici olmadan kurulamaz.' 'Administrator permission was not given; AutoDPI cannot be installed without it.') -ForegroundColor Red
        Read-Host (T 'Kapatmak için Enter' 'Press Enter to close')
    }
    exit
}

Set-Location $PSScriptRoot
# Files extracted from a downloaded zip carry the "from the internet" mark;
# drop it so SmartScreen does not stop autodpi.exe on every start.
Get-ChildItem $PSScriptRoot -File | Unblock-File -ErrorAction SilentlyContinue
# autodpi.exe writes UTF-8; without this PowerShell reads captured output
# (reports, the network lab) in the OEM code page and garbles the Turkish.
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

$exe = Join-Path $PSScriptRoot 'autodpi.exe'
if (-not (Test-Path $exe)) {
    Write-Host ((T 'autodpi.exe bu klasörde yok: ' 'autodpi.exe is not in this folder: ') + $PSScriptRoot) -ForegroundColor Red
    Write-Host (T 'Zip''in tamamını bir klasöre çıkarıp AutoDPI.cmd''yi oradan çalıştırın.' 'Extract the whole zip to a folder and run AutoDPI.cmd from there.')
    Read-Host (T 'Kapatmak için Enter' 'Press Enter to close')
    exit 1
}
$lang = & $exe lang 2>$null
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
        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
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

# Open-Panel serves the control page from a hidden "autodpi ui" process and
# opens it in the browser. One panel at a time: the page lives as long as that
# process, so an older one is replaced.
function Open-Panel {
    if (-not (Get-Service -Name AutoDPI -ErrorAction SilentlyContinue)) {
        Write-Host (T 'Servis kurulu değil: panel açılır ama durum ve liste boş kalır. Önce menüde 1 ile kurun.' 'The service is not installed: the panel opens but state and list stay empty. Install it first with 1.') -ForegroundColor Yellow
    }
    Get-CimInstance Win32_Process -Filter "Name='autodpi.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match '\sui(\s|$)' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 300
    Remove-Item (Join-Path $env:TEMP 'autodpi-panel-*.txt') -ErrorAction SilentlyContinue
    $out = Join-Path $env:TEMP ("autodpi-panel-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    Start-Process $exe -ArgumentList 'ui', '--no-open' -WindowStyle Hidden -RedirectStandardOutput $out
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
    Start-Process explorer.exe -ArgumentList "`"$url`""
    Write-Host (T 'Kontrol paneli tarayıcıda açıldı. Açılmadıysa bu adresi tarayıcıya yapıştırın:' 'The control panel opened in the browser. If it did not, paste this address into the browser:') -ForegroundColor Green
    Write-Host "  $url"
    Write-Host (T 'Panel arka planda çalışır; yeniden açtığınızda yenisiyle değişir, bilgisayar kapanınca durur.' 'The panel runs in the background; opening it again replaces it, and it stops when the computer shuts down.')
    return $true
}

function Save-Report {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $zip = Join-Path $desktop 'autodpi-rapor.zip'
    # A fresh folder every time, outside the desktop: files of an earlier
    # report never ride along in the new zip.
    $o = Join-Path ([IO.Path]::GetTempPath()) ('autodpi-rapor-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $o | Out-Null
    try {
        cmd.exe /c ver > "$o\winver.txt"
        & $exe version *> "$o\version.txt"
        & $exe doctor  *> "$o\doctor.txt"
        & $exe status  *> "$o\status.txt"
        & $exe list    *> "$o\list.txt"
        & $exe log     *> "$o\log.txt"
        sc.exe query AutoDPI *> "$o\sc.txt"
        foreach ($f in @("$env:ProgramData\AutoDPI\autodpi.log", "$PSScriptRoot\deneme.log", "$PSScriptRoot\lab.txt")) {
            if (Test-Path $f) { Copy-Item $f $o -Force }
        }
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue |
            Where-Object Message -match 'AutoDPI' | Format-List TimeCreated, Message *> "$o\events.txt"
        # Defender: only detections that touch AutoDPI's own files (a quarantined
        # helper stops the service). The rest of the machine's history stays out.
        $mine = 'autodpi|sing-box|ciadpi|wintun'
        Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Where-Object { ($_.Resources -join ' ') -match $mine } |
            ForEach-Object {
                [pscustomobject]@{
                    Time          = $_.InitialDetectionTime
                    Threat        = (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName
                    ActionSuccess = $_.ActionSuccess
                    Files         = ($_.Resources | Where-Object { $_ -match $mine }) -join '; '
                }
            } | Format-List *> "$o\defender.txt"
        # What else decides how names resolve, read here and not by autodpi.exe,
        # so it is in the report even when the program itself cannot run.
        # Process names only: a path can hold the user's name.
        & {
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
        } *> "$o\dns.txt"
        Compress-Archive -Force -Path "$o\*" -DestinationPath $zip
        Write-Host ((T 'Rapor hazır: ' 'Report ready: ') + $zip) -ForegroundColor Green
    } finally {
        Remove-Item -Recurse -Force $o -ErrorAction SilentlyContinue
    }
}

if ($Panel) {
    if (-not (Open-Panel)) { Read-Host (T 'Kapatmak için Enter' 'Press Enter to close') | Out-Null; exit 1 }
    Start-Sleep -Seconds 5
    exit
}

while ($true) {
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
  7  Deneme çalıştırması (kurmadan, 5 dakika sonra kendiliğinden kapanır)
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
  7  Trial run (without installing, stops by itself after 5 minutes)
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
            if (Test-Path $tray) { Start-Process explorer.exe -ArgumentList "`"$tray`"" }
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
                Write-Host (T 'Deneme başladı. Bu sırada açılmayan siteleri tarayıcıda deneyin; 5 dakika sonra biter.' 'Trial started. Meanwhile try the sites that do not open in the browser; it ends after 5 minutes.')
                & $exe daemon --for 5m -v --log-file (Join-Path $PSScriptRoot 'deneme.log')
                Write-Host (T 'Deneme bitti. Şimdi bir site açıp internetin normal çalıştığını kontrol edin.' 'Trial over. Now open a site and check that the internet works normally.') -ForegroundColor Green
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
    Write-Host ''
    Read-Host (T 'Menüye dönmek için Enter' 'Press Enter to return to the menu')
}
