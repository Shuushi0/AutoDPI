# Emergency brake (Windows): stop everything autodpi started and show where
# traffic routes afterwards. Run in an elevated PowerShell, in the extracted
# folder (scripts\ in the source tree):
#   powershell -ExecutionPolicy Bypass -File .\restore-network.ps1
# Safe to run any time; touches only our own service and processes.
# Saved as UTF-8 with BOM so Windows PowerShell 5.1 reads the Turkish text.
$ErrorActionPreference = 'Continue'
# CommonApplicationData is C:\ProgramData from the shell, not from an environment variable a user could have set.
$support = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AutoDPI'

# Texts come in pairs, T 'Türkçe' 'English', in the language autodpi uses
# (AUTODPI_LANG, the settings, the display language); without the installed
# autodpi.exe the display language decides.
$script:TR = (Get-UICulture).TwoLetterISOLanguageName -eq 'tr'
$installed = Join-Path $support 'autodpi.exe'
if (Test-Path $installed) {
    $lang = & $installed lang 2>$null
    if ($lang) { $script:TR = "$lang".Trim() -eq 'tr' }
}
function T([string]$trText, [string]$enText) { if ($script:TR) { $trText } else { $enText } }

# Service recovery restarts the service 10 s after any exit that is not a clean
# stop, so force-killing it below would just bring the capture back. Turn the
# recovery actions off first (no actions, failure flag off); `autodpi install`
# sets them again.
# (cmd /c: Windows PowerShell 5.1 drops the empty actions= argument otherwise.)
cmd.exe /c 'sc.exe failure AutoDPI reset= 0 actions= ""' | Out-Null
sc.exe failureflag AutoDPI 0 | Out-Null

Stop-Service -Name AutoDPI -Force -ErrorAction SilentlyContinue
# Still alive (stuck in STOP_PENDING)? End the service process itself.
$q = sc.exe queryex AutoDPI | Select-String 'PID\s*:\s*(\d+)'
if ($q) {
    $svcPid = [int]$q.Matches[0].Groups[1].Value
    if ($svcPid -gt 0) { Stop-Process -Id $svcPid -Force -ErrorAction SilentlyContinue }
}
# A foreground "autodpi daemon" (trial) and helpers from the install dir.
Get-CimInstance Win32_Process -Filter "Name='autodpi.exe'" |
    Where-Object { $_.CommandLine -match '\sdaemon(\s|$)' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith("$support\bin\", 'OrdinalIgnoreCase') } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
# The wintun adapter, its routes and its DNS go away with sing-box; drop
# anything the TUN answered from the DNS client cache.
Clear-DnsClientCache

# The tray app (and its window) may stay: it does not touch the network, it
# only shows that the service is not running.
Write-Host (T 'kalan süreçler (boş olmalı; tepsi simgesi sayılmaz):' 'remaining processes (should be empty; the tray icon does not count):')
Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($support, 'OrdinalIgnoreCase') -and $_.ProcessName -ne 'autodpi-tray' } |
    Format-Table Id, Path
Write-Host (T 'servis kurtarma şimdi kapalı; "autodpi install" yeniden açar (servis açılışta yine başlar).' 'service recovery is now off; "autodpi install" turns it back on (the service still starts at boot).')
Write-Host (T '1.1.1.1 şu arayüzden çıkıyor:' '1.1.1.1 leaves through:')
Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty InterfaceAlias
