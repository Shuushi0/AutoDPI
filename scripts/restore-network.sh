#!/bin/bash
# Emergency brake: stop everything autodpi started and show where traffic
# routes afterwards. Safe to run any time; touches only our own processes.
set -u
SUPPORT="/Library/Application Support/AutoDPI"

# Texts come in pairs, t 'Türkçe' 'English', in the language autodpi uses
# (AUTODPI_LANG, the settings, the system's); without the installed binary
# AUTODPI_LANG or the locale decides.
LNG=$("$SUPPORT/autodpi" lang 2>/dev/null)
if [ -z "$LNG" ]; then
  case "${AUTODPI_LANG:-${LC_ALL:-${LANG:-}}}" in tr*|TR*) LNG=tr ;; *) LNG=en ;; esac
fi
t() { if [ "$LNG" = tr ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }

sudo launchctl bootout system/com.autodpi.daemon 2>/dev/null
sudo pkill -f "autodpi daemon" 2>/dev/null   # installed copy or a foreground trial
sudo pkill -f "autodpi guard" 2>/dev/null
sudo pkill -9 -f "$SUPPORT/bin/" 2>/dev/null
sleep 1
# A daemon that died holding the system resolver left the original here.
SAVED="$SUPPORT/dns-saved.json"
if sudo test -f "$SAVED"; then
  svc=$(sudo plutil -extract service raw -o - "$SAVED")
  servers=$(sudo plutil -extract servers json -o - "$SAVED" 2>/dev/null | tr ',' ' ' | tr -d '[]"')
  sudo networksetup -setdnsservers "$svc" ${servers:-Empty} && sudo rm -f "$SAVED"
  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
  t "DNS geri yüklendi: $svc -> ${servers:-DHCP}" "DNS restored: $svc -> ${servers:-DHCP}"
fi
# What the brake stops: the daemon, its guard, the helpers. The menu bar app
# and a settings page may stay; they do not touch the network.
t "kalan süreçler (boş olmalı):" "remaining processes (should be empty):"
pgrep -fl "autodpi (daemon|guard)|$SUPPORT/bin/" || true
t "1.1.1.1 şu arayüzden çıkıyor:" "1.1.1.1 leaves through:"
route -n get 1.1.1.1 2>/dev/null | grep interface
