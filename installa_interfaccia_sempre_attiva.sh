#!/bin/bash
# Avvia l'interfaccia in automatico all'accesso al Mac e la mantiene sempre attiva.
# Rimozione: ./installa_interfaccia_sempre_attiva.sh rimuovi
DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST="$HOME/Library/LaunchAgents/it.innovapuglia.interfaccia.plist"
if [ "$1" = "rimuovi" ]; then
  launchctl unload "$PLIST" 2>/dev/null; rm -f "$PLIST"; echo "Rimosso."; exit 0
fi
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>it.innovapuglia.interfaccia</string>
<key>ProgramArguments</key><array><string>$DIR/.venv/bin/python</string><string>$DIR/server.py</string><string>--no-browser</string></array>
<key>WorkingDirectory</key><string>$DIR</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
EOF
launchctl unload "$PLIST" 2>/dev/null; launchctl load "$PLIST"
echo "Interfaccia sempre attiva su http://$(ipconfig getifaddr en0 2>/dev/null || echo IP-DEL-MAC):8765"
