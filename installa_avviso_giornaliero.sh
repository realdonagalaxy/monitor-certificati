#!/bin/bash
# Esegue il controllo ogni giorno alle 09:00 (launchd). Per rimuoverlo: ./installa_avviso_giornaliero.sh rimuovi
DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST="$HOME/Library/LaunchAgents/it.innovapuglia.scadenze.plist"
if [ "$1" = "rimuovi" ]; then
  launchctl unload "$PLIST" 2>/dev/null; rm -f "$PLIST"; echo "Rimosso."; exit 0
fi
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>it.innovapuglia.scadenze</string>
<key>ProgramArguments</key><array><string>$DIR/.venv/bin/python</string><string>$DIR/scadenze.py</string></array>
<key>StartCalendarInterval</key><dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
</dict></plist>
EOF
launchctl unload "$PLIST" 2>/dev/null; launchctl load "$PLIST"
echo "Installato: controllo ogni giorno alle 09:00."
