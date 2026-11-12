#!/usr/bin/env python3
"""Legge dati.xlsx e avvisa delle scadenze imminenti o scadute (notifica + finestra macOS)."""
import base64
import configparser
import subprocess
import sys
import tempfile
import urllib.request
from datetime import date, datetime
from pathlib import Path

from openpyxl import load_workbook

CARTELLA = Path(__file__).resolve().parent
FILE_SCELTO = CARTELLA / "excel_scelto.xlsx"  # copia del file scelto dall'interfaccia (ha la precedenza)
CONFIG = configparser.ConfigParser()
CONFIG.read(CARTELLA / "config.ini")
NC = CONFIG["nextcloud"] if CONFIG.has_section("nextcloud") else {}
GIORNI_PREAVVISO = CONFIG.getint("avvisi", "giorni_preavviso", fallback=15)


def trova_file():
    """Restituisce il percorso del file Excel (scelto dall'interfaccia, locale sincronizzato o scaricato da Nextcloud)."""
    if FILE_SCELTO.exists():
        return FILE_SCELTO
    locale = NC.get("percorso_locale", "").strip()
    if locale:
        return Path(locale).expanduser()
    url = NC.get("url", "").strip()
    if url:
        cred = f"{NC.get('utente', '')}:{NC.get('password_app', '')}".encode()
        req = urllib.request.Request(url, headers={"Authorization": "Basic " + base64.b64encode(cred).decode()})
        with urllib.request.urlopen(req, timeout=30) as r:
            tmp = Path(tempfile.gettempdir()) / "innovapuglia_dati.xlsx"
            tmp.write_bytes(r.read())
        return tmp
    return CARTELLA / "dati.xlsx"  # ripiego: file locale di esempio


def a_data(valore):
    if isinstance(valore, datetime):
        return valore.date()
    if isinstance(valore, date):
        return valore
    if isinstance(valore, str):
        for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(valore.strip(), fmt).date()
            except ValueError:
                pass
    return None


def leggi_scadenze(file_excel):
    ws = load_workbook(file_excel, data_only=True).active
    righe = list(ws.iter_rows(values_only=True))
    intestazioni = [str(c or "").strip().lower() for c in righe[0]]
    try:
        i_data = next(i for i, h in enumerate(intestazioni) if "scadenza" in h)
    except StopIteration:
        sys.exit("Nessuna colonna 'Scadenza' trovata nella prima riga di dati.xlsx")
    risultati = []
    for r in righe[1:]:
        d = a_data(r[i_data])
        if not d:
            continue
        stato = str(r[intestazioni.index("stato")] or "").lower() if "stato" in intestazioni else ""
        if stato in ("chiuso", "chiusa", "completato", "completata", "fatto"):
            continue
        descr = " - ".join(str(c) for i, c in enumerate(r) if i != i_data and c not in (None, ""))
        risultati.append((d, descr))
    return sorted(risultati)


def osa(script):
    subprocess.run(["osascript", "-e", script], check=False)


def main():
    try:
        file_excel = trova_file()
        if not file_excel.exists():
            raise FileNotFoundError(file_excel)
        scadenze = leggi_scadenze(file_excel)
    except Exception as e:
        msg = str(e).replace('"', "'")
        osa(f'display alert "Monitoraggio Certificati Sanità" message "Impossibile leggere il file: {msg}"')
        sys.exit(f"Errore: {e}")
    oggi = date.today()
    righe = []
    for d, descr in scadenze:
        delta = (d - oggi).days
        if delta > GIORNI_PREAVVISO:
            continue
        if delta < 0:
            quando = f"SCADUTA da {-delta} gg"
        elif delta == 0:
            quando = "OGGI"
        else:
            quando = f"tra {delta} gg"
        righe.append(f"{d:%d/%m/%Y} ({quando}): {descr}")
    if not righe:
        osa('display notification "Nessuna scadenza imminente." with title "Monitoraggio Certificati Sanità"')
        print("Nessuna scadenza imminente.")
        return
    testo = "\n".join(righe)
    print(testo)
    osa(f'display notification "{len(righe)} scadenze da controllare" with title "Monitoraggio Certificati Sanità" sound name "Glass"')
    esc = testo.replace("\\", "\\\\").replace('"', '\\"')
    osa(f'display dialog "{esc}" with title "Monitoraggio Certificati Sanità" buttons {{"OK"}} default button "OK" with icon caution')


if __name__ == "__main__":
    main()
