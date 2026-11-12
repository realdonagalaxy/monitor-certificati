#!/usr/bin/env python3
"""Interfaccia web locale: mostra URL, Common Name, scadenza e giorni residui dal file Excel.
Il file Excel viene solo LETTO, mai modificato."""
import base64
import os
import time
import hashlib
import io
import shutil
import tempfile
import hmac
import json
import re
import traceback
import socket
import subprocess
import sys
import threading
import zipfile
import webbrowser
from datetime import date, datetime, timedelta
from urllib.parse import quote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID, NameOID
from openpyxl import load_workbook
from openpyxl.utils import get_column_letter

from scadenze import CONFIG, FILE_SCELTO, NC, a_data, trova_file

CARTELLA = Path(__file__).resolve().parent
PORTA = 8765
CSR_DIR = CARTELLA / "csr"
CSR_MAX = 256 * 1024
ZIP_MAX = 10 * 1024 * 1024         # dimensione massima dello ZIP caricato
ZIP_ESTRATTO_MAX = 20 * 1024 * 1024  # dimensione massima complessiva dopo la decompressione
ZIP_FILE_MAX = 200                 # numero massimo di file letti
PASSWORD = CONFIG.get("accesso", "password", fallback="").strip()
DOMINIO_EMAIL = "@innova.puglia.it"
SESSIONE_GIORNI = 30
FILE_SEGRETO = CARTELLA / ".segreto_sessione"
TENTATIVI = {}  # ip -> (fallimenti, blocco_fino_a)


def registra_errore(contesto):
    """Scrive l'errore completo in errori.log (la risposta all'utente resta breve)."""
    try:
        with open(CARTELLA / "errori.log", "a", encoding="utf-8") as f:
            f.write(f"--- {datetime.now():%d/%m/%Y %H:%M:%S} {contesto}\n{traceback.format_exc()}\n")
    except OSError:
        pass


def segreto():
    if not FILE_SEGRETO.exists():
        FILE_SEGRETO.write_bytes(os.urandom(32))
        FILE_SEGRETO.chmod(0o600)
    return FILE_SEGRETO.read_bytes()


def crea_token_cert(nomi, scadenza):
    corpo = base64.urlsafe_b64encode(json.dumps({"n": nomi, "s": scadenza, "x": int(time.time()) + 7200}).encode()).decode()
    return f"{corpo}.{hmac.new(segreto(), b'cert' + corpo.encode(), hashlib.sha256).hexdigest()}"


def leggi_token_cert(token):
    try:
        corpo, firma = token.rsplit(".", 1)
        if not hmac.compare_digest(firma, hmac.new(segreto(), b"cert" + corpo.encode(), hashlib.sha256).hexdigest()):
            return None
        dati = json.loads(base64.urlsafe_b64decode(corpo))
        return dati if dati["x"] > time.time() else None
    except Exception:
        return None


def crea_token(email):
    corpo = base64.urlsafe_b64encode(json.dumps({"e": email, "x": int(time.time()) + SESSIONE_GIORNI * 86400}).encode()).decode()
    firma = hmac.new(segreto(), corpo.encode(), hashlib.sha256).hexdigest()
    return f"{corpo}.{firma}"


def leggi_token(token):
    try:
        corpo, firma = token.rsplit(".", 1)
        if not hmac.compare_digest(firma, hmac.new(segreto(), corpo.encode(), hashlib.sha256).hexdigest()):
            return None
        dati = json.loads(base64.urlsafe_b64decode(corpo))
        return dati["e"] if dati["x"] > time.time() else None
    except Exception:
        return None


def riga_id(foglio, progetto, url, cn):
    return hashlib.sha1("|".join((foglio, progetto, url, cn)).encode()).hexdigest()[:12]


def info_csr(rid):
    meta = CSR_DIR / f"{rid}.json"
    if meta.exists():
        try:
            return json.loads(meta.read_text())
        except ValueError:
            pass
    return None


ETICHETTE_SOGGETTO = [
    (NameOID.COMMON_NAME, "Common Name (CN)"), (NameOID.ORGANIZATION_NAME, "Organizzazione (O)"),
    (NameOID.ORGANIZATIONAL_UNIT_NAME, "Unità organizzativa (OU)"), (NameOID.LOCALITY_NAME, "Località (L)"),
    (NameOID.STATE_OR_PROVINCE_NAME, "Provincia / Stato (ST)"), (NameOID.COUNTRY_NAME, "Paese (C)"),
    (NameOID.EMAIL_ADDRESS, "Email"),
]


def interpreta_csr(testo_pem):
    csr = x509.load_pem_x509_csr(testo_pem.encode())
    soggetto = []
    for oid, etichetta in ETICHETTE_SOGGETTO:
        for a in csr.subject.get_attributes_for_oid(oid):
            soggetto.append({"campo": etichetta, "valore": str(a.value)})
    noti = {o for o, _ in ETICHETTE_SOGGETTO}
    for a in csr.subject:
        if a.oid not in noti:
            soggetto.append({"campo": a.oid.dotted_string, "valore": str(a.value)})
    san = []
    try:
        ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san = [{"tipo": "DNS", "valore": v} for v in ext.get_values_for_type(x509.DNSName)]
        san += [{"tipo": "IP", "valore": str(v)} for v in ext.get_values_for_type(x509.IPAddress)]
        san += [{"tipo": "Email", "valore": v} for v in ext.get_values_for_type(x509.RFC822Name)]
    except x509.ExtensionNotFound:
        pass
    chiave = csr.public_key()
    avvisi = []
    if isinstance(chiave, rsa.RSAPublicKey):
        tipo, bit = "RSA", chiave.key_size
        if bit < 2048:
            avvisi.append(f"Chiave RSA da {bit} bit: sotto il minimo consigliato di 2048 bit")
    elif isinstance(chiave, ec.EllipticCurvePublicKey):
        tipo, bit = f"ECDSA ({chiave.curve.name})", chiave.key_size
    elif isinstance(chiave, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        tipo, bit = "EdDSA", None
    else:
        tipo, bit = type(chiave).__name__, None
    try:
        algoritmo = csr.signature_hash_algorithm.name.upper() if csr.signature_hash_algorithm else "—"
    except Exception:
        algoritmo = "—"
    if algoritmo in ("SHA1", "MD5"):
        avvisi.append(f"Firma con {algoritmo}: algoritmo obsoleto")
    impronta = hashes.Hash(hashes.SHA256())
    impronta.update(chiave.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "common_name": cn[0].value if cn else "",
        "soggetto": soggetto, "san": san,
        "chiave": tipo, "bit": bit, "firma": algoritmo,
        "firma_valida": csr.is_signature_valid,
        "impronta": ":".join(f"{b:02X}" for b in impronta.finalize()),
        "avvisi": avvisi,
    }


BACKUP_DIR = CARTELLA / "backup_excel"
BACKUP_MAX = 30


def nome_dominio(t):
    return re.sub(r"\s*\(.*?\)\s*$", "", t or "").strip().lower()


def _percorso_sheet(z, titolo):
    wb_xml = z.read("xl/workbook.xml").decode("utf-8")
    rid = None
    for m in re.finditer(r"<sheet\b[^>]*>", wb_xml):
        tag = m.group(0)
        nome = re.search(r'name="([^"]*)"', tag)
        if nome and html_unescape(nome.group(1)).strip() == titolo.strip():
            rid = re.search(r'r:id="([^"]*)"', tag).group(1)
    if not rid:
        raise ValueError(f"Foglio '{titolo}' non trovato")
    rels = z.read("xl/_rels/workbook.xml.rels").decode("utf-8")
    for m in re.finditer(r"<Relationship\b[^>]*>", rels):
        if f'Id="{rid}"' in m.group(0):
            target = re.search(r'Target="([^"]*)"', m.group(0)).group(1)
            return target.lstrip("/") if target.startswith("/") else "xl/" + target
    raise ValueError("Percorso del foglio non trovato")


def html_unescape(t):
    return t.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'")


def _imposta_data(xml, ref, serial):
    """Sostituisce solo il valore della cella: stile e resto del file restano identici."""
    m = re.search(r'<c r="' + ref + r'"([^>]*?)(/>|>)', xml)
    if not m:
        raise ValueError(f"Cella {ref} non trovata nel file")
    attrs, chiusura = m.group(1), m.group(2)
    fine = m.end()
    if chiusura == ">":
        fine_c = xml.index("</c>", m.end()) + 4
        if "<f" in xml[m.end():fine_c]:
            raise ValueError(f"La cella {ref} contiene una formula: non la modifico")
        fine = fine_c
    attrs = re.sub(r'\st="[^"]*"', "", attrs)
    return xml[:m.start()] + f'<c r="{ref}"{attrs}><v>{serial}</v></c>' + xml[fine:]


def scrivi_date_excel(percorso, modifiche):
    """modifiche: lista di (titolo_foglio, cella, date). Crea un backup, modifica il file in modo chirurgico e lo sostituisce."""
    percorso = Path(percorso)
    blocco = percorso.parent / ("~$" + percorso.name)
    if blocco.exists():
        try:
            utente = blocco.read_bytes()[1:1 + blocco.read_bytes()[0]].decode("utf-8", "ignore").strip() if blocco.stat().st_size else ""
        except OSError:
            utente = ""
        raise ValueError("Il file Excel risulta aperto" + (f" da {utente}" if utente else "") +
                         ": salvalo e chiudilo in Excel, poi premi di nuovo Conferma")
    BACKUP_DIR.mkdir(exist_ok=True)
    backup = BACKUP_DIR / f"{percorso.stem}_{datetime.now():%Y%m%d_%H%M%S_%f}{percorso.suffix}"
    shutil.copy2(percorso, backup)
    for vecchio in sorted(BACKUP_DIR.glob(f"{percorso.stem}_*{percorso.suffix}"))[:-BACKUP_MAX]:
        vecchio.unlink()
    tmp = Path(tempfile.mkstemp(suffix=".xlsx", dir=percorso.parent)[1])
    try:
        with zipfile.ZipFile(percorso) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            fogli = {}
            for titolo, ref, d in modifiche:
                fogli.setdefault(_percorso_sheet(zin, titolo), []).append((ref, (d - date(1899, 12, 30)).days))
            for item in zin.infolist():
                dati = zin.read(item.filename)
                if item.filename in fogli:
                    xml = dati.decode("utf-8")
                    for ref, serial in fogli[item.filename]:
                        xml = _imposta_data(xml, ref, serial)
                    dati = xml.encode("utf-8")
                elif item.filename == "xl/workbook.xml":  # Excel ricalcola le formule (es. "16 gg prima") all'apertura
                    xml = dati.decode("utf-8")
                    if "<calcPr" in xml:
                        xml = re.sub(r"<calcPr\b([^>]*?)(/?)>", lambda m: "<calcPr" + re.sub(r'\sfullCalcOnLoad="[^"]*"', "", m.group(1)) + ' fullCalcOnLoad="1"' + m.group(2) + ">", xml, count=1)
                    else:
                        xml = xml.replace("</workbook>", '<calcPr fullCalcOnLoad="1"/></workbook>')
                    dati = xml.encode("utf-8")
                zout.writestr(item, dati)
        load_workbook(tmp).close()  # controllo che il file prodotto sia leggibile
        os.replace(tmp, percorso)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    return backup.name


def aggiorna_scadenze(token, ids):
    cert = leggi_token_cert(token)
    if not cert:
        raise ValueError("Verifica scaduta o non valida: ricarica lo ZIP")
    nuova = datetime.strptime(cert["s"], "%Y-%m-%d").date()
    if nuova < date.today():
        raise ValueError("Il certificato è scaduto")
    if not FILE_SCELTO.exists() and not NC.get("percorso_locale", "").strip():
        raise ValueError("Aggiornamento possibile solo con un file Excel locale (percorso_locale o file scelto)")
    nomi = {nome_dominio(n) for n in cert["n"]}
    gruppi = {r["id"]: r for r in leggi()["righe"]}
    scelti = []
    for i in ids:
        g = gruppi.get(i)
        if not g:
            raise ValueError("Certificato non trovato nel file: ricarica la pagina")
        if nome_dominio(g["common_name"]) not in nomi:
            raise ValueError(f"Il Common Name '{g['common_name']}' non corrisponde al certificato")
        scelti.append(g)
    righe_scelte = {(g["foglio"], n) for g in scelti for n in g["righe_excel"]}
    modifiche, bloccati, fatti = [], [], []
    viste = set()
    for g in scelti:
        for c in g["celle"]:
            if (g["foglio"], c["ref"]) in viste:
                continue
            fuori = [n for n in c["righe"] if (g["foglio"], n) not in righe_scelte]
            if fuori:
                altri = sorted({f"{x['progetto']} · {x['common_name']}" for x in gruppi.values()
                                if x["foglio"] == g["foglio"] and set(x["righe_excel"]) & set(fuori)})
                bloccati.append({"progetto": g["progetto"], "common_name": g["common_name"],
                                 "motivo": "La cella della scadenza è unita con altri certificati: " + "; ".join(altri) + ". Selezionali insieme oppure modificala a mano."})
                continue
            viste.add((g["foglio"], c["ref"]))
            modifiche.append((g["foglio"], c["ref"], nuova))
        fatti.append({"progetto": g["progetto"], "common_name": g["common_name"], "vecchia": g["scadenza"], "nuova": nuova.isoformat()})
    bloccati_nomi = {(b["progetto"], b["common_name"]) for b in bloccati}
    fatti = [f for f in fatti if (f["progetto"], f["common_name"]) not in bloccati_nomi]
    backup = scrivi_date_excel(trova_file(), modifiche) if modifiche else None
    return {"aggiornati": fatti, "bloccati": bloccati, "backup": backup}


def testo_mail(riga):
    dominio = re.sub(r"\s*\(.*?\)\s*$", "", riga["common_name"] or riga["url"]).strip()
    d = riga["scadenza"]
    data = "/".join(reversed(d.split("-"))) if d else "data da definire"
    oggetto = f"Richiesta CSR per il dominio {dominio}"
    corpo = (f"Buongiorno,\nil certificato del dominio {dominio} è in scadenza il {data}, "
             "pertanto si richiede la CSR per poter procedere al rinnovo.")
    return oggetto, corpo


def e_arancione(cella):
    """True se la cella ha uno sfondo arancione (colore del tema Office 'Accent 2' o tinta arancio)."""
    f = cella.fill
    if not f or f.fill_type != "solid":
        return False
    c = f.fgColor
    if c.type == "theme":
        return c.theme == 5 and abs(c.tint or 0) < 0.1
    if c.type == "rgb" and isinstance(c.rgb, str) and len(c.rgb) == 8:
        r, g, b = (int(c.rgb[i:i + 2], 16) for i in (2, 4, 6))
        mx, mn = max(r, g, b), min(r, g, b)
        if mx - mn < 60 or mx < 180:
            return False
        h = (60 * (g - b) / (mx - mn)) % 360 if mx == r else 999
        return 15 <= h <= 40
    return False


def raggruppa(righe):
    """Unisce le righe con stesso progetto e Common Name (stesso foglio): URL su più righe di testo."""
    gruppi, ordine = {}, []
    for r in righe:
        chiave = (r["foglio"], r["progetto"].lower(), r["common_name"].lower(), r["altro_ufficio"]) if r["common_name"] else (r["foglio"], r["id"])
        if chiave not in gruppi:
            gruppi[chiave] = []
            ordine.append(chiave)
        gruppi[chiave].append(r)

    def unici(rs, campo, sep):
        vals = []
        for r in rs:
            if r[campo] and r[campo] not in vals:
                vals.append(r[campo])
        return sep.join(vals)

    risultato = []
    for chiave in ordine:
        rs = gruppi[chiave]
        if len(rs) == 1:
            risultato.append(rs[0])
            continue
        con_data = [r for r in rs if r["scadenza"]]
        base = dict(min(con_data, key=lambda r: r["scadenza"]) if con_data else rs[0])
        for campo, sep in (("url", "\n"), ("progetto", ", "), ("tipo", ", "), ("pm", ", "),
                           ("fruitore", ", "), ("fornitore", ", "), ("csr_da", ", "), ("nota", "; ")):
            base[campo] = unici(rs, campo, sep)
        base["id"] = riga_id(base["foglio"], base["progetto"], "", base["common_name"])
        base["csr"] = info_csr(base["id"])
        base["righe"] = len(rs)
        base["righe_excel"] = sorted({n for r in rs for n in r["righe_excel"]})
        celle, viste = [], set()
        for r in rs:
            for c in r["celle"]:
                if c["ref"] not in viste:
                    viste.add(c["ref"])
                    celle.append(c)
        base["celle"] = celle
        altre = sorted({r["scadenza"] for r in rs if r["scadenza"]} - {base["scadenza"]})
        base["altre_date"] = altre
        risultato.append(base)
    return risultato


def _cert_da_bytes(dati):
    """Restituisce i certificati X.509 contenuti in un file (PEM, DER o PKCS#7). Le chiavi private vengono ignorate."""
    trovati = []
    if b"-----BEGIN CERTIFICATE-----" in dati:
        for blocco in re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", dati, re.S):
            try:
                trovati.append(x509.load_pem_x509_certificate(blocco))
            except ValueError:
                pass
        return trovati
    for caricatore in (x509.load_der_x509_certificate, pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            r = caricatore(dati)
            return r if isinstance(r, list) else [r]
        except Exception:
            continue
    return trovati


def _nome(nome, oid):
    v = nome.get_attributes_for_oid(oid)
    return v[0].value if v else ""


def certificati_da_zip(contenuto):
    risultati, oggi = [], datetime.utcnow()
    with zipfile.ZipFile(io.BytesIO(contenuto)) as z:
        voci = [i for i in z.infolist() if not i.is_dir()]
        if len(voci) > ZIP_FILE_MAX or sum(i.file_size for i in voci) > ZIP_ESTRATTO_MAX:
            raise ValueError("Lo ZIP contiene troppi file o è troppo grande una volta decompresso")
        for info in voci:
            nome_file = info.filename.rsplit("/", 1)[-1]
            if info.file_size > 2 * 1024 * 1024 or nome_file.startswith("."):
                continue
            for c in _cert_da_bytes(z.read(info)):
                try:
                    san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    san = []
                try:
                    is_ca = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
                except x509.ExtensionNotFound:
                    is_ca = False
                fine = c.not_valid_after_utc.replace(tzinfo=None)
                inizio = c.not_valid_before_utc.replace(tzinfo=None)
                risultati.append({
                    "file": info.filename,
                    "common_name": _nome(c.subject, NameOID.COMMON_NAME),
                    "san": san,
                    "emittente": _nome(c.issuer, NameOID.COMMON_NAME) or _nome(c.issuer, NameOID.ORGANIZATION_NAME),
                    "emissione": inizio.strftime("%Y-%m-%d"),
                    "scadenza": fine.strftime("%Y-%m-%d"),
                    "giorni": (fine.date() - oggi.date()).days,
                    "ca": is_ca,
                })
    unici = {}
    for r in risultati:  # lo stesso certificato può essere presente in più formati
        chiave = (r["common_name"], r["emissione"], r["scadenza"], r["emittente"])
        if chiave in unici:
            unici[chiave]["file"] += ", " + r["file"]
        else:
            unici[chiave] = r
    risultato = sorted(unici.values(), key=lambda r: (r["ca"], r["common_name"]))
    oggi_d = datetime.utcnow().strftime("%Y-%m-%d")
    for r in risultato:
        # "valido" = non scaduto, già in vigore, non è una CA. Solo i certificati validi ottengono il token per aggiornare l'Excel.
        r["valido"] = (not r["ca"]) and r["giorni"] >= 0 and r["emissione"] <= oggi_d
        if r["valido"]:
            r["token"] = crea_token_cert([r["common_name"], *r["san"]], r["scadenza"])
    return risultato


def testo(v):
    return " ".join(str(v).split()) if v not in (None, "") else ""


def leggi():
    file_excel = trova_file()
    wb = load_workbook(file_excel, data_only=True)
    oggi = date.today()
    righe = []
    for ws in wb.worksheets:
        rows = [list(r) for r in ws.iter_rows(values_only=True)]
        for rng in ws.merged_cells.ranges:  # le celle unite hanno il valore solo in alto a sinistra
            v = rows[rng.min_row - 1][rng.min_col - 1]
            for ri in range(rng.min_row - 1, rng.max_row):
                for ci in range(rng.min_col - 1, rng.max_col):
                    rows[ri][ci] = v
        if not rows:
            continue
        h = [testo(c).lower() for c in rows[0]]

        def col(*chiavi):
            return next((i for i, x in enumerate(h) if any(k in x for k in chiavi)), None)

        i_url, i_cn = col("url"), col("common name")
        i_sc, i_prog = col("scadenza"), col("progetto")
        celle_unite = {}  # riga -> (cella in alto a sinistra, righe coperte) per la colonna scadenza
        if i_sc is not None:
            for rng in ws.merged_cells.ranges:
                if rng.min_col <= i_sc + 1 <= rng.max_col:
                    ref = f"{get_column_letter(rng.min_col)}{rng.min_row}"
                    for ri in range(rng.min_row, rng.max_row + 1):
                        celle_unite[ri] = (ref, list(range(rng.min_row, rng.max_row + 1)))
        i_pm, i_tipo = col("pm innovapuglia"), col("tipo")
        i_fru, i_emi, i_for = col("fruitore"), col("emissione"), col("fornitore")
        i_csr = col("csr prodotta")

        def val(r, i):
            return testo(r[i]) if i is not None and i < len(r) else ""

        progetto_corr = ""
        for n_riga, r in enumerate(rows[1:], start=2):
            if not any(c not in (None, "") for c in r):
                continue
            altro = i_cn is not None and e_arancione(ws.cell(row=n_riga, column=i_cn + 1))
            if val(r, i_prog):
                progetto_corr = val(r, i_prog)  # celle unite: eredita il progetto sopra
            d = a_data(r[i_sc]) if i_sc is not None else None
            rid = riga_id(ws.title.strip(), progetto_corr, val(r, i_url), val(r, i_cn))
            righe.append({
                "id": rid,
                "csr": info_csr(rid),
                "csr_da": val(r, i_csr),
                "altro_ufficio": bool(altro),
                "righe_excel": [n_riga],
                "celle": ([{"ref": celle_unite.get(n_riga, (f"{get_column_letter(i_sc + 1)}{n_riga}", [n_riga]))[0],
                            "righe": celle_unite.get(n_riga, (None, [n_riga]))[1]}] if i_sc is not None else []),
                "nota": val(r, 8) if altro else "",
                "foglio": ws.title.strip(),
                "progetto": progetto_corr,
                "url": val(r, i_url),
                "common_name": val(r, i_cn),
                "tipo": val(r, i_tipo),
                "pm": val(r, i_pm),
                "fruitore": val(r, i_fru),
                "fornitore": val(r, i_for),
                "emissione": (a_data(r[i_emi]).isoformat() if i_emi is not None and a_data(r[i_emi]) else None),
                "scadenza": d.isoformat() if d else None,
                "giorni": (d - oggi).days if d else None,
            })
    modificato = datetime.fromtimestamp(Path(file_excel).stat().st_mtime).strftime("%d/%m/%Y %H:%M")
    righe = raggruppa(righe)
    return {"scelto": FILE_SCELTO.exists(), "file": Path(file_excel).name, "modificato": modificato, "aggiornato": datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "righe": righe}


EXCEL_MAX = 20 * 1024 * 1024


def leggi_riassunto():
    d = leggi()
    return {"file": d["file"], "righe": len(d["righe"])}


def ip_lan():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect(("10.255.255.255", 1))
            return sk.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class H(BaseHTTPRequestHandler):
    def utente(self):
        for voce in self.headers.get("Cookie", "").split(";"):
            nome, _, valore = voce.strip().partition("=")
            if nome == "sessione":
                return leggi_token(valore)
        return None

    def autorizzato(self):
        return not PASSWORD or self.utente() is not None

    def pagina(self, nome, tipo):
        corpo = (CARTELLA / nome).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Cache-Control", "no-store" if tipo.startswith("text/html") else "max-age=3600")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def login(self):
        ip = self.client_address[0]
        fallimenti, blocco = TENTATIVI.get(ip, (0, 0))
        if blocco > time.time():
            return self.rispondi(429, {"errore": f"Troppi tentativi. Riprova tra {int(blocco - time.time()) + 1} secondi."})
        try:
            dati = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)))
            email, password = str(dati.get("email", "")).strip().lower(), str(dati.get("password", ""))
        except (ValueError, AttributeError):
            return self.rispondi(400, {"errore": "Richiesta non valida"})
        if not re.fullmatch(r"[a-z0-9._%+\-]+" + re.escape(DOMINIO_EMAIL), email):
            return self.rispondi(400, {"errore": f"Usa la tua email aziendale ({DOMINIO_EMAIL})"})
        if not hmac.compare_digest(password.encode(), PASSWORD.encode()):
            fallimenti += 1
            TENTATIVI[ip] = (fallimenti, time.time() + 60 if fallimenti >= 5 else 0)
            if fallimenti >= 5:
                TENTATIVI[ip] = (0, time.time() + 60)
            return self.rispondi(401, {"errore": "Credenziali non corrette"})
        TENTATIVI.pop(ip, None)
        corpo = json.dumps({"ok": True, "email": email}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", f"sessione={crea_token(email)}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSIONE_GIORNI * 86400}")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def logout(self):
        corpo = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "sessione=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        percorso = self.path.split("?")[0]
        if percorso == "/logo.jpg":
            return self.pagina("logo.jpg", "image/jpeg")
        if percorso == "/login":
            if self.autorizzato():
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self.pagina("login.html", "text/html; charset=utf-8")
        if percorso == "/api/utente":
            return self.rispondi(200, {"email": self.utente() or ""}) if self.autorizzato() else self.nega()
        if not self.autorizzato():
            return self.nega()
        mi = re.fullmatch(r"/api/csr/([0-9a-f]{12})/info", self.path.split("?")[0])
        if mi:
            f = CSR_DIR / f"{mi.group(1)}.csr"
            if not f.exists():
                return self.rispondi(404, {"errore": "CSR non trovata"})
            try:
                return self.rispondi(200, interpreta_csr(f.read_text()))
            except ValueError:
                return self.rispondi(422, {"errore": "Impossibile interpretare il contenuto della CSR"})
        mc = re.fullmatch(r"/api/csr/([0-9a-f]{12})", self.path.split("?")[0])
        if mc and (CSR_DIR / f"{mc.group(1)}.csr").exists():
            meta = info_csr(mc.group(1)) or {"nome": "richiesta.csr"}
            corpo = (CSR_DIR / f"{mc.group(1)}.csr").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{meta["nome"]}"')
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)
            return
        if self.path.startswith("/api/dati"):
            try:
                corpo, tipo, cod = json.dumps(leggi()).encode(), "application/json", 200
            except Exception as e:
                corpo, tipo, cod = json.dumps({"errore": str(e)}).encode(), "application/json", 500
        elif self.path in ("/", "/index.html"):
            corpo, tipo, cod = (CARTELLA / "index.html").read_bytes(), "text/html; charset=utf-8", 200
        else:
            corpo, tipo, cod = b"not found", "text/plain", 404
        self.send_response(cod)
        self.send_header("Content-Type", tipo)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def rispondi(self, cod, obj):
        corpo = json.dumps(obj).encode()
        self.send_response(cod)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def nega(self):
        if self.command == "GET" and self.path.split("?")[0] in ("/", "/index.html"):
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.rispondi(401, {"errore": "Sessione scaduta: accedi di nuovo"})

    def do_POST(self):
        if self.path.split("?")[0] == "/api/login":
            return self.login()
        if self.path.split("?")[0] == "/api/logout":
            return self.logout()
        if not self.autorizzato():
            return self.nega()
        if self.path.split("?")[0] == "/api/excel/scadenza":
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 65536)
                dati = json.loads(self.rfile.read(n))
                if not isinstance(dati.get("ids"), list) or not dati["ids"]:
                    raise ValueError("Nessun certificato selezionato")
                return self.rispondi(200, aggiorna_scadenze(str(dati.get("token", "")), [str(i) for i in dati["ids"]]))
            except ValueError as e:
                return self.rispondi(400, {"errore": str(e) or "Errore durante l'aggiornamento"})
            except PermissionError as e:
                registra_errore("aggiornamento Excel")
                return self.rispondi(500, {"errore": f"Il Mac non permette di scrivere il file ({e.filename}). Controlla i permessi della cartella Nextcloud."})
            except Exception as e:
                registra_errore("aggiornamento Excel")
                return self.rispondi(500, {"errore": f"Errore durante il salvataggio ({type(e).__name__}: {e}). Dettagli in errori.log"})
        if self.path.split("?")[0] == "/api/excel/scegli":
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > EXCEL_MAX:
                return self.rispondi(413, {"errore": "File vuoto o troppo grande (max 20 MB)"})
            corpo = self.rfile.read(n)
            tmp = FILE_SCELTO.with_suffix(".tmp")
            try:
                tmp.write_bytes(corpo)
                load_workbook(tmp, data_only=True).close()  # deve essere un .xlsx valido
            except Exception:
                tmp.unlink(missing_ok=True)
                return self.rispondi(400, {"errore": "Il file non è un Excel .xlsx valido"})
            tmp.replace(FILE_SCELTO)
            try:
                return self.rispondi(200, leggi_riassunto())
            except Exception as e:
                FILE_SCELTO.unlink(missing_ok=True)
                return self.rispondi(400, {"errore": f"Il file non ha il formato atteso: {e}"})
        if self.path.split("?")[0] == "/api/zip":
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > ZIP_MAX:
                return self.rispondi(413, {"errore": "File vuoto o troppo grande (max 10 MB)"})
            try:
                certs = certificati_da_zip(self.rfile.read(n))
            except zipfile.BadZipFile:
                return self.rispondi(400, {"errore": "Il file non è uno ZIP valido"})
            except ValueError as e:
                return self.rispondi(400, {"errore": str(e)})
            except NotImplementedError:
                return self.rispondi(400, {"errore": "ZIP protetto da password o con compressione non supportata"})
            if not certs:
                return self.rispondi(404, {"errore": "Nessun certificato trovato nello ZIP"})
            return self.rispondi(200, {"certificati": certs})
        mo = re.fullmatch(r"/api/outlook/([0-9a-f]{12})", self.path.split("?")[0])
        if mo:
            if self.client_address[0] not in ("127.0.0.1", "::1", ip_lan()):
                return self.rispondi(403, {"errore": "Disponibile solo dal Mac"})
            riga = next((r for r in leggi()["righe"] if r["id"] == mo.group(1)), None)
            if not riga:
                return self.rispondi(404, {"errore": "riga non trovata"})
            oggetto, corpo = testo_mail(riga)
            url = f"mailto:?subject={quote(oggetto)}&body={quote(corpo)}"
            subprocess.run(["open", "-a", "Microsoft Outlook", url], check=False)
            return self.rispondi(200, {"ok": True})
        m = re.fullmatch(r"/api/csr/([0-9a-f]{12})", self.path.split("?")[0])
        if not m:
            return self.rispondi(404, {"errore": "non trovato"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > CSR_MAX:
            return self.rispondi(413, {"errore": "File vuoto o troppo grande (max 256 KB)"})
        contenuto = self.rfile.read(n).decode("utf-8", "replace")
        if "BEGIN CERTIFICATE REQUEST" not in contenuto and "BEGIN NEW CERTIFICATE REQUEST" not in contenuto:
            return self.rispondi(400, {"errore": "Il file non sembra una CSR (manca l'intestazione PEM)"})
        nome = re.sub(r"[^\w.\- ]", "_", self.headers.get("X-Nome-File", "richiesta.csr"))[:80]
        CSR_DIR.mkdir(exist_ok=True)
        rid = m.group(1)
        try:
            ricevuta = datetime.strptime(self.headers.get("X-Data-Ricezione", ""), "%Y-%m-%d").strftime("%d/%m/%Y")
        except ValueError:
            return self.rispondi(400, {"errore": "Data di ricezione non valida"})
        meta = {"nome": nome, "data": datetime.now().strftime("%d/%m/%Y %H:%M"), "ricevuta": ricevuta}
        (CSR_DIR / f"{rid}.csr").write_text(contenuto)
        (CSR_DIR / f"{rid}.json").write_text(json.dumps(meta))
        self.rispondi(200, meta)

    def do_DELETE(self):
        if not self.autorizzato():
            return self.nega()
        if self.path.split("?")[0] == "/api/excel/scegli":
            FILE_SCELTO.unlink(missing_ok=True)  # torna al file di config.ini
            return self.rispondi(200, {"ok": True})
        m = re.fullmatch(r"/api/csr/([0-9a-f]{12})", self.path.split("?")[0])
        if not m:
            return self.rispondi(404, {"errore": "non trovato"})
        for ext in ("csr", "json"):
            (CSR_DIR / f"{m.group(1)}.{ext}").unlink(missing_ok=True)
        self.rispondi(200, {"ok": True})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORTA), H)
    print(f"Sul Mac:      http://127.0.0.1:{PORTA}")
    print(f"Da cellulare: http://{ip_lan()}:{PORTA}  (stessa rete Wi-Fi)")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.7, lambda: webbrowser.open(f"http://127.0.0.1:{PORTA}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
