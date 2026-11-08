#!/usr/bin/env python3
"""Build the password-protected directors' copy of the Nexus Finance Desk.

Usage:
  python3 build.py --app <app.html> --snapshot <snapshot.json> --password <pw>

  --app       the Finance Desk page source (as published in Claude). It is inserted
              into shell.html, which supplies the password screen and a read-only
              stand-in for the data connection. Output: index.html
  --snapshot  the full data snapshot the app uploads ({"v":1,"at":...,"cols":{...},"docs":{...}}).
              It is encrypted with AES-256-GCM using a PBKDF2-SHA256 key (310,000 rounds).
              Output: data.enc.json, plus last_updated.txt holding the snapshot time.
Either input can be given alone to refresh just that part.
"""
import argparse, base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ITER = 310000
MARK = "<!--NEXUS-APP-->"

def build_page(app_path):
    app = open(app_path, encoding="utf-8").read()
    # A full document (doctype/html/head/body) would nest badly: keep only what is inside <body>, or the whole fragment.
    low = app.lower()
    if "<body" in low:
        start = low.index(">", low.index("<body")) + 1
        end = low.rfind("</body>")
        app = app[start:end if end > start else len(app)]
    if "window.claude" not in app or "COLS" not in app:
        sys.exit("that doesn't look like the Finance Desk page")
    shell = open(os.path.join(HERE, "shell.html"), encoding="utf-8").read()
    if shell.count(MARK) != 1:
        sys.exit("shell.html is missing the app marker")
    open(os.path.join(HERE, "index.html"), "w", encoding="utf-8").write(shell.replace(MARK, app))
    print(f"wrote index.html ({len(app):,} characters of app)")

def build_data(snap_path, pw):
    data = json.load(open(snap_path, encoding="utf-8"))
    if not isinstance(data, dict) or "cols" not in data or "banks" not in data["cols"]:
        sys.exit("snapshot is missing cols/banks")
    plain = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plain, None)
    b = lambda x: base64.b64encode(x).decode()
    json.dump({"v": 2, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}, open(os.path.join(HERE, "data.enc.json"), "w"))
    open(os.path.join(HERE, "last_updated.txt"), "w").write(data.get("at", ""))
    n = sum(len(v) for v in data["cols"].values())
    print(f"wrote data.enc.json ({len(ct):,} bytes, {n} records, as at {data.get('at','?')})")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app"); ap.add_argument("--snapshot"); ap.add_argument("--password")
    a = ap.parse_args()
    if not a.app and not a.snapshot:
        ap.error("give --app and/or --snapshot")
    if a.snapshot and not a.password:
        ap.error("--snapshot needs --password")
    if a.app: build_page(a.app)
    if a.snapshot: build_data(a.snapshot, a.password)
