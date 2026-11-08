#!/usr/bin/env python3
"""Encrypt the directors' summary for the password-protected page.

Usage: python3 build.py <summary.json> <password> [out=data.enc.json]

summary.json is the "sync/directors" record from the Nexus Finance Desk app.
Output is AES-256-GCM with a PBKDF2-SHA256 key (310,000 rounds), matching index.html.
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 310000

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    src, pw = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.enc.json")
    data = json.load(open(src, encoding="utf-8"))
    if isinstance(data, dict) and "data" in data and "banks" not in data:
        data = data["data"]  # accept a raw database document too
    for k in ("banks", "recv", "pay", "projects"):
        if k not in data:
            sys.exit(f"summary is missing '{k}'")
    plain = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plain, None)
    b = lambda x: base64.b64encode(x).decode()
    json.dump({"v": 1, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}, open(out, "w"))
    print(f"wrote {out} ({len(ct)} bytes, as at {data.get('updatedAt', '?')})")

if __name__ == "__main__":
    main()
