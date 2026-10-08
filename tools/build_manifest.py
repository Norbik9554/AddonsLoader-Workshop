"""Buduje paczki wtyczek i manifest.json Workshopu (tylko biblioteka standardowa).

  python tools/build_manifest.py            # zbuduj paczki z src/<id>/ wg meta/<id>.json i zapisz manifest.json
  python tools/build_manifest.py --check    # sprawdź, czy manifest.json i paczki są aktualne (bez zapisu)

Układ: src/<id>/ = pliki wtyczki (jeśli jest plugin.sig, trafia do paczki), meta/<id>.json = opis, plugins/<id>/<id>-<wersja>.zip.
Paczka jest deterministyczna (stałe daty, posortowane pliki), więc ta sama zawartość = ta sama suma SHA-256.
Wtyczki oficjalne podpisz PRZED budową: python dev/plugin_signing/sign_plugin.py sign src/<id> --key <klucz> --version <wersja>.
"""
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BAZA_URL = "https://raw.githubusercontent.com/Norbik9554/AddonsLoader-Workshop/main/"
DATA_ZIP = (2026, 1, 1, 0, 0, 0)


def zbuduj(id_: str, wersja: str) -> bytes:
    import io
    bufor = io.BytesIO()
    zrodlo = ROOT / "src" / id_
    with zipfile.ZipFile(bufor, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(p for p in zrodlo.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"):
            zi = zipfile.ZipInfo(f"{id_}/{f.relative_to(zrodlo).as_posix()}", DATA_ZIP)
            zi.compress_type, zi.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            z.writestr(zi, f.read_bytes())
    return bufor.getvalue()


def main() -> int:
    a = argparse.ArgumentParser(); a.add_argument("--check", action="store_true"); arg = a.parse_args()
    wtyczki, rozbieznosci = [], []
    for meta in sorted((ROOT / "meta").glob("*.json")):
        m = json.loads(meta.read_text(encoding="utf-8"))
        id_, wersja = m["id"], m["version"]
        if meta.stem != id_ or not (ROOT / "src" / id_ / "logic.py").exists():
            sys.exit(f"{meta.name}: id musi równać się nazwie pliku, a src/{id_}/logic.py musi istnieć")
        dane = zbuduj(id_, wersja)
        rel = f"plugins/{id_}/{id_}-{wersja}.zip"
        cel = ROOT / rel
        if arg.check:
            if not cel.exists() or cel.read_bytes() != dane:
                rozbieznosci.append(rel)
        else:
            cel.parent.mkdir(parents=True, exist_ok=True); cel.write_bytes(dane)
        wtyczki.append({**m, "file": rel, "url": BAZA_URL + rel, "sha256": hashlib.sha256(dane).hexdigest(), "size": len(dane),
                        "signed": (ROOT / "src" / id_ / "plugin.sig").exists()})
    manifest = {"schema": 1, "plugins": wtyczki}
    tekst = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    if arg.check:
        if not (ROOT / "manifest.json").exists() or (ROOT / "manifest.json").read_text(encoding="utf-8") != tekst:
            rozbieznosci.append("manifest.json")
        print("AKTUALNE" if not rozbieznosci else "NIEAKTUALNE: " + ", ".join(rozbieznosci))
        return 1 if rozbieznosci else 0
    (ROOT / "manifest.json").write_text(tekst, encoding="utf-8")
    print(f"Zapisano manifest.json ({len(wtyczki)} wtyczek):", ", ".join(f"{w['id']} {w['version']}" for w in wtyczki))
    return 0


if __name__ == "__main__":
    sys.exit(main())
