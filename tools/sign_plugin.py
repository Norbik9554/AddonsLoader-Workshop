"""Podpisy wtyczek Workshopu — schemat klienta Addons Loader (plik `plugin.sig` w folderze wtyczki). Wymaga pakietu `cryptography`.

  python tools/sign_plugin.py keygen --out keys/test            # nowa para kluczy (właściciel ma już swój klucz — patrz docs/SIGNING.md)
  python tools/sign_plugin.py sign src/AutoLan --key keys/official.pem --version 1.0.1
  python tools/sign_plugin.py verify src/AutoLan --pub <klucz_publiczny_base64>        # folder
  python tools/sign_plugin.py verify plugins/AutoLan/AutoLan-1.0.1.zip --pub <...>     # gotowa paczka
  python tools/sign_plugin.py pubkey --key keys/official.pem

Algorytm jest identyczny z `client/plugin_signature.py` (Ed25519 po odcisku palca plików folderu, prefiks domenowy
`AddonsLoader-plugin-signature-v1`). Zmiana tutaj bez zmiany w kliencie (i odwrotnie) = podpisy przestają się zgadzać; pilnuje tego
test zgodności w tests/test_sign_plugin.py (wektor + opcjonalnie sprawdzenie z kopią klienta).

Hasło do klucza prywatnego: zmienna SIGN_KEY_PASSWORD albo pytanie w terminalu.
Kody wyjścia `verify`: 0 = podpis poprawny (oficjalna), 2 = brak plugin.sig (niepodpisana), 1 = podpis zły lub paczka niezgodna z zasadami.
"""
import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:
    sys.exit("Brak pakietu 'cryptography' (pip install cryptography).")

# ── Stałe zgodne z klientem (client/plugin_signature.py) ─────────────────────
SIG_FILE = "plugin.sig"
SCHEMA = 1
DOMAIN = b"AddonsLoader-plugin-signature-v1\n"
POMIJANE_KATALOGI = {"__pycache__"}
POMIJANE_ROZSZERZENIA = (".pyc", ".pyo")

# ── Zasady paczki ZIP (Workshop) ─────────────────────────────────────────────
MAX_PLIKOW, MAX_PLIK, MAX_RAZEM, MAX_STOSUNEK = 200, 5 * 1024 * 1024, 20 * 1024 * 1024, 100
RE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RE_WERSJA = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
RE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
ZARZADZONE = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}

# Przyczyny odrzucenia (te same kody co w kliencie).
PRZYCZYNY = {
    "uszkodzony_podpis": "plik plugin.sig jest uszkodzony",
    "nieznany_klucz": "podpis wykonano nieznanym kluczem",
    "zly_podpis": "podpis nie zgadza się z zawartością",
    "zla_nazwa": "folder ma inną nazwę niż podpisana wtyczka",
    "plik_zmieniony": "plik został zmieniony po podpisaniu",
    "dodatkowe_pliki": "w folderze jest plik, którego nie było przy podpisywaniu",
    "brakujace_pliki": "brakuje pliku, który był przy podpisywaniu",
    "niebezpieczne_pliki": "folder zawiera dowiązania symboliczne",
}


class Blad(Exception):
    """Błąd narzędzia lub weryfikacji (kod wyjścia 1)."""


# ── Rdzeń podpisu (kopia algorytmu z klienta) ────────────────────────────────
def iter_plugin_files(folder) -> list:
    """Ścieżki względne (posix) plików objętych podpisem. Pomija `plugin.sig` w korzeniu, `__pycache__` i `.pyc/.pyo`;
    dowiązania symboliczne są błędem."""
    korzen = os.path.abspath(folder)
    if not os.path.isdir(korzen):
        raise Blad(f"to nie jest folder: {folder}")
    wynik = []
    for katalog, podkatalogi, pliki in os.walk(korzen):
        podkatalogi[:] = sorted(d for d in podkatalogi if d not in POMIJANE_KATALOGI)
        for d in podkatalogi:
            if os.path.islink(os.path.join(katalog, d)):
                raise Blad(f"dowiązanie w folderze wtyczki: {d}")
        for n in sorted(pliki):
            sciezka = os.path.join(katalog, n)
            if n.lower().endswith(POMIJANE_ROZSZERZENIA) or (katalog == korzen and n == SIG_FILE):
                continue
            if os.path.islink(sciezka):
                raise Blad(f"dowiązanie w folderze wtyczki: {n}")
            wynik.append(os.path.relpath(sciezka, korzen).replace(os.sep, "/"))
    return sorted(wynik)


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for kawalek in iter(lambda: f.read(1024 * 1024), b""):
            h.update(kawalek)
    return h.hexdigest()


def hash_files(folder) -> dict:
    korzen = os.path.abspath(folder)
    return {rel: sha256_file(os.path.join(korzen, *rel.split("/"))) for rel in iter_plugin_files(folder)}


def canonical_bytes(payload: dict) -> bytes:
    return DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pub_b64(klucz: Ed25519PrivateKey) -> str:
    return base64.b64encode(klucz.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")


def key_id(public_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(public_b64)).hexdigest()[:16]


def teraz() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_payload(folder, plugin_id: str, version: str, name: str = "", publisher: str = "official", signed_at: str = None) -> dict:
    if not RE_ID.match(plugin_id or ""):
        raise Blad(f"niepoprawny identyfikator wtyczki: {plugin_id!r}")
    if not RE_WERSJA.match(version or ""):
        raise Blad(f"wersja musi mieć postać MAJOR.MINOR.PATCH: {version!r}")
    return {"schema": SCHEMA, "id": plugin_id, "name": name or plugin_id, "version": version, "publisher": publisher,
            "signed_at": signed_at or teraz(), "files": hash_files(folder)}


def sign_folder(folder, klucz: Ed25519PrivateKey, plugin_id: str, version: str, name: str = "", signed_at: str = None) -> dict:
    """Podpisuje folder i zapisuje `plugin.sig` w jego korzeniu (atomowo). Zwraca zawartość pliku."""
    korzen = Path(folder).resolve()
    # __pycache__ i .pyc nie wchodzą do podpisu, a Python mógłby je załadować — nie wolno ich mieć w źródłach wtyczki.
    for p in korzen.rglob("*"):
        if p.name in POMIJANE_KATALOGI or p.suffix.lower() in POMIJANE_ROZSZERZENIA:
            raise Blad(f"usuń przed podpisaniem (nie jest objęte podpisem): {p.relative_to(korzen).as_posix()}")
    payload = build_payload(korzen, plugin_id, version, name, signed_at=signed_at)
    pub = pub_b64(klucz)
    sig = {"payload": payload, "key_id": key_id(pub),
           "signature": base64.b64encode(klucz.sign(canonical_bytes(payload))).decode("ascii")}
    cel = korzen / SIG_FILE
    tmp = cel.with_name(SIG_FILE + ".tmp")
    tmp.write_text(json.dumps(sig, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, cel)
    return sig


def verify_folder(folder, klucze_pub_b64, expected_id: str = None):
    """Zwraca (None, payload) gdy podpis jest poprawny i pliki zgadzają się co do jednego; inaczej (kod_przyczyny, szczegół)."""
    try:
        with open(os.path.join(os.path.abspath(folder), SIG_FILE), "r", encoding="utf-8") as f:
            sig = json.load(f)
    except FileNotFoundError:
        return "brak_podpisu", ""
    except (OSError, ValueError):
        return "uszkodzony_podpis", ""
    if not isinstance(sig, dict) or not isinstance(sig.get("payload"), dict) or not isinstance(sig.get("signature"), str):
        return "uszkodzony_podpis", ""
    payload = sig["payload"]
    if payload.get("schema") != SCHEMA or not isinstance(payload.get("files"), dict) or not payload.get("id"):
        return "uszkodzony_podpis", ""
    try:
        podpis = base64.b64decode(sig["signature"], validate=True)
    except ValueError:
        return "uszkodzony_podpis", ""
    try:
        klucze = [k for k in klucze_pub_b64 if sig.get("key_id") in (None, key_id(k))]
    except ValueError:
        raise Blad("klucz publiczny nie jest poprawnym base64")
    if not klucze:
        return "nieznany_klucz", str(sig.get("key_id"))
    poprawny = False
    for k in klucze:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(podpis, canonical_bytes(payload))
            poprawny = True
            break
        except (InvalidSignature, ValueError):
            continue
    if not poprawny:
        return "zly_podpis", ""
    if expected_id is not None and payload["id"] != expected_id:
        return "zla_nazwa", f"podpis dla '{payload['id']}', folder '{expected_id}'"
    try:
        aktualne = hash_files(folder)
    except Blad as e:
        return "niebezpieczne_pliki", str(e)
    podpisane = payload["files"]
    dodatkowe = sorted(set(aktualne) - set(podpisane))
    if dodatkowe:
        return "dodatkowe_pliki", dodatkowe[0]
    brakujace = sorted(set(podpisane) - set(aktualne))
    if brakujace:
        return "brakujace_pliki", brakujace[0]
    for rel, sha in podpisane.items():
        if aktualne[rel] != sha:
            return "plik_zmieniony", rel
    return None, payload


# ── Paczka ZIP ───────────────────────────────────────────────────────────────
def rozpakuj_paczke(zip_path, cel) -> tuple:
    """Sprawdza zasady paczki PRZED zapisem czegokolwiek i rozpakowuje do `cel` (pusty katalog). Zwraca (id, wersja z nazwy pliku)."""
    zip_path = Path(zip_path)
    try:
        z = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as e:
        raise Blad(f"{zip_path.name}: nie jest poprawnym ZIP-em ({e})")
    with z:
        wpisy = z.infolist()
        if not wpisy or len(wpisy) > MAX_PLIKOW:
            raise Blad(f"liczba wpisów poza zakresem 1..{MAX_PLIKOW}")
        id_ = wpisy[0].filename.split("/")[0]
        if not RE_ID.match(id_):
            raise Blad(f"niepoprawny folder główny: {id_!r}")
        widziane, razem, doZapisu = set(), 0, []
        for zi in wpisy:
            nazwa = zi.filename
            if zi.flag_bits & 0x1:
                raise Blad(f"{nazwa}: wpis zaszyfrowany")
            if (zi.external_attr >> 16) & 0o170000 == 0o120000:
                raise Blad(f"{nazwa}: dowiązanie symboliczne")
            katalog = nazwa.endswith("/")
            czesci = nazwa.rstrip("/").split("/")
            if czesci[0] != id_:
                raise Blad(f"{nazwa}: wpis poza folderem {id_}/")
            wzgl = czesci[1:]
            for seg in wzgl:
                if not RE_SEGMENT.match(seg) or seg.endswith(".") or seg.split(".")[0].upper() in ZARZADZONE:
                    raise Blad(f"{nazwa}: niedozwolona nazwa ścieżki")
            if katalog:
                continue
            if not wzgl:
                raise Blad(f"{nazwa}: plik w miejscu folderu głównego")
            # Pliki, które podpis pomija, a Python mógłby załadować — w paczce zabronione.
            if any(s in POMIJANE_KATALOGI for s in wzgl[:-1]) or wzgl[-1].lower().endswith(POMIJANE_ROZSZERZENIA):
                raise Blad(f"{nazwa}: pliki .pyc/__pycache__ nie są dozwolone w paczce")
            rel = "/".join(wzgl)
            if rel.lower() in widziane:
                raise Blad(f"{nazwa}: duplikat nazwy (bez względu na wielkość liter)")
            widziane.add(rel.lower())
            if zi.file_size > MAX_PLIK:
                raise Blad(f"{nazwa}: plik większy niż {MAX_PLIK} B")
            if zi.compress_size and zi.file_size / zi.compress_size > MAX_STOSUNEK:
                raise Blad(f"{nazwa}: podejrzanie wysoki stopień kompresji")
            razem += zi.file_size
            if razem > MAX_RAZEM:
                raise Blad(f"suma rozmiarów większa niż {MAX_RAZEM} B")
            doZapisu.append((zi, rel))
        if "logic.py" not in widziane:
            raise Blad("w paczce musi być logic.py")
        korzen = Path(cel) / id_
        for zi, rel in doZapisu:
            plik = korzen.joinpath(*rel.split("/"))
            plik.parent.mkdir(parents=True, exist_ok=True)
            with z.open(zi) as f:
                dane = f.read(zi.file_size + 1)
            if len(dane) != zi.file_size:
                raise Blad(f"{zi.filename}: rozmiar niezgodny z nagłówkiem")
            plik.write_bytes(dane)
    m = re.fullmatch(r"(.+)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\.zip", zip_path.name)
    if not m or m.group(1) != id_:
        raise Blad(f"nazwa pliku powinna brzmieć {id_}-<wersja>.zip")
    return id_, m.group(2)


def sprawdz(cel, klucze) -> tuple:
    """Zwraca (poziom, opis): 2 = oficjalna, 0 = niepodpisana; zły podpis lub niezgodna paczka → Blad."""
    cel = Path(cel)
    if cel.is_file():
        with tempfile.TemporaryDirectory() as tmp:
            id_, wersja = rozpakuj_paczke(cel, tmp)
            folder = Path(tmp) / id_
            poziom, opis = _sprawdz_folder(folder, klucze, id_)
            if poziom == 2 and opis != wersja:
                raise Blad(f"wersja w podpisie ({opis}) różni się od wersji w nazwie paczki ({wersja})")
            return poziom, opis
    return _sprawdz_folder(cel, klucze, cel.resolve().name)


def _sprawdz_folder(folder, klucze, id_) -> tuple:
    przyczyna, szczegol = verify_folder(folder, klucze, expected_id=id_)
    if przyczyna is None:
        return 2, str(szczegol.get("version", ""))
    if przyczyna == "brak_podpisu":
        return 0, ""
    opis = PRZYCZYNY.get(przyczyna, przyczyna)
    raise Blad(f"{opis} ({szczegol})" if szczegol else opis)


# ── Klucze i polecenia ───────────────────────────────────────────────────────
def haslo(potwierdz: bool = False) -> bytes:
    h = os.environ.get("SIGN_KEY_PASSWORD")
    if h is None:
        h = getpass.getpass("Hasło do klucza: ")
        if potwierdz and getpass.getpass("Powtórz hasło: ") != h:
            raise Blad("hasła się różnią")
    if not h:
        raise Blad("puste hasło klucza jest niedozwolone")
    return h.encode("utf-8")


def wczytaj_klucz(sciezka) -> Ed25519PrivateKey:
    try:
        k = serialization.load_pem_private_key(Path(sciezka).read_bytes(), password=haslo())
    except (ValueError, TypeError, OSError) as e:
        raise Blad(f"nie można odczytać klucza (złe hasło lub plik): {e}")
    if not isinstance(k, Ed25519PrivateKey):
        raise Blad("klucz nie jest kluczem Ed25519")
    return k


def klucze_publiczne(a) -> list:
    klucze = list(a.pub or [])
    if a.pubfile:
        klucze += [l.strip() for l in Path(a.pubfile).read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    if not klucze:
        raise Blad("podaj --pub <base64> albo --pubfile <plik>")
    return klucze


def cmd_keygen(a) -> int:
    out = Path(a.out)
    pem, pub_plik = out.with_suffix(".pem"), out.with_suffix(".pub")
    if pem.exists() or pub_plik.exists():
        raise Blad(f"{pem} lub {pub_plik} już istnieje — nie nadpisuję")
    pem.parent.mkdir(parents=True, exist_ok=True)
    k = Ed25519PrivateKey.generate()
    pem_bajty = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(haslo(potwierdz=True)))
    fd = os.open(pem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem_bajty)
    pub = pub_b64(k)
    pub_plik.write_text(pub + "\n", encoding="utf-8")
    print(f"Klucz prywatny (zaszyfrowany): {pem}\nKlucz publiczny: {pub_plik}\nkey_id: {key_id(pub)}\nbase64: {pub}")
    print("UWAGA: zrób dwie kopie zapasowe pliku .pem i nigdy nie dodawaj go do repozytorium.")
    return 0


def cmd_sign(a) -> int:
    folder = Path(a.folder).resolve()
    plugin_id = a.id or folder.name
    sig = sign_folder(folder, wczytaj_klucz(a.key), plugin_id, a.version, a.name or "", a.signed_at)
    print(f"Podpisano '{plugin_id}' {a.version}: {len(sig['payload']['files'])} plików, klucz {sig['key_id']} → {folder / SIG_FILE}")
    return 0


def cmd_verify(a) -> int:
    poziom, wersja = sprawdz(a.cel, klucze_publiczne(a))
    if poziom == 0:
        print(f"{Path(a.cel).name}: niepodpisana")
        return 2
    print(f"{Path(a.cel).name}: oficjalna (wersja {wersja})")
    return 0


def cmd_pubkey(a) -> int:
    print(pub_b64(wczytaj_klucz(a.key)))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("keygen"); s.add_argument("--out", required=True); s.set_defaults(f=cmd_keygen)
    s = sub.add_parser("sign"); s.add_argument("folder"); s.add_argument("--key", required=True); s.add_argument("--version", required=True)
    s.add_argument("--id"); s.add_argument("--name"); s.add_argument("--signed-at", help="RRRR-MM-DDTHH:MM:SSZ (domyślnie teraz; do powtarzalnych testów)"); s.set_defaults(f=cmd_sign)
    s = sub.add_parser("verify"); s.add_argument("cel", help="folder wtyczki albo plik .zip")
    s.add_argument("--pub", action="append", help="zaufany klucz publiczny (base64), można podać kilka razy"); s.add_argument("--pubfile"); s.set_defaults(f=cmd_verify)
    s = sub.add_parser("pubkey"); s.add_argument("--key", required=True); s.set_defaults(f=cmd_pubkey)
    a = p.parse_args(argv)
    try:
        return a.f(a)
    except Blad as e:
        print(f"ZABLOKOWANA / BŁĄD: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
