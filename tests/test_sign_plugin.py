"""Testy tools/sign_plugin.py (schemat plugin.sig z klienta): python -m unittest discover -s tests

Zgodność z klientem: stały wektor poniżej został policzony przez `client/plugin_signature.py`. Dodatkowo, gdy zmienna
ADDONS_LOADER_SHARED wskazuje katalog z `plugin_signature.py` (kopia klienta), test sprawdza podpisy w obie strony.
"""
import base64
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import sign_plugin as sp  # noqa: E402

os.environ["SIGN_KEY_PASSWORD"] = "test-haslo"

# Wektor zgodności z klientem (seed = bajty 0..31, signed_at stałe).
WEKTOR_PUB = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
WEKTOR_KEY_ID = "56475aa75463474c"
WEKTOR_PODPIS = "vr/l46BYBxk/5mnCrbxfjCNWWa19JrlSt4CiN7TrH5P0KIhj3IPT3ldYJoNfI/Ik0Qfs+QbernI4Ajy4sxkTDg=="
CZAS = "2026-10-27T12:00:00Z"


def zbuduj_folder(korzen: Path, pliki=None) -> Path:
    """Folder Demo/ z logic.py i podkatalogiem."""
    pliki = {"logic.py": b"print('hi')\n", "sub/a.txt": b"x\n", **(pliki or {})}
    folder = Path(korzen) / "Demo"
    for rel, dane in pliki.items():
        cel = folder.joinpath(*rel.split("/"))
        cel.parent.mkdir(parents=True, exist_ok=True)
        cel.write_bytes(dane)
    return folder


def spakuj(folder: Path, zip_: Path, dodatkowe=()) -> Path:
    with zipfile.ZipFile(zip_, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                zi = zipfile.ZipInfo(f"{folder.name}/{p.relative_to(folder).as_posix()}", (2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(zi, p.read_bytes())
        for nazwa, dane, attr in dodatkowe:
            zi = zipfile.ZipInfo(nazwa, (2026, 1, 1, 0, 0, 0))
            zi.external_attr = attr
            z.writestr(zi, dane)
    return zip_


class Baza(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.folder = zbuduj_folder(self.d)
        self.out = self.d / "klucz"
        self.assertEqual(sp.main(["keygen", "--out", str(self.out)]), 0)
        self.pem = self.out.with_suffix(".pem")
        self.pub = self.out.with_suffix(".pub").read_text().strip()

    def tearDown(self):
        self.tmp.cleanup()

    def podpisz(self, folder=None, wersja="1.0.0"):
        return sp.main(["sign", str(folder or self.folder), "--key", str(self.pem), "--version", wersja])

    def poziom(self, cel=None, klucze=None):
        return sp.sprawdz(cel or self.folder, klucze or [self.pub])[0]


class TestZgodnoscZKlientem(Baza):
    def test_wektor(self):
        klucz = sp.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.assertEqual(sp.pub_b64(klucz), WEKTOR_PUB)
        self.assertEqual(sp.key_id(WEKTOR_PUB), WEKTOR_KEY_ID)
        sig = sp.sign_folder(self.folder, klucz, "Demo", "1.0.0", signed_at=CZAS)
        self.assertEqual(sig["signature"], WEKTOR_PODPIS)

    @unittest.skipUnless(os.environ.get("ADDONS_LOADER_SHARED"), "ustaw ADDONS_LOADER_SHARED na katalog z plugin_signature.py klienta")
    def test_wzajemna_weryfikacja_z_kodem_klienta(self):
        sys.path.insert(0, os.environ["ADDONS_LOADER_SHARED"])
        import plugin_signature as ps
        self.assertEqual(self.podpisz(), 0)
        wynik = ps.verify_folder(str(self.folder), [self.pub], expected_id="Demo")
        self.assertTrue(wynik.ok, wynik)
        klucz = sp.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        inny = zbuduj_folder(self.d / "k")
        ps.sign_folder(str(inny), klucz, "Demo", "1.0.0")
        self.assertIsNone(sp.verify_folder(inny, [WEKTOR_PUB], expected_id="Demo")[0])


class TestFolder(Baza):
    def test_niepodpisana(self):
        self.assertEqual(self.poziom(), 0)
        self.assertEqual(sp.main(["verify", str(self.folder), "--pub", self.pub]), 2)

    def test_podpisana(self):
        self.assertEqual(self.podpisz(), 0)
        self.assertEqual(self.poziom(), 2)
        self.assertEqual(sp.main(["verify", str(self.folder), "--pub", self.pub]), 0)

    def test_zmiany_po_podpisaniu(self):
        self.podpisz()
        (self.folder / "logic.py").write_bytes(b"print('hacked')\n")
        with self.assertRaises(sp.Blad):
            self.poziom()
        (self.folder / "logic.py").write_bytes(b"print('hi')\n")
        (self.folder / "extra.py").write_bytes(b"x=1\n")
        with self.assertRaises(sp.Blad):
            self.poziom()
        (self.folder / "extra.py").unlink()
        (self.folder / "sub" / "a.txt").unlink()
        with self.assertRaises(sp.Blad):
            self.poziom()

    def test_obcy_klucz(self):
        self.podpisz()
        with self.assertRaises(sp.Blad):
            self.poziom(klucze=[WEKTOR_PUB])

    def test_inna_nazwa_folderu(self):
        self.podpisz()
        kopia = self.d / "Inny"
        os.rename(self.folder, kopia)
        with self.assertRaises(sp.Blad):
            self.poziom(kopia)

    def test_podpis_skopiowany_do_innej_wtyczki(self):
        self.podpisz()
        inna = zbuduj_folder(self.d / "inna", {"logic.py": b"print('zlosliwy')\n"})
        (inna / sp.SIG_FILE).write_bytes((self.folder / sp.SIG_FILE).read_bytes())
        with self.assertRaises(sp.Blad):
            self.poziom(inna)

    def test_uszkodzony_plik_podpisu(self):
        for tresc in (b"nie json", b"[]", b'{"payload": {}, "signature": "x"}'):
            (self.folder / sp.SIG_FILE).write_bytes(tresc)
            with self.assertRaises(sp.Blad):
                self.poziom()

    def test_pycache_blokuje_podpisanie(self):
        (self.folder / "__pycache__").mkdir()
        (self.folder / "__pycache__" / "logic.cpython-312.pyc").write_bytes(b"\0")
        self.assertEqual(self.podpisz(), 1)

    def test_zla_wersja_i_id(self):
        self.assertEqual(self.podpisz(wersja="1.0"), 1)
        self.assertEqual(sp.main(["sign", str(self.folder), "--key", str(self.pem), "--version", "1.0.0", "--id", "../x"]), 1)

    def test_zle_haslo(self):
        os.environ["SIGN_KEY_PASSWORD"] = "inne"
        try:
            self.assertEqual(self.podpisz(), 1)
        finally:
            os.environ["SIGN_KEY_PASSWORD"] = "test-haslo"

    def test_keygen_nie_nadpisuje(self):
        self.assertEqual(sp.main(["keygen", "--out", str(self.out)]), 1)


class TestPaczka(Baza):
    def test_podpisana_paczka(self):
        self.podpisz()
        z = spakuj(self.folder, self.d / "Demo-1.0.0.zip")
        self.assertEqual(self.poziom(z), 2)
        self.assertEqual(sp.main(["verify", str(z), "--pub", self.pub]), 0)

    def test_niepodpisana_paczka(self):
        self.assertEqual(self.poziom(spakuj(self.folder, self.d / "Demo-1.0.0.zip")), 0)

    def test_wersja_w_nazwie_musi_zgadzac_sie_z_podpisem(self):
        self.podpisz(wersja="1.0.0")
        z = spakuj(self.folder, self.d / "Demo-1.0.1.zip")
        with self.assertRaises(sp.Blad):
            self.poziom(z)

    def test_zmieniona_paczka(self):
        self.podpisz()
        (self.folder / "logic.py").write_bytes(b"print('inny')\n")
        with self.assertRaises(sp.Blad):
            self.poziom(spakuj(self.folder, self.d / "Demo-1.0.0.zip"))

    def odrzuca(self, pliki=None, dodatkowe=(), nazwa="Demo-1.0.0.zip"):
        folder = zbuduj_folder(self.d / "p", pliki)
        z = spakuj(folder, self.d / nazwa, dodatkowe)
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(sp.Blad):
            sp.rozpakuj_paczke(z, tmp)

    def test_zip_slip(self):
        self.odrzuca(dodatkowe=[("Demo/../evil.py", b"x", 0o100644 << 16)])
        self.odrzuca(dodatkowe=[("/etc/passwd", b"x", 0o100644 << 16)])
        self.odrzuca(dodatkowe=[("Inny/x.py", b"x", 0o100644 << 16)])

    def test_dowiazanie_symboliczne(self):
        self.odrzuca(dodatkowe=[("Demo/link", b"logic.py", 0o120777 << 16)])

    def test_duplikat_wielkosc_liter(self):
        self.odrzuca(dodatkowe=[("Demo/LOGIC.PY", b"2", 0o100644 << 16)])

    def test_nazwy_zarezerwowane_i_niedozwolone(self):
        for nazwa in ("CON.txt", "NUL", "plik.", "a:b", "a b.py"):
            self.odrzuca(dodatkowe=[(f"Demo/{nazwa}", b"x", 0o100644 << 16)])

    def test_pyc_w_paczce(self):
        self.odrzuca(dodatkowe=[("Demo/__pycache__/logic.cpython-312.pyc", b"\0", 0o100644 << 16)])
        self.odrzuca(dodatkowe=[("Demo/stary.pyc", b"\0", 0o100644 << 16)])

    def test_limity(self):
        self.odrzuca(pliki={"duzy.bin": b"\0" * (sp.MAX_PLIK + 1)})
        self.odrzuca(pliki={f"p{i}.py": b"x" for i in range(sp.MAX_PLIKOW)})
        self.odrzuca(pliki={"bomba.bin": b"\0" * 1_000_000})

    def test_brak_logic_i_zla_nazwa_zip(self):
        z = self.d / "Demo-1.0.0.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Demo/plik.txt", b"x")
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(sp.Blad):
            sp.rozpakuj_paczke(z, tmp)
        self.odrzuca(nazwa="Inna-1.0.0.zip")


if __name__ == "__main__":
    unittest.main()
