"""
EDUROAM AUTORENEW v2 jako wtyczka Addons Loader — JEDEN PLIK (klasyczna, API 2.0), te same funkcje co program
eduroam_autorenew.py: licznik i stan, toasty przed końcem, automatyczne odnowienie (rozłączenie Proton VPN → portal →
nowa data wygaśnięcia → połączenie VPN), ręczne sterowanie VPN, budzik, diagnostyka, sprzątanie kart portalu.

Różnice względem programu (wynikają z piaskownicy wtyczek: bez subprocess/PowerShell/Playwright):
  • logowanie w portalu zwykłymi żądaniami HTTP (bez przeglądarki); gdy się nie uda — okno otwiera portal w przeglądarce;
  • informacje o sieci: psutil + wmi; klik w Protona: UI Automation (comtypes); adres IP: iphlpapi; budzik: COM Harmonogramu.

NOWE (analiza tego, co mogło zatrzymać automat): nadzór nad Protonem (zawieszony / niezaładowany / niespójny klient → restart
klienta), rozłączanie VPN z weryfikacją (Proton potrafi połączyć się sam), kill switch po rozłączeniu, brak hasła sprawdzany
przed ruszeniem VPN, globalny limit czasu odnawiania, wykrywanie wybudzenia z uśpienia, pauza po serii porażek, zapasowe adresy
sondy, kontrola sensowności daty z portalu.

Hasło jest w Menedżerze poświadczeń (okno i backend czytają je ctypes) i nigdy nie przechodzi przez komunikaty Loadera.
"""

PLUGIN_API_VERSION = "2.0"

import ctypes
import html
import json
import multiprocessing
import queue
import re
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QDateTime, QProcess, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (QApplication, QCheckBox, QDateTimeEdit, QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout)

from plugin_core import BasePlugin

PLUGIN_ID = "eduroam_autorenew"
FORMAT_DATY = "%Y-%m-%d %H:%M:%S"
TYK_S = 5.0                      # co ile backend sprawdza sieć i wysyła stan do okna
POWTORZ_USTAWIEN_S = 30.0        # okno może wystartować później niż backend
HEARTBEAT_CO_S = 5.0
POWIADOMIENIA_MIN = (10, 5, 2, 1)
RENEW_DEADLINE_S = 900           # globalny limit czasu jednego odnawiania
FAIL_BACKOFF_AFTER, FAIL_BACKOFF_S, COOLDOWN_S = 3, 1800, 180
PRZED_WYGASNIECIEM_S = 20        # tyle s przed końcem sesji rozłączamy VPN, żeby portal był od razu po wygaśnięciu
TYK_BLISKO_S = 2.0               # szybsza sonda w pobliżu wygaśnięcia (±2 min)
WAKE_GAP_S = 90                  # przerwa w pętli dłuższa niż to = komputer spał
PROTON_UI_UNKNOWN_S = 30         # tyle s okno Protona bez przycisków Połącz/Rozłącz = zawieszenie
PROBE_URL, PROBE_OK = "http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"
REDIRECT_URL = "http://www.msftconnecttest.com/redirect"
PROBE_FALLBACKS = (("http://detectportal.firefox.com/success.txt", "success"), ("http://clients3.google.com/generate_204", ""))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
EXPIRY_RE = re.compile(r"(?:wyrejestrowania|deregist\w*|expires?)[^0-9]{0,20}(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", re.I)
BAD_LOGIN_RE = re.compile(r"invalid login or password|nieprawid\w+\s+(?:login|has[łl]o|nazw)|incorrect (?:user|pass)", re.I)
SEKRET_RE = re.compile(r"pass|pwd|has[lł]o", re.I)
STRICT_TAB_RE = re.compile(r"username/password login", re.I)
OKNO_PRZEGLADARKI_RE = re.compile(r"google chrome|microsoft.{0,3}edge|brave|opera|vivaldi|chromium", re.I)   # przeglądarki Chromium
ID_ROZLACZ, ID_POLACZ, ID_POMIN = "ConnectionCardDisconnectButton", "ConnectionCardConnectButton", "CloseButton"
ZADANIE = "EduroamAutoRenew-Watch"
KLIENT_PROTONA = "protonvpn.client.exe"
DOMYSLNE = {"access_hours": 3, "notify_min": list(POWIADOMIENIA_MIN), "lead_min": 15,
            "campus_prefixes": ["172.30."], "campus_gateways": [], "auto": True, "budzik": False,
            "wait_after_vpn_s": 10, "portal_wait_s": 60, "portal_hosty": ["packetfence"]}
_TEKST, _AKCENT, _OK, _OSTRZ, _BLAD, _SZARY = "#c9d1d9", "#58a6ff", "#3fb950", "#d29922", "#f85149", "#8b949e"


# =============================================================================================
#  DANE SZYFROWANE (Windows DPAPI): login, hasło i data wygaśnięcia — używa okno i backend
#  Pliki leżą w osobnym folderze wtyczki: client\plugin_data\<nazwa wtyczki>\ (poswiadczenia.dat, stan.dat).
#  Odczyt jest możliwy tylko na tym koncie Windows i tym komputerze. Hasło i login nie przechodzą przez komunikaty
#  Loadera (te trafiają do jego logów), a data wygaśnięcia w komunikatach jest szyfrowana.
# =============================================================================================
_ENTROPIA = b"EduroamAutoRenew-v2"


class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _do_blobu(dane: bytes):
    bufor = (ctypes.c_ubyte * max(1, len(dane))).from_buffer_copy(dane or b"\0")
    return _BLOB(len(dane), ctypes.cast(bufor, ctypes.POINTER(ctypes.c_ubyte))), bufor


def dpapi_szyfruj(tekst: str) -> bytes:
    wej, _b1 = _do_blobu(tekst.encode("utf-8"))
    ent, _b2 = _do_blobu(_ENTROPIA)
    wyj = _BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(wej), "EduroamAutoRenew", ctypes.byref(ent), None, None, 0,
                                                  ctypes.byref(wyj)):
        raise OSError("CryptProtectData")
    try:
        return ctypes.string_at(wyj.pbData, wyj.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(wyj.pbData)


def dpapi_odszyfruj(dane: bytes):
    if not dane:
        return None
    wej, _b1 = _do_blobu(dane)
    ent, _b2 = _do_blobu(_ENTROPIA)
    wyj = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(wej), None, ctypes.byref(ent), None, None, 0, ctypes.byref(wyj)):
        return None
    try:
        return ctypes.string_at(wyj.pbData, wyj.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(wyj.pbData)


def katalog_danych() -> Path:
    """Osobny folder wtyczki: client/plugin_data/<nazwa> (obok katalogu plugins); w trybie deweloperskim: obok pliku."""
    tu = Path(__file__).resolve().parent
    katalog = (tu.parent.parent / "plugin_data" / tu.name) if tu.parent.name.lower() == "plugins" else (tu / "plugin_data")
    katalog.mkdir(parents=True, exist_ok=True)
    return katalog


def _czytaj_szyfrowany(nazwa: str):
    try:
        surowe = (katalog_danych() / nazwa).read_bytes()
    except OSError:
        return None
    tekst = dpapi_odszyfruj(surowe)
    try:
        return json.loads(tekst) if tekst else None
    except ValueError:
        return None


def _zapisz_szyfrowany(nazwa: str, dane: dict) -> bool:
    try:
        plik = katalog_danych() / nazwa
        tmp = plik.with_suffix(".tmp")
        tmp.write_bytes(dpapi_szyfruj(json.dumps(dane, ensure_ascii=False)))
        tmp.replace(plik)                                                    # zapis atomowy
        return True
    except OSError:
        return False


def poswiadczenia_odczyt() -> dict:
    d = _czytaj_szyfrowany("poswiadczenia.dat") or {}
    return {"login": str(d.get("login") or ""), "haslo": d.get("haslo") or None}


def poswiadczenia_zapisz(login=None, haslo=None) -> bool:
    """None = zostaw dotychczasową wartość."""
    teraz = poswiadczenia_odczyt()
    return _zapisz_szyfrowany("poswiadczenia.dat", {"login": teraz["login"] if login is None else login,
                                                    "haslo": teraz["haslo"] if haslo is None else haslo})


def _szyfruj_hex(tekst: str) -> str:
    return dpapi_szyfruj(tekst).hex()


def _odszyfruj_hex(hex_tekst):
    try:
        return dpapi_odszyfruj(bytes.fromhex(hex_tekst)) if hex_tekst else None
    except ValueError:
        return None


# --- jednorazowa migracja z poprzedniej wersji (Menedżer poświadczeń Windows) ---------------------
class _FILETIME(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


class _CRED(ctypes.Structure):
    _fields_ = [("Flags", ctypes.c_uint32), ("Type", ctypes.c_uint32), ("TargetName", ctypes.c_wchar_p),
                ("Comment", ctypes.c_wchar_p), ("LastWritten", _FILETIME), ("CredentialBlobSize", ctypes.c_uint32),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", ctypes.c_uint32),
                ("AttributeCount", ctypes.c_uint32), ("Attributes", ctypes.c_void_p), ("TargetAlias", ctypes.c_wchar_p),
                ("UserName", ctypes.c_wchar_p)]


def _cred_czytaj(cel: str):
    p = ctypes.POINTER(_CRED)()
    if not ctypes.windll.advapi32.CredReadW(cel, 1, 0, ctypes.byref(p)):
        return None
    try:
        c = p.contents
        return ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le")
    finally:
        ctypes.windll.advapi32.CredFree(p)


def migruj_poswiadczenia() -> bool:
    """Jeśli nie ma jeszcze poswiadczenia.dat, przenosi login i hasło z Menedżera poświadczeń (stary program/wtyczka)."""
    if (katalog_danych() / "poswiadczenia.dat").exists():
        return False
    haslo = _cred_czytaj("EduroamAutoRenew:password") or _cred_czytaj("password@EduroamAutoRenew")
    login = _cred_czytaj("username@EduroamAutoRenew") or ""
    if not (haslo or login):
        return False
    return _zapisz_szyfrowany("poswiadczenia.dat", {"login": login, "haslo": haslo})


def _otworz_portal_w_przegladarce(url: str) -> None:
    """Otwiera adres w Chrome (jeśli jest zainstalowany) — to w nim wtyczka potrafi sterować kartą; domyślna przeglądarka
    systemu bywa niedziałającym Edge (wtedy zwykłe otwarcie adresu nic nie robi). Bez Chrome: domyślna przeglądarka."""
    for baza in ("C:/Program Files/Google/Chrome/Application", "C:/Program Files (x86)/Google/Chrome/Application"):
        exe = Path(baza) / "chrome.exe"
        if exe.exists():
            QProcess.startDetached(str(exe), [url])
            return
    QDesktopServices.openUrl(QUrl(url))


def _znajdz_klienta_protona():
    for baza in ("C:/Program Files/Proton/VPN", "C:/Program Files (x86)/Proton/VPN"):
        znalezione = sorted(Path(baza).glob("*/ProtonVPN.Client.exe"))
        if znalezione:
            return znalezione[-1]
    return None


# =============================================================================================
#  CZĘŚĆ 1: OKNO (proces GUI Loadera — tylko Qt i biblioteka standardowa)
# =============================================================================================
class EduroamWidget(QFrame):
    action_requested = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        from config import is_ghost_flash_debug_enabled          # ochrona przed miganiem okna przy osadzaniu
        if not is_ghost_flash_debug_enabled():
            self.setGeometry(-32000, -32000, 1, 1)
            self.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
            self.setWindowFlags(Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint)

        self.setObjectName("EduroamRamka")
        self.setStyleSheet(
            "#EduroamRamka { background: transparent; border: none; }"
            f"QLabel {{ color: {_TEKST}; font-family: 'Segoe UI'; }}"
            f"QPushButton {{ background: #21262d; color: {_TEKST}; border: 1px solid #30363d; border-radius: 5px;"
            " padding: 3px 8px; }"
            f"QPushButton:hover {{ border-color: {_AKCENT}; }} QPushButton:disabled {{ color: #484f58; }}"
            f"QLineEdit, QDateTimeEdit {{ background: #0d1117; color: {_TEKST}; border: 1px solid #30363d; border-radius: 4px; }}"
            f"QCheckBox {{ color: {_TEKST}; }}"
            f"QPlainTextEdit {{ background: #0d1117; color: {_TEKST}; border: 1px solid #30363d; font-family: Consolas;"
            " font-size: 11px; }")
        self._wygasa = None
        self._edytor_pusty = True                                             # edytor daty jeszcze nie dostał zapisanej daty
        self._edytor_daty_ostatnia = None
        self._odnawia = False
        self._kampus = None
        self._stan_sieci = "?"
        self._notify_min = sorted(POWIADOMIENIA_MIN, reverse=True)
        self._zbuduj()
        self._odswiez_dane()
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tykniecie)
        self._timer.start()
        self._tykniecie()

    # --- budowa ------------------------------------------------------------------------------
    @staticmethod
    def _styl_banera(kolor: str) -> str:
        return f"font-size: 14px; font-weight: bold; padding: 6px; border-radius: 6px; color: white; background: {kolor};"

    def _zbuduj(self):
        uklad = QVBoxLayout(self)
        uklad.setContentsMargins(14, 24, 14, 12)
        uklad.setSpacing(6)
        self._baner = QLabel("Łączę z backendem…")
        self._baner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._baner.setStyleSheet(self._styl_banera(_SZARY))
        uklad.addWidget(self._baner)
        self._licznik = QLabel("--:--:--")
        self._licznik.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._licznik.setFont(QFont("Consolas", 34, QFont.Weight.Bold))
        uklad.addWidget(self._licznik)

        info = QGridLayout()
        info.setHorizontalSpacing(10)
        self._pola = {}
        for i, (klucz, etykieta) in enumerate((
                ("internet", "Internet"), ("vpn", "Proton VPN"), ("proton", "Klient Proton"), ("kampus", "Sieć uczelni"),
                ("karta", "Karta"), ("wygasa", "Dostęp wygasa"), ("ostatnie", "Ostatnie odnowienie"),
                ("nastepne", "Następny toast"))):
            nazwa = QLabel(etykieta + ":")
            nazwa.setStyleSheet(f"color: {_SZARY};")
            wartosc = QLabel("—")
            wartosc.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._pola[klucz] = wartosc
            info.addWidget(nazwa, i, 0, Qt.AlignmentFlag.AlignRight)
            info.addWidget(wartosc, i, 1)
        info.setColumnStretch(1, 1)
        uklad.addLayout(info)

        konto = QGridLayout()
        self._login = QLineEdit(placeholderText="Login")
        self._haslo = QLineEdit(placeholderText="Hasło (zapisywane szyfrowane, DPAPI)")
        self._haslo.setEchoMode(QLineEdit.EchoMode.Password)
        self._pokaz = QPushButton("Pokaż")
        self._pokaz.setCheckable(True)
        self._pokaz.toggled.connect(self._przelacz_haslo)
        zapisz = QPushButton("Zapisz dane")
        zapisz.clicked.connect(lambda _=False: self._zapisz_dane())
        konto.addWidget(self._login, 0, 0, 1, 2)
        konto.addWidget(self._haslo, 1, 0)
        konto.addWidget(self._pokaz, 1, 1)
        konto.addWidget(zapisz, 0, 2, 2, 1)
        konto.setColumnStretch(0, 1)
        uklad.addLayout(konto)

        sesja = QHBoxLayout()
        self._edytor_daty = QDateTimeEdit(QDateTime.currentDateTime().addSecs(3 * 3600))
        self._edytor_daty.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._edytor_daty.setCalendarPopup(True)
        ustaw = QPushButton("Ustaw wygaśnięcie")
        ustaw.clicked.connect(lambda _=False: self.action_requested.emit(
            {"action": "set_expiry", "value": self._edytor_daty.dateTime().toString("yyyy-MM-dd HH:mm:ss")}))
        sesja.addWidget(self._edytor_daty, 1)
        sesja.addWidget(ustaw)
        uklad.addLayout(sesja)

        opcje = QHBoxLayout()
        self._auto = QCheckBox("Odnawiaj automatycznie")
        self._auto.setChecked(True)
        self._auto.clicked.connect(lambda on: self.action_requested.emit({"action": "set_settings", "auto": bool(on)}))
        self._budzik = QCheckBox("Budź z uśpienia przed końcem")
        self._budzik.setToolTip("Zadanie w Harmonogramie zadań tylko BUDZI komputer 15 min przed końcem sesji "
                                "(nie uruchamia drugiego Loadera) — Loader musi być uruchomiony")
        self._budzik.clicked.connect(self._przelacz_budzik)
        opcje.addWidget(self._auto)
        opcje.addWidget(self._budzik)
        uklad.addLayout(opcje)

        przyciski = QHBoxLayout()
        self._b_portal = QPushButton("Otwórz portal")
        self._b_portal.clicked.connect(lambda _=False: self._otworz_portal())
        for etykieta, funkcja in (("Odnów teraz", lambda: self.action_requested.emit({"action": "renew"})),
                                  ("Połącz / rozłącz VPN", lambda: self.action_requested.emit({"action": "vpn_toggle"})),
                                  ("Napraw Protona", lambda: self.action_requested.emit({"action": "fix_proton"})),
                                  ("Diagnostyka", lambda: self.action_requested.emit({"action": "diag"})),
                                  ("Test toastu", lambda: self.action_requested.emit({"action": "toast_test"}))):
            p = QPushButton(etykieta)
            p.clicked.connect(lambda _=False, f=funkcja: f())
            przyciski.addWidget(p)
        przyciski.addWidget(self._b_portal)
        uklad.addLayout(przyciski)

        self._log = QPlainTextEdit(readOnly=True)
        self._log.setMaximumBlockCount(500)
        uklad.addWidget(self._log, 1)

    # --- licznik i baner (lokalnie, co sekundę) -----------------------------------------------
    def _tykniecie(self):
        zostalo = (self._wygasa - datetime.now()).total_seconds() if self._wygasa else None
        if zostalo is None:
            self._licznik.setText("--:--:--")
            self._licznik.setStyleSheet(f"color: {_SZARY};")
        else:
            godz, reszta = divmod(abs(int(zostalo)), 3600)
            self._licznik.setText(f"{'-' if zostalo < 0 else ''}{godz}:{reszta // 60:02d}:{reszta % 60:02d}")
            self._licznik.setStyleSheet(f"color: {_OK if zostalo > 600 else (_OSTRZ if zostalo > 120 else _BLAD)};")
        if self._odnawia:
            tekst, kolor = "ODNAWIANIE DOSTĘPU…", _OSTRZ
        elif self._kampus is False:
            tekst, kolor = "POZA SIECIĄ UCZELNI — wtyczka nic nie robi", _SZARY
        elif zostalo is None:
            tekst, kolor = "Czas wygaśnięcia nieznany — ustaw go albo poczekaj na odnowienie", _SZARY
        elif zostalo <= 0:
            tekst, kolor = "SESJA WYGASŁA", _BLAD
        elif zostalo <= 120:
            tekst, kolor = "Sesja kończy się za chwilę", _BLAD
        elif zostalo <= 600:
            tekst, kolor = "Sesja kończy się", _OSTRZ
        else:
            tekst, kolor = "Sesja LAN aktywna", _OK
        self._baner.setText(tekst)
        self._baner.setStyleSheet(self._styl_banera(kolor))
        if zostalo is not None and zostalo > 0:
            dalsze = [t for t in self._notify_min if zostalo > t * 60]
            nastepny = f"za {int((zostalo - dalsze[0] * 60) // 60)} min ({dalsze[0]} min przed końcem)" if dalsze else "—"
        else:
            nastepny = "—"
        self._pola["nastepne"].setText(nastepny)
        self._pola["wygasa"].setText(f"{self._wygasa:{FORMAT_DATY}}" if self._wygasa else "—")

    # --- akcje okna -----------------------------------------------------------------------------
    def _odswiez_dane(self):
        """Login i informacja o haśle z szyfrowanego pliku (odczyt w procesie GUI — nie idzie przez logi Loadera)."""
        d = poswiadczenia_odczyt()
        if not self._login.hasFocus() and not self._login.text():
            self._login.setText(d["login"])
        self._haslo.setPlaceholderText("Hasło zapisane (szyfrowane) — wpisz nowe, aby zmienić" if d["haslo"]
                                       else "Hasło (zapisywane szyfrowane, DPAPI)")

    def _przelacz_haslo(self, pokaz: bool):
        if pokaz and not self._haslo.text():
            self._haslo.setText(poswiadczenia_odczyt()["haslo"] or "")
        self._haslo.setEchoMode(QLineEdit.EchoMode.Normal if pokaz else QLineEdit.EchoMode.Password)
        self._pokaz.setText("Ukryj" if pokaz else "Pokaż")

    def _zapisz_dane(self):
        ok = poswiadczenia_zapisz(login=self._login.text().strip(), haslo=self._haslo.text() or None)
        self._dopisz("login i hasło zapisane szyfrowane (DPAPI) w folderze plugin_data wtyczki" if ok
                     else "NIE udało się zapisać danych", _OK if ok else _BLAD)
        if self._haslo.text() and not self._pokaz.isChecked():
            self._haslo.clear()
        self._odswiez_dane()

    def _przelacz_budzik(self, wlacz: bool):
        self.action_requested.emit({"action": "wake", "on": bool(wlacz)})

    def _otworz_portal(self):
        """Portal pojawia się dopiero po wygaśnięciu (przy działającym dostępie Microsoft odsyła na msn.com)."""
        if self._stan_sieci == "ONLINE":
            self._dopisz("Dostęp do sieci jest już pełny — portal logowania nie jest potrzebny")
            return
        _otworz_portal_w_przegladarce(REDIRECT_URL)

    def _pokaz_toast(self, tekst: str, poziom: str = "info") -> bool:
        """Powiadomienie w samym Loaderze (jego toast + Centrum Powiadomień) — bez własnego ikonki w zasobniku."""
        kolor = {"ok": "#2ecc71", "warn": "#f9e2af", "bad": "#f38ba8"}.get(poziom, "#89b4fa")
        for w in QApplication.topLevelWidgets():
            if hasattr(w, "show_toast") and hasattr(w, "notification_history"):
                try:
                    w.show_toast(tekst, kolor, "info")
                    return True
                except Exception:                                            # noqa: BLE001
                    return False
        return False

    def _dopisz(self, tekst: str, kolor: str = _TEKST):
        self._log.appendHtml(f"<span style='color:{kolor}'>{time.strftime('%H:%M:%S')}&nbsp; {html.escape(tekst)}</span>")

    # --- backend -> okno ------------------------------------------------------------------------
    def update_data(self, data_str):
        try:
            dane = json.loads(data_str)
        except (TypeError, ValueError):
            return
        if not isinstance(dane, dict):
            return
        typ = dane.get("type")
        if typ in (None, "heartbeat", "sandbox_info"):
            return
        if typ == "tick":
            self._zastosuj_tick(dane)
        elif typ == "settings":
            self._zastosuj_ustawienia(dane)
        elif typ == "proton":
            ok = dane.get("stan") == "ok"
            self._pola["proton"].setText(f"<span style='color:{_OK if ok else _BLAD}'>{html.escape(str(dane.get('stan')))}</span>"
                                         f" — {html.escape(str(dane.get('opis', ''))[:80])}")
        elif typ == "log":
            self._dopisz(str(dane.get("msg", ""))[:300])
        elif typ == "toast":
            self._pokaz_toast(str(dane.get("text", ""))[:200], str(dane.get("poziom", "info")))
            self._dopisz(f"powiadomienie: {dane.get('text', '')}"[:300], _AKCENT)
        elif typ == "renewing":
            self._odnawia = bool(dane.get("on"))
            self._tykniecie()
        elif typ == "launch_proton":
            exe = _znajdz_klienta_protona()
            if exe is not None:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(exe)))   # aktywuje/uruchamia klienta (backend nie może)
        elif typ == "open_portal":
            _otworz_portal_w_przegladarce(REDIRECT_URL)                  # ręczne logowanie / karta dla sterowania w Chrome

    def _zastosuj_tick(self, d: dict):
        st = str(d.get("stan", "?"))
        self._stan_sieci, self._kampus, self._odnawia = st, d.get("kampus"), bool(d.get("odnawia"))
        kolor = {"ONLINE": _OK, "PORTAL": _OSTRZ}.get(st, _BLAD)
        self._pola["internet"].setText(f"<span style='color:{kolor}'>{html.escape(st)}</span>")
        self._pola["vpn"].setText("<span style='color:%s'>%s</span>" % (_OK if d.get("vpn") else _SZARY,
                                                                        "połączony" if d.get("vpn") else "rozłączony"))
        self._pola["kampus"].setText("tak" if d.get("kampus") else "nie")
        self._pola["karta"].setText(f"{d.get('alias') or '—'} · {d.get('ip') or '—'} · brama {d.get('gw') or '—'}")
        self._pola["ostatnie"].setText(str(d.get("ostatnie") or "—"))
        self._b_portal.setEnabled(st != "ONLINE")
        self._b_portal.setToolTip("Dostęp jest już pełny — portal pojawi się po wygaśnięciu" if st == "ONLINE" else "")
        try:                                                                 # data wygaśnięcia przychodzi zaszyfrowana
            tekst = _odszyfruj_hex(d.get("wygasa_enc"))
            self._wygasa = datetime.strptime(tekst, FORMAT_DATY) if tekst else None
        except (TypeError, ValueError):
            self._wygasa = None
        if self._wygasa and (self._edytor_pusty or self._edytor_daty_ostatnia != self._wygasa):
            if not self._edytor_daty.hasFocus():                              # nie nadpisuj pola, które ktoś właśnie edytuje
                self._edytor_daty.setDateTime(QDateTime(self._wygasa.year, self._wygasa.month, self._wygasa.day,
                                                        self._wygasa.hour, self._wygasa.minute, self._wygasa.second))
                self._edytor_pusty = False
                self._edytor_daty_ostatnia = self._wygasa
        self._tykniecie()

    def _zastosuj_ustawienia(self, d: dict):
        self._odswiez_dane()
        self._auto.setChecked(bool(d.get("auto", True)))
        self._budzik.setChecked(bool(d.get("budzik", False)))
        przekroczone = d.get("notify_min")
        if isinstance(przekroczone, list) and przekroczone:
            self._notify_min = sorted((int(x) for x in przekroczone if isinstance(x, (int, float))), reverse=True)


# =============================================================================================
#  CZĘŚĆ 2: WTYCZKA + BACKEND (piaskownica; importy ciężkich bibliotek leniwie, w funkcjach)
# =============================================================================================
class EduroamWtyczka(BasePlugin):
    @staticmethod
    def get_config():
        return {
            "name": "AutoLan v1",
            "plugin_id": PLUGIN_ID,
            "category": "Sieć",
            "description": "Pilnuje 3-godzinnego dostępu LAN (PacketFence): licznik, toasty 10/5/2/1 min, automatyczne "
                           "odnowienie z rozłączeniem i połączeniem Proton VPN, nadzór nad zawieszonym klientem Protona. "
                           "Używa ctypes, psutil, wmi, comtypes, urllib (żółte ostrzeżenia skanera).",
            "author": "AutoLan",
            "version": "1.0.0",
            "width": 7,
            "height": 9,
            "network": True,
            "depends_on": [],
            "widget_class": EduroamWidget,
        }

    def init_ui(self):
        return EduroamWidget()

    # ----------------------------------------------------------------------------------------
    #  pliki, komunikacja, COM
    # ----------------------------------------------------------------------------------------
    @staticmethod
    def _katalog() -> Path:
        return katalog_danych()

    def _wczytaj_json(self, nazwa: str, domyslne: dict) -> dict:
        try:
            plik = self._katalog() / nazwa
            if plik.is_file():
                dane = json.loads(plik.read_text(encoding="utf-8"))
                if isinstance(dane, dict):
                    return {**domyslne, **dane}
        except (OSError, ValueError) as e:
            self.send_error(f"{PLUGIN_ID}: nie wczytano {nazwa} ({e})")
        return dict(domyslne)

    def _zapisz_json(self, nazwa: str, dane: dict) -> None:
        try:
            plik = self._katalog() / nazwa
            tmp = plik.with_suffix(".tmp")
            tmp.write_text(json.dumps(dane, ensure_ascii=False, indent=1), encoding="utf-8")
            tmp.replace(plik)                                                # zapis atomowy
        except OSError as e:
            self.send_error(f"{PLUGIN_ID}: nie zapisano {nazwa} ({e})")

    def _wyslij(self, dane: dict) -> None:
        with self._blokada_wyjscia:                                          # jedna linia = jeden komunikat, także z wątków
            self.send_to_gui(dane)

    def _log(self, msg) -> None:
        self._wyslij({"type": "log", "msg": str(msg)[:300]})

    def _toast(self, tekst: str, poziom: str = "info") -> None:
        self._log(f"Powiadomienie: {tekst}")
        self._wyslij({"type": "toast", "text": tekst, "poziom": poziom})

    def _wyslij_ustawienia(self) -> None:
        c = self.cfg
        self._wyslij({"type": "settings", "auto": c["auto"], "budzik": c["budzik"],
                      "notify_min": c["notify_min"], "lead_min": c["lead_min"]})

    @staticmethod
    def _com_init() -> list:
        zainicjowane = []
        for modul in ("pythoncom", "comtypes"):                              # COM trzeba zainicjować w każdym wątku
            try:
                __import__(modul).CoInitialize()
                zainicjowane.append(modul)
            except Exception:                                                # noqa: BLE001
                pass
        return zainicjowane

    @staticmethod
    def _com_zwolnij(zainicjowane: list) -> None:
        """Obiekty COM zwalniamy PRZED końcem wątku (inaczej stderr: „Win32 exception … releasing IUnknown”, a Loader
        traktuje stderr jako błąd)."""
        import gc
        gc.collect()
        for modul in reversed(zainicjowane):
            try:
                __import__(modul).CoUninitialize()
            except Exception:                                                # noqa: BLE001
                pass

    def _w_watku(self, funkcja, *args) -> None:
        def praca():
            com = self._com_init()
            try:
                funkcja(*args)
            except Exception as e:                                           # noqa: BLE001
                self.send_error(f"{PLUGIN_ID}: {funkcja.__name__}: {type(e).__name__}: {str(e)[:200]}")
                self._log(f"BŁĄD: {type(e).__name__}: {str(e)[:150]}")
            finally:
                self._com_zwolnij(com)
        threading.Thread(target=praca, daemon=True).start()

    def _z_limitem(self, fn, sekundy: float, domyslnie=None):
        """Wywołanie, które nie może zawiesić backendu (UI Automation na zawieszonym kliencie potrafi nie wrócić)."""
        pudelko: dict = {}

        def praca():
            com = self._com_init()
            try:
                pudelko["v"] = fn()
            except Exception as e:                                           # noqa: BLE001
                pudelko["e"] = e
            finally:
                self._com_zwolnij(com)
        t = threading.Thread(target=praca, daemon=True)
        t.start()
        t.join(sekundy)
        return pudelko.get("v", domyslnie)

    # ----------------------------------------------------------------------------------------
    #  sieć: sonda (z zapasowymi adresami), karty, adres IP
    # ----------------------------------------------------------------------------------------
    @staticmethod
    def _http_get(url: str, timeout: float = 4.0) -> dict:
        import http.client
        import urllib.parse
        parts = urllib.parse.urlsplit(url)
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
        try:
            conn.request("GET", (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
                         headers={"Host": parts.hostname, "User-Agent": UA, "Connection": "close"})
            r = conn.getresponse()
            return {"status": r.status, "location": r.getheader("Location"),
                    "body": r.read(100_000).decode("utf-8", "replace")}
        except (OSError, http.client.HTTPException) as e:
            return {"error": f"{type(e).__name__}: {e}"}
        finally:
            conn.close()

    def _probe(self) -> str:
        """ONLINE / PORTAL / OFFLINE / BLOKADA_VPN. Gdy główny adres nie odpowiada, pytamy zapasowe — chwilowa awaria
        jednego serwera nie wywołuje fałszywego odnawiania."""
        r = self._http_get(PROBE_URL)
        if r.get("error"):
            if "10013" in r["error"]:
                return "BLOKADA_VPN"
            for url, oczekiwana in PROBE_FALLBACKS:
                z = self._http_get(url)
                if z.get("error"):
                    continue
                if z["status"] == 204 or (oczekiwana and z["body"].strip() == oczekiwana):
                    return "ONLINE"
                if 300 <= z["status"] < 400:
                    return "PORTAL"
            return "OFFLINE"
        if r["status"] == 200 and r["body"].strip() == PROBE_OK:
            return "ONLINE"
        return "PORTAL" if 300 <= r["status"] < 400 or r["status"] in (200, 511) else "OFFLINE"

    def _czekaj_na_stan(self, chciane: set, limit_s: float, co_s: float = 3.0) -> str:
        koniec, stan = time.time() + limit_s, "?"
        while time.time() < koniec:
            stan = self._probe()
            if stan in chciane:
                return stan
            time.sleep(co_s)
        return stan

    @staticmethod
    def _karty() -> list:
        import psutil
        stats = psutil.net_if_stats()
        wynik = []
        for nazwa, adresy in psutil.net_if_addrs().items():
            ipv4 = next((a.address for a in adresy if a.family.name == "AF_INET"), None)
            st = stats.get(nazwa)
            wynik.append({"nazwa": nazwa, "ip": ipv4, "up": bool(st and st.isup)})
        return wynik

    @staticmethod
    def _karta_przewodowa(karty: list):
        for k in karty:
            n = k["nazwa"].lower()
            if k["up"] and k["ip"] and not k["ip"].startswith(("127.", "169.254.")) and "proton" not in n \
                    and "wireguard" not in n and "loopback" not in n:
                return k
        return None

    @staticmethod
    def _brama(ip: str):
        try:
            import wmi
            for c in wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True):
                if ip in (c.IPAddress or ()):
                    return (c.DefaultIPGateway or [None])[0]
        except Exception:                                                    # noqa: BLE001
            return None
        return None

    def _net_info(self) -> dict:
        karty = self._karty()
        eth = self._karta_przewodowa(karty)
        return {"vpn_up": any("proton" in k["nazwa"].lower() and k["up"] for k in karty),
                "alias": eth["nazwa"] if eth else None, "ip": eth["ip"] if eth else None,
                "gw": self._brama(eth["ip"]) if eth else None}

    def _vpn_up(self) -> bool:
        return any("proton" in k["nazwa"].lower() and k["up"] for k in self._karty())

    def _w_sieci_uczelni(self, info: dict) -> bool:
        ip, gw = info.get("ip"), info.get("gw")
        return bool(ip and (gw in self.cfg["campus_gateways"] or any(ip.startswith(p) for p in self.cfg["campus_prefixes"])))

    def _dhcp(self, alias: str, przerwa_s: float = 5) -> bool:
        """Odświeżenie adresu IP przez iphlpapi (zamiast ipconfig) — bez administratora, bez subprocess."""
        import wmi
        idx = None
        for a in wmi.WMI().Win32_NetworkAdapter(NetConnectionID=alias):
            idx = a.InterfaceIndex
        if idx is None:
            return False

        class MapaIp(ctypes.Structure):
            _fields_ = [("Index", ctypes.c_ulong), ("Name", ctypes.c_wchar * 128)]
        ip = ctypes.windll.iphlpapi
        rozmiar = ctypes.c_ulong(0)
        ip.GetInterfaceInfo(None, ctypes.byref(rozmiar))
        bufor = ctypes.create_string_buffer(rozmiar.value)
        if ip.GetInterfaceInfo(bufor, ctypes.byref(rozmiar)) != 0:
            return False
        ile = ctypes.c_long.from_buffer_copy(bufor, 0).value
        rozm = ctypes.sizeof(MapaIp)
        mapa = next((m for m in (MapaIp.from_buffer_copy(bufor, 4 + i * rozm) for i in range(ile)) if m.Index == idx), None)
        if mapa is None:
            return False
        r1 = ip.IpReleaseAddress(ctypes.byref(mapa))
        time.sleep(przerwa_s)
        r2 = ip.IpRenewAddress(ctypes.byref(mapa))
        for _ in range(20):
            if self._karta_przewodowa(self._karty()):
                break
            time.sleep(2)
        self._log(f"Odświeżenie adresu IP: release={r1}, renew={r2}")
        return r1 == 0 and r2 == 0

    # ----------------------------------------------------------------------------------------
    #  Proton VPN: UI Automation (comtypes), nadzór, restart
    # ----------------------------------------------------------------------------------------
    @staticmethod
    def _uia():
        import comtypes.client
        comtypes.client.GetModule("UIAutomationCore.dll")
        from comtypes.gen import UIAutomationClient as ui
        return ui, comtypes.client.CreateObject("{ff48dba4-60ef-4201-aa87-54103eef594e}", interface=ui.IUIAutomation)

    def _okno_protona(self):
        ui, auto = self._uia()
        okno = auto.GetRootElement().FindFirst(ui.TreeScope_Children, auto.CreatePropertyCondition(ui.UIA_NamePropertyId, "Proton VPN"))
        return ui, auto, okno

    @staticmethod
    def _element(ui, auto, okno, auto_id):
        return okno.FindFirst(ui.TreeScope_Descendants, auto.CreatePropertyCondition(ui.UIA_AutomationIdPropertyId, auto_id))

    def _proton_ui_stan(self) -> str:
        """connected / disconnected / unknown (brak obu przycisków: ładowanie, łączenie, zawieszenie) / nowindow (okno
        ukryte w zasobniku) / hung (Windows: Not Responding albo UI Automation nie odpowiada)."""
        def odczyt():
            ui, auto, okno = self._okno_protona()
            if not okno:
                return "nowindow"
            if ctypes.windll.user32.IsHungAppWindow(okno.CurrentNativeWindowHandle):
                return "hung"
            if self._element(ui, auto, okno, ID_ROZLACZ):
                return "connected"
            if self._element(ui, auto, okno, ID_POLACZ):
                return "disconnected"
            return "unknown"
        return self._z_limitem(odczyt, 20, "hung")

    @staticmethod
    def _proton_proces_dziala() -> bool:
        import psutil
        return any((p.info["name"] or "").lower() == KLIENT_PROTONA for p in psutil.process_iter(["name"]))

    def _proton_zdrowie(self, quick: bool = False) -> tuple:
        """(stan, opis): ok / brak_klienta / zawieszony / niespojny."""
        if not self._proton_proces_dziala():
            return "brak_klienta", "proces ProtonVPN.Client nie działa"
        koniec = time.time() + (0 if quick else PROTON_UI_UNKNOWN_S)
        while True:
            ui, karta = self._proton_ui_stan(), self._vpn_up()
            if ui == "hung":
                return "zawieszony", "Windows: klient nie odpowiada (Not Responding / UI Automation)"
            if ui == "nowindow":
                return "ok", "okno klienta ukryte w zasobniku"
            if (ui == "connected" and karta) or (ui == "disconnected" and not karta):
                return "ok", ui
            if time.time() >= koniec:
                if ui == "unknown":
                    return "zawieszony", "okno klienta nie pokazuje stanu połączenia (ładowanie albo zawieszenie)"
                return "niespojny", f"klient pokazuje „{ui}”, a karta VPN jest {'aktywna' if karta else 'nieaktywna'}"
            time.sleep(3)

    def _proton_restart(self) -> bool:
        """To, co robiłeś ręcznie: zamyka proces klienta i uruchamia go od nowa (usługi Protona zostają, bez admina).
        Backend nie może tworzyć procesów, więc start klienta zleca oknu (proces GUI)."""
        import psutil
        self._log("Proton: zamykam proces klienta i uruchamiam go ponownie")
        for p in psutil.process_iter(["name"]):
            if (p.info["name"] or "").lower() == KLIENT_PROTONA:
                try:
                    p.kill()
                except Exception:                                            # noqa: BLE001
                    pass
        time.sleep(4)
        self._wyslij({"type": "launch_proton"})
        koniec = time.time() + 45
        while time.time() < koniec:
            time.sleep(2)
            if self._proton_proces_dziala() and self._proton_ui_stan() in ("connected", "disconnected", "nowindow"):
                self._log("Proton: klient uruchomiony ponownie")
                return True
        self._log("Proton: klient nie wrócił w 45 s")
        return False

    def _kliknij_protona(self, auto_id: str) -> bool:
        ui, auto, okno = self._okno_protona()
        if not okno:                                                         # klient ukryty: okno aktywuje jego okno
            self._wyslij({"type": "launch_proton"})
            for _ in range(25):
                time.sleep(1)
                ui, auto, okno = self._okno_protona()
                if okno:
                    break
        if not okno:
            self._log("Proton: nie widzę okna klienta")
            return False
        wywolaj = ui.IUIAutomationInvokePattern
        for _ in range(30):
            pomin = self._element(ui, auto, okno, ID_POMIN)                  # okienka po rozłączeniu („Skip”)
            if pomin:
                try:
                    pomin.GetCurrentPattern(ui.UIA_InvokePatternId).QueryInterface(wywolaj).Invoke()
                except Exception:                                            # noqa: BLE001
                    pass
                time.sleep(0.5)
            el = self._element(ui, auto, okno, auto_id)
            if el:
                el.GetCurrentPattern(ui.UIA_InvokePatternId).QueryInterface(wywolaj).Invoke()
                return True
            time.sleep(0.5)
        return False

    def _czekaj_vpn(self, chce_up: bool, limit_s: float) -> bool:
        koniec = time.time() + limit_s
        while time.time() < koniec:
            if self._vpn_up() == chce_up:
                return True
            time.sleep(0.5)
        return self._vpn_up() == chce_up

    def _vpn_rozlacz(self) -> bool:
        """Rozłącza i sprawdza, że VPN NIE wrócił (Proton potrafi połączyć się sam). Po nieudanej próbie sprawdza
        zdrowie klienta i w razie potrzeby restartuje go."""
        if not self._vpn_up():
            return True
        for proba in (1, 2, 3):
            kliknieto = self._kliknij_protona(ID_ROZLACZ)
            if kliknieto and self._czekaj_vpn(False, 30):
                time.sleep(3)
                if not self._vpn_up():
                    return True
                self._log(f"Proton połączył się z powrotem sam — ponawiam rozłączenie ({proba}/3)")
                continue
            self._log(f"Rozłączenie nieudane (próba {proba}/3)" + ("" if kliknieto else " — nie znaleziono przycisku"))
            if proba == 2:
                stan, opis = self._proton_zdrowie(quick=True)
                self._log(f"Proton: stan klienta — {stan} ({opis})")
                if stan != "ok" or not kliknieto:
                    self._proton_restart()
        return not self._vpn_up()

    def _vpn_polacz(self, limit_s: float = 60) -> bool:
        """Proton potrafi połączyć się sam po powrocie sieci, więc stan sprawdzamy przez cały czas. Gdy się nie uda,
        diagnozuje klienta, restartuje go i próbuje jeszcze raz."""
        for runda in (1, 2):
            koniec, kliknieto = time.time() + limit_s, False
            while time.time() < koniec:
                if self._vpn_up():
                    return True
                if not kliknieto:
                    kliknieto = self._kliknij_protona(ID_POLACZ)
                time.sleep(2)
            if self._vpn_up():
                return True
            if runda == 1:
                stan, opis = self._proton_zdrowie(quick=True)
                self._log(f"VPN nie połączył się w {limit_s:.0f} s — stan klienta: {stan} ({opis}); restartuję klienta")
                self._proton_restart()
        return self._vpn_up()

    # ----------------------------------------------------------------------------------------
    #  captive portal: logowanie HTTP (bez przeglądarki)
    # ----------------------------------------------------------------------------------------
    @staticmethod
    def _parser_formularzy():
        from html.parser import HTMLParser

        class Parser(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.forms = []

            def handle_starttag(self, tag, attrs):
                a = {k: (v or "") for k, v in attrs}
                if tag == "form":
                    self.forms.append({"action": a.get("action", ""), "inputs": []})
                elif tag in ("input", "button") and self.forms:
                    self.forms[-1]["inputs"].append({"type": (a.get("type") or ("submit" if tag == "button" else "text")).lower(),
                                                     "name": a.get("name", ""), "value": a.get("value", ""),
                                                     "checked": "checked" in a})
        return Parser()

    @staticmethod
    def _dane_formularza(form: dict, login: str, haslo: str) -> dict:
        """Ukryte pola bez zmian, regulamin zaznaczony, login, hasło i pierwszy przycisk wysłania."""
        dane, login_ok, submit_ok = {}, False, False
        for i in form["inputs"]:
            t, n, v = i["type"], i["name"], i["value"]
            if not n:
                continue
            if t == "password":
                dane[n] = haslo
            elif t in ("text", "email", "tel") and not login_ok:
                dane[n], login_ok = login, True
            elif t == "checkbox":
                if re.search(r"aup|accept|terms|agree|regulamin|warunk", n, re.I) or i["checked"]:
                    dane[n] = v or "1"
            elif t == "hidden":
                dane[n] = v
            elif t == "submit" and not submit_ok:
                dane[n], submit_ok = v, True
        return dane

    @staticmethod
    def _zaufany_portal(url: str) -> bool:
        """Login i hasło tylko na portal w sieci lokalnej — nigdy na stronę w internecie (np. msn.com)."""
        import ipaddress
        import socket
        import urllib.parse
        host = urllib.parse.urlsplit(url).hostname or ""
        if re.search(r"(microsoft|msn|live|bing|windows|msftconnecttest)\.", host + ".", re.I):
            return False
        try:
            return ipaddress.ip_address(socket.gethostbyname(host)).is_private
        except (OSError, ValueError):
            return False

    def _adres_portalu(self):
        """Adres strony logowania. Portal PolLub odpowiada na sondę i na /redirect kodem 200 z nagłówkiem Location (przeglądarka
        idzie za nim, urllib nie) — czytamy więc Location, a w razie jego braku meta refresh / skrypt w treści."""
        import urllib.parse
        for url in (PROBE_URL, REDIRECT_URL):
            r = self._http_get(url)
            if r.get("error"):
                continue
            if r.get("location"):
                return urllib.parse.urljoin(url, r["location"])
            m = re.search(r"""(?:url\s*=\s*|location(?:\.href)?\s*=\s*|replace\()\s*["']?(https?://[^"'>\s)]+)""", r["body"], re.I)
            if m:
                return m.group(1)
        return None

    def _zaloguj_w_portalu(self, login: str, haslo: str) -> tuple:
        """Zwraca (sukces, data wygaśnięcia | None, powód)."""
        import http.client
        import http.cookiejar
        import urllib.error
        import urllib.parse
        import urllib.request
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        opener.addheaders = [("User-Agent", UA), ("Accept-Language", "pl,en;q=0.8"), ("Accept", "text/html,*/*;q=0.8")]
        try:
            start = self._adres_portalu()
            if not start:
                return False, None, "nie znaleziono adresu portalu (brak przekierowania w odpowiedzi sondy)"
            with opener.open(start, timeout=15) as r:
                strona, url = r.read().decode("utf-8", "replace"), r.geturl()
            if "msftconnecttest" in (urllib.parse.urlsplit(url).hostname or ""):
                return False, None, "portal nie przekierował (brak captive portalu?)"
            self._log(f"Portal: {url[:90]}")
            if not self._zaufany_portal(url):
                return False, None, "otwarta strona nie jest portalem w sieci lokalnej — nie wysyłam danych"
            host = "http://" + urllib.parse.urlsplit(url).netloc
            try:                                                             # jak skrypt strony: zapamiętaj adres docelowy
                urllib.request.urlopen(urllib.request.Request(host + "/record_destination_url", b"%5Bobject+Object%5D=",
                                                              {"Referer": url, "Origin": host}), timeout=5).close()
            except Exception:                                                # noqa: BLE001 — nieistotne dla logowania
                pass
            for _ in range(4):
                if not self._zaufany_portal(url):
                    return False, None, "przekierowanie poza sieć lokalną — przerywam"
                parser = self._parser_formularzy()
                parser.feed(strona)
                form = next((f for f in parser.forms if any(i["type"] == "password" for i in f["inputs"])), None) or \
                    next((f for f in parser.forms if any(i["type"] == "submit" for i in f["inputs"])), None)
                if form is None:
                    break
                dane = self._dane_formularza(form, login, haslo)
                self._log("Portal: wysyłam formularz (" + ", ".join(k for k in dane if not SEKRET_RE.search(k)) + ")")
                req = urllib.request.Request(urllib.parse.urljoin(url, form["action"] or url), urllib.parse.urlencode(dane).encode(),
                                             {"Referer": url, "Origin": host})
                with opener.open(req, timeout=20) as r:
                    strona, url = r.read().decode("utf-8", "replace"), r.geturl()
                if BAD_LOGIN_RE.search(strona):
                    return False, None, "portal odrzucił login lub hasło"
                m = EXPIRY_RE.search(re.sub(r"<[^>]+>", " ", strona))
                if m:
                    return True, datetime.strptime(m.group(1), FORMAT_DATY), "rejestracja potwierdzona"
            return self._probe() == "ONLINE", None, "formularz wysłany"
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            return False, None, f"błąd połączenia: {e}"

    # ----------------------------------------------------------------------------------------
    #  logowanie w karcie Chrome (UI Automation + mysz/klawiatura) — zapasowa droga, gdy HTTP zawiedzie
    # ----------------------------------------------------------------------------------------
    def _zaloguj_przez_chrome(self, login: str, haslo: str, max_s: float = 90) -> tuple:
        """Przechodzi portal w otwartej karcie Chrome: akceptuje regulamin (sukces = czerwony przycisk znika z ekranu), wpisuje
        dane przez wzorzec Value (bez klikania w pole — omija podpowiedzi menedżera haseł), czeka 2 s, klika „Kontynuuj”,
        czeka 8 s na reakcję. Zwraca (sukces, data wygaśnięcia | None, powód)."""
        import win32api
        import win32con
        import win32gui
        hosty = [h.lower() for h in self.cfg["portal_hosty"]]
        ui, auto = self._uia()
        kropki = set("•●*·∙")

        def nasz(url: str) -> bool:
            return any(h in url.lower() for h in hosty)

        def lista(tablica):
            return [tablica.GetElement(i) for i in range(tablica.Length)]

        def okna():
            return lista(auto.GetRootElement().FindAll(ui.TreeScope_Children, auto.CreatePropertyCondition(
                ui.UIA_ClassNamePropertyId, "Chrome_WidgetWin_1")))

        def dokumenty(okno):
            return lista(okno.FindAll(ui.TreeScope_Descendants, auto.CreatePropertyCondition(
                ui.UIA_ControlTypePropertyId, ui.UIA_DocumentControlTypeId)))

        def wartosc(el):
            try:
                return el.GetCurrentPattern(ui.UIA_ValuePatternId).QueryInterface(ui.IUIAutomationValuePattern).CurrentValue
            except Exception:                                                # noqa: BLE001
                return None

        def znajdz_portal():
            for okno in okna():
                hwnd = okno.CurrentNativeWindowHandle
                if not OKNO_PRZEGLADARKI_RE.search(okno.CurrentName or "") or win32gui.IsIconic(hwnd):
                    continue
                for d in dokumenty(okno):
                    if nasz(wartosc(d) or ""):
                        return okno, hwnd, d
                for k in lista(okno.FindAll(ui.TreeScope_Descendants, auto.CreatePropertyCondition(
                        ui.UIA_ControlTypePropertyId, ui.UIA_TabItemControlTypeId))):
                    if STRICT_TAB_RE.search(k.CurrentName or ""):            # karta portalu w tle: wybierz i sprawdź adres
                        k.GetCurrentPattern(ui.UIA_SelectionItemPatternId).QueryInterface(ui.IUIAutomationSelectionItemPattern).Select()
                        time.sleep(0.8)
                        for d in dokumenty(okno):
                            if nasz(wartosc(d) or ""):
                                return okno, hwnd, d
            return None, None, None

        def elementy(doc):
            wynik = []
            for e in lista(doc.FindAll(ui.TreeScope_Descendants, auto.CreateTrueCondition())):
                try:
                    r = e.CurrentBoundingRectangle
                    if r.right - r.left > 0 and r.bottom - r.top > 0:
                        wynik.append((e.CurrentControlType, e.CurrentName or "", e, r))
                except Exception:                                            # noqa: BLE001
                    continue
            return wynik

        def znajdz(elem, wzorzec, typy=None, maks=80):
            rx = re.compile(wzorzec, re.I)
            for ct, nazwa, e, r in elem:
                if (typy is None or ct in typy) and nazwa and len(nazwa) <= maks and rx.search(nazwa):
                    return e, r
            return None, None

        def pierwszy_plan(okno, hwnd) -> bool:
            try:
                okno.SetFocus()
            except Exception:                                                # noqa: BLE001
                pass
            time.sleep(0.3)
            if win32gui.GetForegroundWindow() != hwnd:
                try:
                    win32api.keybd_event(win32con.VK_MENU, 0, 0, 0)
                    win32api.keybd_event(win32con.VK_MENU, 0, win32con.KEYEVENTF_KEYUP, 0)
                    win32gui.SetForegroundWindow(hwnd)
                except Exception:                                            # noqa: BLE001
                    pass
                time.sleep(0.3)
            return win32gui.GetForegroundWindow() == hwnd

        def klik_myszy(okno, r):
            w = okno.CurrentBoundingRectangle
            x, y = (r.left + r.right) // 2, (r.top + r.bottom) // 2
            if not (w.left <= x <= w.right and w.top <= y <= w.bottom):
                raise RuntimeError("element poza oknem przeglądarki")
            win32api.SetCursorPos((x, y))
            time.sleep(0.15)
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            time.sleep(0.05)
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

        def czerwony(x, y) -> bool:
            hdc = win32gui.GetDC(0)
            try:
                c = win32gui.GetPixel(hdc, x, y)
            finally:
                win32gui.ReleaseDC(0, hdc)
            r, g, b = c & 255, (c >> 8) & 255, (c >> 16) & 255
            return r > 150 and g < 90 and b < 90                             # czerwony przycisk „Akceptuję warunki”

        def wpisz(el, tekst) -> bool:
            wz = el.GetCurrentPattern(ui.UIA_ValuePatternId).QueryInterface(ui.IUIAutomationValuePattern)
            wz.SetValue(tekst)
            try:
                el.SetFocus()                                                # Esc zamyka podpowiedź haseł, End daje keyup
                for vk in (win32con.VK_ESCAPE, win32con.VK_END):
                    win32api.keybd_event(vk, 0, 0, 0)
                    win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)
            except Exception:                                                # noqa: BLE001
                pass
            time.sleep(0.2)
            akt = wz.CurrentValue
            return akt == tekst or (bool(akt) and set(akt) <= kropki and len(akt) == len(tekst))

        def tekst_strony(elem) -> str:
            return " ".join(n for _ct, n, _e, _r in elem)

        for o in okna():                                                     # pierwsze zapytanie włącza dostępność stron
            dokumenty(o)
        time.sleep(2.0)
        okno, hwnd, doc = znajdz_portal()
        if doc is None:
            self._log("Chrome: nie widzę karty portalu — proszę okno o jej otwarcie")
            self._wyslij({"type": "open_portal"})
            for _ in range(17):
                time.sleep(1.5)
                okno, hwnd, doc = znajdz_portal()
                if doc is not None:
                    break
        if doc is None:
            return False, None, "karta portalu nie pojawiła się w Chrome"
        self._log("Chrome: znaleziono kartę portalu")
        aup_ok, aup_proby, wyslano, koniec = False, 0, 0, time.time() + max_s
        while time.time() < koniec:
            okno, hwnd, doc = znajdz_portal()
            if doc is None:
                if self._probe() == "ONLINE":
                    return True, None, "internet działa"
                time.sleep(1.5)
                continue
            elem = elementy(doc)
            tekst = tekst_strony(elem)
            m = EXPIRY_RE.search(tekst)
            if m:
                return True, datetime.strptime(m.group(1), FORMAT_DATY), "rejestracja potwierdzona (Chrome)"
            if self._probe() == "ONLINE":
                return True, None, "internet działa"
            if BAD_LOGIN_RE.search(tekst):
                return False, None, "portal odrzucił login lub hasło"
            if not pierwszy_plan(okno, hwnd):
                self._log("Chrome: nie udało się wysunąć okna na pierwszy plan")
                time.sleep(1.5)
                continue
            aup, r_aup = znajdz(elem, r"akcept\w*\s+warunki|accept|zgadzam", None, 60)
            edit = (ui.UIA_EditControlTypeId,)
            edit_login, _r1 = znajdz(elem, r"u[żz]ytkownika|username|login|e-?mail", edit)
            edit_haslo, _r2 = znajdz(elem, r"has[łl]o|password", edit)
            if aup is not None and not aup_ok:
                if aup_proby >= 2:
                    return False, None, "nie udało się zaakceptować regulaminu w Chrome"
                aup_proby += 1
                px, py = r_aup.left - 50, (r_aup.top + r_aup.bottom) // 2
                if not czerwony(px, py):
                    aup_ok = True                                            # przycisk niewidoczny = już zaakceptowany
                    continue
                self._log("Chrome: akceptuję regulamin")
                try:
                    klik_myszy(okno, r_aup)
                except Exception as e:                                       # noqa: BLE001
                    self._log(f"Chrome: kliknięcie regulaminu nie powiodło się ({type(e).__name__})")
                for _ in range(6):
                    time.sleep(0.5)
                    if not czerwony(px, py):
                        aup_ok = True
                        self._log("Chrome: regulamin zaakceptowany (przycisk zniknął z ekranu)")
                        break
                continue
            if edit_login is not None and edit_haslo is not None:
                if not aup_ok:
                    self._log("Chrome: regulamin niepotwierdzony — nie wysyłam formularza")
                    time.sleep(1.5)
                    continue
                if wyslano >= 2:
                    return False, None, "formularz wysłany kilka razy bez skutku"
                poprawne = False
                for _ in range(3):                                           # autouzupełnianie potrafi nadpisać pola
                    if wpisz(edit_login, login) and wpisz(edit_haslo, haslo):
                        poprawne = True
                        break
                if not poprawne:
                    return False, None, "nie udało się wpisać danych w pola (autouzupełnianie?)"
                time.sleep(2.0)
                przycisk, r_p = znajdz(elementy(doc), r"kontynuuj|continue|zaloguj|submit|dalej", (ui.UIA_ButtonControlTypeId,), 40)
                if przycisk is None or not przycisk.CurrentIsEnabled:
                    self._log("Chrome: przycisk „Kontynuuj” niedostępny — ponawiam")
                    time.sleep(1.0)
                    continue
                self._log("Chrome: klikam „Kontynuuj”")
                try:
                    przycisk.GetCurrentPattern(ui.UIA_InvokePatternId).QueryInterface(ui.IUIAutomationInvokePattern).Invoke()
                except Exception:                                            # noqa: BLE001
                    klik_myszy(okno, r_p)
                wyslano += 1
                t0, jeszcze_raz = time.time(), False
                while time.time() < t0 + 8:                                  # 8 s na reakcję portalu, bez ponownego wpisywania
                    time.sleep(1.0)
                    if self._probe() == "ONLINE":
                        return True, None, "internet działa"
                    o2, h2, d2 = znajdz_portal()
                    if d2 is None:
                        continue
                    e2 = elementy(d2)
                    t2 = tekst_strony(e2)
                    m2 = EXPIRY_RE.search(t2)
                    if m2:
                        return True, datetime.strptime(m2.group(1), FORMAT_DATY), "rejestracja potwierdzona (Chrome)"
                    if BAD_LOGIN_RE.search(t2):
                        return False, None, "portal odrzucił login lub hasło"
                    p2, r2 = znajdz(e2, r"kontynuuj|continue|zaloguj|submit|dalej", (ui.UIA_ButtonControlTypeId,), 40)
                    if not jeszcze_raz and time.time() - t0 >= 3 and p2 is not None and \
                            znajdz(e2, r"has[łl]o|password", edit)[0] is not None:
                        jeszcze_raz, aup_ok = True, False                    # formularz nadal widoczny: kliknij myszą
                        try:
                            klik_myszy(o2, r2)
                        except Exception:                                    # noqa: BLE001
                            pass
                continue
            time.sleep(1.5)
        return self._probe() == "ONLINE", None, "upłynął czas na logowanie w Chrome"

    # ----------------------------------------------------------------------------------------
    #  sprzątanie kart portalu w Chrome (UI Automation + klawisz Ctrl+W)
    # ----------------------------------------------------------------------------------------
    def _zamknij_karty_portalu(self) -> int:
        """Zamyka duplikaty kart portalu (także otwarte przez Windows) i kartę przekierowania msn.com?ocid=wispr. Zamyka
        tylko karty o potwierdzonym adresie; inne karty użytkownika nie są ruszane."""
        import win32api
        import win32con
        import win32gui

        def nasza(url: str) -> bool:
            return "ocid=wispr" in url or "msftconnecttest.com" in url or any(h in url.lower() for h in self.cfg["portal_hosty"])

        def na_pierwszy_plan(okno, hwnd) -> bool:
            """Windows nie pozwala dowolnemu procesowi przejąć pierwszego planu — SetFocus z UI Automation, a w razie
            potrzeby „stuknięcie” Alt odblokowuje SetForegroundWindow. Ctrl+W idzie tylko do potwierdzonego okna."""
            try:
                okno.SetFocus()
            except Exception:                                                # noqa: BLE001
                pass
            time.sleep(0.3)
            if win32gui.GetForegroundWindow() != hwnd:
                try:
                    win32api.keybd_event(win32con.VK_MENU, 0, 0, 0)
                    win32api.keybd_event(win32con.VK_MENU, 0, win32con.KEYEVENTF_KEYUP, 0)
                    win32gui.SetForegroundWindow(hwnd)
                except Exception:                                            # noqa: BLE001
                    pass
                time.sleep(0.3)
            return win32gui.GetForegroundWindow() == hwnd

        def ctrl_w():
            win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
            win32api.keybd_event(ord("W"), 0, 0, 0)
            win32api.keybd_event(ord("W"), 0, win32con.KEYEVENTF_KEYUP, 0)
            win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)

        def adres_aktywnej_karty(ui, auto, okno) -> str:
            dokumenty = okno.FindAll(ui.TreeScope_Descendants, auto.CreatePropertyCondition(ui.UIA_ControlTypePropertyId, ui.UIA_DocumentControlTypeId))
            for n in range(dokumenty.Length):
                try:
                    return dokumenty.GetElement(n).GetCurrentPattern(ui.UIA_ValuePatternId).QueryInterface(
                        ui.IUIAutomationValuePattern).CurrentValue or ""
                except Exception:                                            # noqa: BLE001
                    continue
            return ""

        zamkniete = 0
        ui, auto = self._uia()
        okna = auto.GetRootElement().FindAll(ui.TreeScope_Children, auto.CreatePropertyCondition(ui.UIA_ClassNamePropertyId, "Chrome_WidgetWin_1"))
        for i in range(okna.Length):                                          # pierwsze zapytanie włącza dostępność stron w Chrome
            adres_aktywnej_karty(ui, auto, okna.GetElement(i))
        time.sleep(2.0)                                                       # …a drzewo stron pojawia się z opóźnieniem
        for i in range(okna.Length):
            okno = okna.GetElement(i)
            hwnd = okno.CurrentNativeWindowHandle
            if not OKNO_PRZEGLADARKI_RE.search(okno.CurrentName or "") or win32gui.IsIconic(hwnd):
                continue                                                      # tylko okna przeglądarki, nie zminimalizowane
            for _ in range(8):
                zrobiono = False
                if nasza(adres_aktywnej_karty(ui, auto, okno)):
                    if not na_pierwszy_plan(okno, hwnd):
                        self._log("Sprzątanie kart: nie udało się wysunąć okna Chrome na pierwszy plan — pomijam")
                        break
                    ctrl_w()
                    zamkniete, zrobiono = zamkniete + 1, True
                    time.sleep(0.8)
                else:
                    karty = okno.FindAll(ui.TreeScope_Descendants, auto.CreatePropertyCondition(ui.UIA_ControlTypePropertyId, ui.UIA_TabItemControlTypeId))
                    for j in range(karty.Length):
                        k = karty.GetElement(j)
                        if STRICT_TAB_RE.search(k.CurrentName or ""):
                            k.GetCurrentPattern(ui.UIA_SelectionItemPatternId).QueryInterface(ui.IUIAutomationSelectionItemPattern).Select()
                            time.sleep(0.8)
                            if nasza(adres_aktywnej_karty(ui, auto, okno)):
                                if not na_pierwszy_plan(okno, hwnd):
                                    self._log("Sprzątanie kart: nie udało się wysunąć okna Chrome na pierwszy plan — pomijam")
                                    break
                                ctrl_w()
                                zamkniete, zrobiono = zamkniete + 1, True
                                time.sleep(0.8)
                                break
                if not zrobiono:
                    break
        if zamkniete:
            self._log(f"Zamknięto kart portalu/przekierowania: {zamkniete}")
        return zamkniete

    def _sprzatanie_kart(self) -> None:
        """Od razu, a potem jeszcze po 20 i 60 s (Windows i przekierowania potrafią otworzyć lub odświeżyć kartę z opóźnieniem)."""
        def run():
            try:
                self._zamknij_karty_portalu()
            except Exception as e:                                           # noqa: BLE001
                self._log(f"Sprzątanie kart: {type(e).__name__}: {str(e)[:80]}")
        self._w_watku(run)
        for opoznienie in (20, 60):
            t = threading.Timer(opoznienie, lambda: self._w_watku(run))
            t.daemon = True
            t.start()

    # ----------------------------------------------------------------------------------------
    #  stan trwały i budzik
    # ----------------------------------------------------------------------------------------
    def _ustaw_wygasniecie(self, dt, opis=None) -> None:
        """dt=None oznacza „tylko opis” (np. nieudane odnowienie) — czas wygaśnięcia zostaje bez zmian."""
        if dt is not None:
            self.wygasa = dt
            self.powiadomione.clear()
            self.nieaktualne_zalogowane = False
        if opis:
            self.ostatnie = opis
        _zapisz_szyfrowany("stan.dat", {"wygasa": self.wygasa.strftime(FORMAT_DATY) if self.wygasa else None,
                                        "ostatnie": self.ostatnie})
        if dt is not None:
            try:
                self._zaplanuj_budzik()
            except Exception as e:                                           # noqa: BLE001
                self._log(f"Budzik: {type(e).__name__}: {str(e)[:100]}")

    def _harmonogram(self):
        import win32com.client
        svc = win32com.client.Dispatch("Schedule.Service")
        svc.Connect()
        return svc, svc.GetFolder("\\")

    def _zaplanuj_budzik(self) -> None:
        """Jednorazowy budzik (WakeToRun) na wygaśnięcie minus lead_min. Zadanie TYLKO budzi komputer: akcja to
        „cmd /c exit”, bo uruchamianie Loadera tworzyło jego drugą kopię (a z nią drugi backend) i psuło odnawianie."""
        if not (self.cfg["budzik"] and self.wygasa):
            return
        kiedy = max(datetime.now() + timedelta(minutes=1), self.wygasa - timedelta(minutes=self.cfg["lead_min"]))
        svc, folder = self._harmonogram()
        td = svc.NewTask(0)
        td.RegistrationInfo.Description = "Eduroam AutoRenew: budzi komputer przed końcem sesji LAN (nic nie uruchamia)"
        td.Settings.Enabled = True
        td.Settings.WakeToRun = True
        td.Settings.StartWhenAvailable = True
        td.Settings.DisallowStartIfOnBatteries = False
        td.Settings.StopIfGoingOnBatteries = False
        wyzwalacz = td.Triggers.Create(1)
        wyzwalacz.StartBoundary = kiedy.strftime("%Y-%m-%dT%H:%M:%S")
        wyzwalacz.Enabled = True
        akcja = td.Actions.Create(0)
        akcja.Path = "C:\\Windows\\System32\\cmd.exe"
        akcja.Arguments = "/c exit"
        folder.RegisterTaskDefinition(ZADANIE, td, 6, None, None, 3)
        self._log("Harmonogram: budzik zaplanowany")

    def _budzik(self, wlacz: bool) -> None:
        if wlacz:
            self._zaplanuj_budzik()
            if not self.wygasa:
                self._log("Budzik włączony — zostanie zaplanowany po ustaleniu czasu wygaśnięcia")
        else:
            try:
                self._harmonogram()[1].DeleteTask(ZADANIE, 0)
                self._log("Harmonogram: budzik usunięty")
            except Exception:                                                # noqa: BLE001
                pass

    # ----------------------------------------------------------------------------------------
    #  odnawianie (maszyna stanów — jak w programie)
    # ----------------------------------------------------------------------------------------
    def _limit_czasu(self, etap: str) -> None:
        if time.time() > self._deadline:
            raise TimeoutError(f"przekroczono limit {RENEW_DEADLINE_S // 60} min na etapie: {etap}")

    def _preflight_proton(self) -> None:
        """Przed ruszeniem VPN: czy klient Protona jest sprawny. Zawieszony/niezaładowany → restart."""
        stan, opis = self._proton_zdrowie(quick=True)                        # szybko: długie czekanie tylko przy restarcie
        if stan == "niespojny":                                              # niespójność może być chwilowa — rozłączanie sobie poradzi
            stan, opis = "ok", opis + " (niespójność pominięta, sprawdzę przy rozłączaniu)"
        self._log(f"Proton: stan klienta — {stan} ({opis})")
        self._wyslij({"type": "proton", "stan": stan, "opis": opis})
        if stan != "ok":
            self._log("Proton wygląda na zawieszony lub niespójny — restartuję klienta przed odnowieniem")
            self._proton_restart()
            stan2, opis2 = self._proton_zdrowie()
            self._log(f"Proton po restarcie: {stan2} ({opis2})")
            self._wyslij({"type": "proton", "stan": stan2, "opis": opis2})

    def _odnow(self, powod: str, reczne: bool) -> None:
        if not self._odnawianie.acquire(blocking=False):
            return
        ok = False
        try:
            self.odnawia = True
            self._wyslij({"type": "renewing", "on": True})
            try:
                ok = self._odnow_wlasciwe(powod, reczne)
            except TimeoutError as e:
                self.fail_count += 1
                self._log(f"PRZERWANO ODNAWIANIE: {e}")
                self._toast("Odnawianie trwało za długo i zostało przerwane — sprawdź log", "warn")
                self.monitor_pauza_do = time.monotonic() + COOLDOWN_S
                self._diagnostyka_do_logu()
            except Exception as e:                                           # noqa: BLE001
                self._log(f"BŁĄD odnowienia: {type(e).__name__}: {str(e)[:150]}")
                self.send_error(f"{PLUGIN_ID}: odnowienie: {type(e).__name__}: {e}")
        finally:
            self.odnawia = False
            self.bledy = 0
            self._wyslij({"type": "renewing", "on": False})
            self._odnawianie.release()

    def _odnow_wlasciwe(self, powod: str, reczne: bool) -> bool:
        cfg = self.cfg
        dane_logowania = poswiadczenia_odczyt()
        login, haslo = dane_logowania["login"], dane_logowania["haslo"]
        if not (login and haslo):
            self._log("Brak loginu lub hasła (szyfrowany plik wtyczki) — uzupełnij dane w oknie (VPN nie został ruszony)")
            self._toast("Brak loginu lub hasła — uzupełnij dane w oknie wtyczki", "warn")
            self.monitor_pauza_do = time.monotonic() + 300
            return False
        if reczne and self._probe() == "ONLINE":
            self._log("Odnów teraz: dostęp jest aktywny — odnowienie niepotrzebne (portal pojawia się dopiero po wygaśnięciu). "
                      "Nic nie zmieniam, VPN zostaje włączony.")
            return True
        self._log(f"=== ODNAWIANIE: {powod} ===")
        t_start = time.time()
        self._deadline = time.time() + RENEW_DEADLINE_S
        self._preflight_proton()
        byl_vpn = self._vpn_up()
        if byl_vpn:
            t0 = time.time()
            self._log("Rozłączam Proton VPN…")
            if not self._vpn_rozlacz():
                self._log("BŁĄD: nie udało się rozłączyć VPN")
                self._toast("Nie udało się rozłączyć VPN — odnów dostęp ręcznie", "bad")
                self.fail_count += 1
                return False
            czekaj = max(0.0, cfg["wait_after_vpn_s"] - (time.time() - t0))
            self._log(f"VPN rozłączony, czekam na sieć ({czekaj:.0f} s)")
            time.sleep(czekaj)
            if self._probe() == "BLOKADA_VPN":                               # kill switch / resztki NRPT blokują ruch
                self._log("Sieć zablokowana mimo rozłączonego VPN (kill switch?) — czekam 20 s")
                time.sleep(20)
                if self._probe() == "BLOKADA_VPN":
                    self._log("Blokada trwa — restartuję klienta Protona, żeby zdjąć kill switch")
                    self._proton_restart()
            self._limit_czasu("po rozłączeniu VPN")
        self._log("Czekam na portal logowania…")
        przed = powod.startswith("tuż przed")
        stan = self._czekaj_na_stan({"PORTAL"} if przed else {"PORTAL", "ONLINE"}, 25 if reczne else cfg["portal_wait_s"] + 20, 1.0)
        info = self._net_info()
        if stan not in ("PORTAL", "ONLINE") and info.get("alias"):
            self._log(f"Portal nie pojawił się ({stan}) — odświeżam adres IP karty „{info['alias']}”")
            self._dhcp(info["alias"])
            stan = self._czekaj_na_stan({"PORTAL", "ONLINE"}, 300)
        self._log(f"Stan sieci: {stan}")
        self._limit_czasu("oczekiwanie na portal")
        ok = stan == "ONLINE"
        odrzucone = False
        if ok and przed:
            self._log("Sesja nadal aktywna po rozłączeniu VPN (wygaśnięcie nieaktualne?) — łączę VPN z powrotem, sprawdzę za 2 min")
            self.monitor_pauza_do = time.monotonic() + 120
        if stan == "PORTAL":
            self._log(f"Portal widoczny po {time.time() - t_start:.0f} s od startu odnawiania")
            for proba in (1, 2, 3):
                self._limit_czasu("logowanie w portalu")
                ok, wygasa, powod_blad = self._zaloguj_w_portalu(login, haslo)
                self._log(f"Logowanie HTTP, próba {proba}/3: {powod_blad}")
                if not ok and "odrzucił" not in powod_blad and proba <= 2:   # zapasowa droga: sterowanie kartą Chrome
                    self._log("Próbuję zalogować się w karcie Chrome (UI Automation)")
                    try:
                        ok, wygasa, powod_blad = self._zaloguj_przez_chrome(login, haslo)
                    except Exception as e:                                   # noqa: BLE001
                        ok, wygasa, powod_blad = False, None, f"błąd sterowania Chrome: {type(e).__name__}: {str(e)[:100]}"
                    self._log(f"Logowanie w Chrome, próba {proba}/2: {powod_blad}")
                if ok or "odrzucił" in powod_blad:
                    odrzucone = "odrzucił" in powod_blad
                    break
                time.sleep(5 * proba)
            if ok:
                nowe = wygasa
                if nowe is not None and not (timedelta(minutes=30) < nowe - datetime.now() < timedelta(hours=12)):
                    self._log(f"Data z portalu wygląda nieprawdopodobnie — przyjmuję {cfg['access_hours']} h od teraz "
                              "(strefa czasowa / zmiana czasu?)")
                    nowe = None
                nowe = nowe or datetime.now() + timedelta(hours=cfg["access_hours"])
                self._ustaw_wygasniecie(nowe, f"{datetime.now():%H:%M:%S} odnowiono")
                zostalo_min = int((nowe - datetime.now()).total_seconds() // 60)
                self._log(f"Zalogowano. Nowe wygaśnięcie zapisane szyfrowane (za {zostalo_min // 60} h {zostalo_min % 60} min)")
                if self._czekaj_na_stan({"ONLINE"}, 20) != "ONLINE" and info.get("alias"):
                    self._log("Sieć jeszcze nie działa po rejestracji — odświeżam adres IP")
                    self._dhcp(info["alias"])
                    self._czekaj_na_stan({"ONLINE"}, 60)
                brama = self._net_info().get("gw")
                if brama and brama not in cfg["campus_gateways"]:            # zapamiętaj sieć uczelni
                    cfg["campus_gateways"].append(brama)
                    self._zapisz_json("ustawienia.json", cfg)
            else:
                self._ustaw_wygasniecie(None, f"{datetime.now():%H:%M:%S} NIEUDANE: {powod_blad}")
        if ok and byl_vpn:
            self._limit_czasu("przed połączeniem VPN")
            self._log("Łączę Proton VPN…")
            self._log("VPN połączony. Odnowienie zakończone ✔" if self._vpn_polacz() else
                      "BŁĄD: VPN nie połączył się — połącz ręcznie")
        if ok:
            self.fail_count = 0
            self.monitor_po_odnowieniu = True
            self._toast("Dostęp odnowiony" + (", VPN połączony" if byl_vpn else ""), "ok")
            self._sprzatanie_kart()
        else:
            self.fail_count += 1
            self._log(f"NIE UDAŁO SIĘ odnowić (VPN pozostaje rozłączony); nieudane z rzędu: {self.fail_count}")
            self._diagnostyka_do_logu()
            self._toast("Odnowienie nieudane — zaloguj się ręcznie w otwartej przeglądarce", "bad")
            self._wyslij({"type": "open_portal"})
            self.monitor_pauza_do = time.monotonic() + (1800 if odrzucone else COOLDOWN_S)
            if odrzucone:
                self._toast("Portal odrzucił login lub hasło — popraw dane w oknie wtyczki", "bad")
            if self.fail_count >= FAIL_BACKOFF_AFTER:
                self.monitor_pauza_do = time.monotonic() + FAIL_BACKOFF_S
                self._log(f"Seria {self.fail_count} porażek — pauza {FAIL_BACKOFF_S // 60} min, potrzebna Twoja interwencja")
                self._toast(f"Odnowienie nie udaje się {self.fail_count}. raz z rzędu — sprawdź wtyczkę (log)", "bad")
        return ok

    def _diagnostyka_do_logu(self) -> None:
        """Stan, z którego widać, co mogło zablokować odnowienie (też do pliku diagnostyka.txt w plugin_data)."""
        try:
            stan, opis = self._proton_zdrowie(quick=True)
            info = self._net_info()
            linia = (f"DIAGNOSTYKA: sonda={self._probe()}, VPN={'połączony' if info['vpn_up'] else 'rozłączony'}, "
                     f"karta={info['alias']} ip={info['ip']} brama={info['gw']}, Proton={stan} ({opis}), "
                     f"klient działa={self._proton_proces_dziala()}, nieudane z rzędu={self.fail_count}, "
                     f"hasło zapisane={poswiadczenia_odczyt()['haslo'] is not None}")
            self._log(linia)
            self._wyslij({"type": "proton", "stan": stan, "opis": opis})
            plik = self._katalog() / "diagnostyka.txt"
            plik.write_text(f"{datetime.now():{FORMAT_DATY}}  {linia}\n", encoding="utf-8")
        except Exception as e:                                               # noqa: BLE001
            self._log(f"DIAGNOSTYKA: błąd zbierania stanu: {type(e).__name__}")

    def _test_chrome(self) -> None:
        d = poswiadczenia_odczyt()
        ok, wyg, powod = self._zaloguj_przez_chrome(d["login"], d["haslo"] or "", max_s=60)
        self._log(f"Test logowania w Chrome: {'OK' if ok else 'BŁĄD'} — {powod}")

    def _przelacz_vpn(self) -> None:
        if self._vpn_up():
            self._log("VPN: rozłączam")
            self._log("VPN rozłączony" if self._vpn_rozlacz() else "VPN: nie udało się rozłączyć")
        else:
            self._log("VPN: łączę")
            self._log("VPN połączony" if self._vpn_polacz() else "VPN: nie udało się połączyć")

    def _napraw_proton(self) -> None:
        self._log("Proton: ręczny restart klienta")
        ok = self._proton_restart()
        stan, opis = self._proton_zdrowie(quick=True)
        self._log(f"Proton po restarcie: {stan} ({opis})" + ("" if ok else " — klient nie wrócił"))
        self._wyslij({"type": "proton", "stan": stan, "opis": opis})

    # ----------------------------------------------------------------------------------------
    #  decyzje monitora (toasty, kiedy odnawiać)
    # ----------------------------------------------------------------------------------------
    def _krok_monitora(self, stan: str, kampus: bool, vpn: bool = False) -> dict:
        wynik = {"powod": None, "toast": None, "kasuj": False, "log": None}
        cfg, teraz = self.cfg, datetime.now()
        zostalo = (self.wygasa - teraz).total_seconds() if self.wygasa else None
        if not kampus:
            self.bledy = 0
            return wynik
        if zostalo is not None and zostalo > 0:
            przekroczone = [t for t in cfg["notify_min"] if zostalo <= t * 60]
            if przekroczone and min(przekroczone) not in self.powiadomione:      # jeden toast z faktycznym czasem
                self.powiadomione |= {t for t in cfg["notify_min"] if t >= min(przekroczone)}
                wynik["toast"] = (f"Sesja LAN kończy się za {max(1, round(zostalo / 60))} min — "
                                  "program odnowi ją sam, VPN rozłączy się na chwilę")
        self.bledy = 0 if stan == "ONLINE" else self.bledy + 1
        if cfg["auto"] and time.monotonic() > self.monitor_pauza_do:
            if vpn and zostalo is not None and 0 < zostalo <= PRZED_WYGASNIECIEM_S and stan == "ONLINE":
                wynik["powod"] = "tuż przed wygaśnięciem"                      # VPN rozłączamy z wyprzedzeniem (bez czekania na utratę sieci)
            elif zostalo is not None and zostalo <= 0 and stan != "ONLINE":
                wynik["powod"] = "upłynął czas dostępu"
            elif zostalo is not None and zostalo <= -180:
                wynik["kasuj"] = True
                wynik["log"] = "Czas dostępu minął, ale internet działa — wygaśnięcie nieaktualne, kasuję"
            elif zostalo is not None and zostalo <= 0 and not self.nieaktualne_zalogowane:
                self.nieaktualne_zalogowane = True
                wynik["log"] = "Czas dostępu minął, ale internet jeszcze działa — czekam na jego utratę"
            elif self.bledy >= 4 and (zostalo is None or zostalo <= 900):
                wynik["powod"] = f"internet nie działa ({stan})"
        return wynik

    # ----------------------------------------------------------------------------------------
    #  polecenia z okna i pętla główna
    # ----------------------------------------------------------------------------------------
    def _polecenie(self, p: dict) -> None:
        akcja = p.get("action")
        if akcja == "renew":
            self._w_watku(self._odnow, "ręcznie", True)
        elif akcja == "set_expiry":
            try:
                self._ustaw_wygasniecie(datetime.strptime(str(p.get("value")), FORMAT_DATY), "ustawione ręcznie")
                self._log("Wygaśnięcie ustawione (zapisane szyfrowane)")
            except ValueError:
                self.send_error(f"{PLUGIN_ID}: zły format daty {p.get('value')!r}")
        elif akcja == "set_settings":
            if isinstance(p.get("auto"), bool):
                self.cfg["auto"] = p["auto"]
            self._zapisz_json("ustawienia.json", self.cfg)
            self._wyslij_ustawienia()
        elif akcja == "vpn_toggle":
            self._w_watku(self._przelacz_vpn)
        elif akcja == "fix_proton":
            self._w_watku(self._napraw_proton)
        elif akcja == "diag":
            self._w_watku(self._diagnostyka_do_logu)
        elif akcja == "wake":
            self.cfg["budzik"] = bool(p.get("on"))
            self._zapisz_json("ustawienia.json", self.cfg)
            self._wyslij_ustawienia()
            self._w_watku(self._budzik, self.cfg["budzik"])
        elif akcja == "close_tabs":
            self._w_watku(self._zamknij_karty_portalu)
        elif akcja == "test_chrome":                                          # diagnostyka: logowanie w karcie Chrome
            self._w_watku(self._test_chrome)
        elif akcja == "toast_test":
            self._toast("Test powiadomienia: sesja LAN kończy się za 5 min")
        else:
            self.send_error(f"{PLUGIN_ID}: nieznane polecenie {akcja!r}")

    @staticmethod
    def _nasluch_stdin(kolejka: "queue.Queue") -> None:
        for surowa in sys.stdin:
            surowa = surowa.strip()
            if not surowa:
                continue
            try:
                polecenie = json.loads(surowa)
            except ValueError:
                continue
            if isinstance(polecenie, dict):
                kolejka.put(polecenie)

    def run_backend(self):
        print(f"PID:{multiprocessing.current_process().pid}", flush=True)
        self._blokada_wyjscia = threading.Lock()
        self._odnawianie = threading.Lock()
        self.odnawia = False
        self.fail_count = 0
        self.bledy = 0
        self.powiadomione: set = set()
        self.nieaktualne_zalogowane = False
        self.monitor_pauza_do = 0.0
        self.monitor_po_odnowieniu = False
        self._deadline = 0.0
        # jedna kopia backendu: drugi Loader / przeładowanie wtyczki nie może uruchomić równoległego odnawiania
        self._mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\EduroamAutoRenewBackend")
        if ctypes.windll.kernel32.GetLastError() == 183:                     # ERROR_ALREADY_EXISTS
            for _ in range(20):                                              # stara kopia po przeładowaniu jeszcze się zamyka
                time.sleep(1)
                ctypes.windll.kernel32.CloseHandle(self._mutex)
                self._mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\EduroamAutoRenewBackend")
                if ctypes.windll.kernel32.GetLastError() != 183:
                    break
            else:
                self.send_error(f"{PLUGIN_ID}: inna kopia backendu już działa — ta kończy pracę")
                return
        com_glowny = self._com_init()                                        # wmi (brama) wołamy w głównym wątku  # noqa: F841

        self.cfg = self._wczytaj_json("ustawienia.json", DOMYSLNE)
        self.cfg.pop("username", None)                                       # login jest teraz tylko w szyfrowanym pliku
        if migruj_poswiadczenia():
            self._log("Przeniesiono login i hasło do szyfrowanego pliku wtyczki")
        stan = _czytaj_szyfrowany("stan.dat") or {"wygasa": None, "ostatnie": None}
        try:
            self.wygasa = datetime.strptime(stan["wygasa"], FORMAT_DATY) if stan["wygasa"] else None
        except (TypeError, ValueError):
            self.wygasa = None
        self.ostatnie = stan.get("ostatnie")

        kolejka: "queue.Queue" = queue.Queue()
        threading.Thread(target=self._nasluch_stdin, args=(kolejka,), daemon=True).start()
        self._wyslij_ustawienia()
        self._log("AutoLan v1: backend uruchomiony")
        if not self.cfg["budzik"]:
            self._w_watku(self._budzik, False)                               # usuń ewentualne stare zadanie budzika

        info, ostatnia_siec, ostatni_tyk = {}, 0.0, 0.0
        ostatnie_ustawienia = ostatni_heartbeat = ostatni_proton = ostatnia_iteracja = time.monotonic()
        ostatnia_scienna = time.time()
        while True:
            try:
                try:
                    polecenie = kolejka.get(timeout=1.0)
                except queue.Empty:
                    polecenie = None
                if polecenie is not None:
                    self._polecenie(polecenie)

                teraz, scienna = time.monotonic(), time.time()
                if scienna - ostatnia_scienna > WAKE_GAP_S:                  # komputer spał: sieć dopiero wraca
                    self._log(f"Wykryto wybudzenie systemu (przerwa {int(scienna - ostatnia_scienna)} s) — czekam 20 s na sieć")
                    self.bledy = 0
                    ostatni_tyk = teraz + 20 - TYK_S
                ostatnia_scienna = scienna
                if teraz - ostatni_heartbeat >= HEARTBEAT_CO_S:
                    with self._blokada_wyjscia:
                        self.send_heartbeat()
                    ostatni_heartbeat = teraz
                if teraz - ostatnie_ustawienia >= POWTORZ_USTAWIEN_S:
                    self._wyslij_ustawienia()
                    ostatnie_ustawienia = teraz
                blisko = self.wygasa is not None and abs((self.wygasa - datetime.now()).total_seconds()) < 120
                if self.odnawia or teraz - ostatni_tyk < (TYK_BLISKO_S if blisko else TYK_S):
                    continue
                ostatni_tyk = teraz

                if teraz - ostatni_proton > 120:                             # tylko pokazujemy; restart tylko przed odnowieniem
                    ostatni_proton = teraz
                    s, o = self._proton_zdrowie(quick=True)
                    self._wyslij({"type": "proton", "stan": s, "opis": o})
                if teraz - ostatnia_siec > (5 if blisko else 30) or not info:
                    info, ostatnia_siec = self._net_info(), teraz
                stan_sieci = self._probe()
                kampus = self._w_sieci_uczelni(info)
                d = self._krok_monitora(stan_sieci, kampus, bool(info.get("vpn_up")))
                if d["toast"]:
                    self._toast(d["toast"])
                if d["log"]:
                    self._log(d["log"])
                if d["kasuj"]:
                    self.wygasa = None
                    self._ustaw_wygasniecie(None, self.ostatnie)
                if d["powod"]:
                    self.bledy = 0
                    self._w_watku(self._odnow, d["powod"], False)
                self._wyslij({"type": "tick", "stan": stan_sieci, "vpn": bool(info.get("vpn_up")), "kampus": kampus,
                              "alias": info.get("alias"), "ip": info.get("ip"), "gw": info.get("gw"),
                              "wygasa_enc": _szyfruj_hex(self.wygasa.strftime(FORMAT_DATY)) if self.wygasa else None,
                              "ostatnie": self.ostatnie, "odnawia": False})
            except Exception as e:   # noqa: BLE001 — pętla backendu ma przeżyć pojedynczy błąd
                self.send_error(f"{PLUGIN_ID}: błąd w pętli: {type(e).__name__}: {e}")
                time.sleep(2)


def get_config():
    return EduroamWtyczka.get_config()


if __name__ == "__main__":
    if "--backend" in sys.argv:
        EduroamWtyczka().run_backend()
