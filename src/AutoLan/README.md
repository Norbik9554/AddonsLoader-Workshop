# Eduroam AutoRenew v2 — wtyczka Addons Loader (jeden plik: `logic.py`)

Te same funkcje co program `eduroam_autorenew.py` (v2): licznik i stan (internet, VPN, klient Proton, sieć uczelni, karta/IP/brama,
ostatnie odnowienie, czas do następnego powiadomienia), powiadomienia 10/5/2/1 min, automatyczne odnowienie (rozłączenie Proton VPN →
portal → nowa data wygaśnięcia → połączenie VPN), „Odnów teraz”, łączenie/rozłączanie VPN, „Napraw Protona”, diagnostyka, budzik,
sprzątanie kart portalu w Chrome, „Otwórz portal” (zablokowane przy działającym dostępie), login/hasło z „Pokaż”.

## Instalacja
Skopiuj **cały folder** `EduroamAutoRenew` do `…\Addons Loader V16\client\plugins\` (powstaje `plugins\EduroamAutoRenew\logic.py`),
odśwież listę i przeciągnij „Eduroam AutoRenew” na siatkę (7×9). Skaner AST daje tylko żółte ostrzeżenia — w *Ustawieniach* musi być
wyłączone „Blokuj wtyczki z ostrzeżeniem skanera AST”. **Trzymaj wtyczkę w jednym folderze** (nie kopiuj jej drugi raz pod inną nazwą).

## Dane: osobny folder i szyfrowanie
Folder: `…\client\plugin_data\EduroamAutoRenew\`
| Plik | Zawartość | Szyfrowanie |
|---|---|---|
| `poswiadczenia.dat` | login i hasło | tak (Windows DPAPI: odczyt tylko na tym koncie i tym komputerze) |
| `stan.dat` | data wygaśnięcia i opis ostatniego odnowienia | tak (DPAPI) |
| `ustawienia.json` | automatyczne odnawianie, budzik, progi powiadomień, zapamiętana brama | nie (nic wrażliwego) |
| `diagnostyka.txt` | stan ostatniej diagnostyki (bez daty, loginu i hasła) | nie |

Login i hasło nie przechodzą przez komunikaty Loadera (te trafiają do jego logów); data wygaśnięcia jest w komunikatach zaszyfrowana, a
logi wtyczki nie zawierają jej jawnej wartości. Przy pierwszym starcie wtyczka przenosi login i hasło z Menedżera poświadczeń Windows.

## Powiadomienia
Bez ikony w zasobniku: używa wbudowanych powiadomień Loadera (toast + Centrum Powiadomień).

## Budzik
Zadanie Harmonogramu **tylko budzi komputer** (akcja `cmd /c exit`, `WakeToRun`) 15 min przed końcem sesji. Nie uruchamia Loadera — wcześniejsza
wersja uruchamiała jego drugą kopię, a z nią drugi backend, i psuła odnawianie. Loader musi być uruchomiony. Backend dodatkowo pilnuje, żeby
działała tylko jedna jego kopia.

## Logowanie w portalu
1. HTTP: adres portalu z nagłówka `Location` odpowiedzi 200 (tak odpowiada PolLub — poprzednia wersja szukała 302 i dlatego „portal nie
   przekierował”), potem formularz z regulaminem, loginem i hasłem.
2. Zapasowo: sterowanie kartą Chrome (UI Automation + mysz): akceptacja regulaminu z weryfikacją po kolorze przycisku, wpisanie danych bez
   klikania w pola, 2 s przerwy, „Kontynuuj”, 8 s na reakcję. Gdy portalu nie ma w Chrome, okno wtyczki otwiera go w przeglądarce.
Oba tryby potrzebują Chrome tylko przy zapasowej drodze; chrome musi być widoczny (nie zminimalizowany).

## Czym różni się od programu (piaskownica: bez subprocess, PowerShella, Playwrighta)
PowerShell → psutil + wmi; pywinauto → comtypes (UI Automation); `ipconfig` → `iphlpapi`; Playwright → HTTP + Chrome przez UI Automation;
restart klienta Protona: `psutil` zamyka proces, start zleca oknu wtyczki.

Analiza przyczyn zatrzymania automatu: `ANALIZA_BLOKAD.md` w głównym folderze projektu.
