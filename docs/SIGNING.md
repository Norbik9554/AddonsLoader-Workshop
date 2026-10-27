# Podpisy wtyczek Workshopu — schemat `plugin.sig` (stan: 2026-10-27)

Ten dokument opisuje **schemat, który już działa w kliencie** Addons Loader (`client/plugin_signature.py`, `client/plugin_trust.py`),
oraz to, jak Workshop z niego korzysta. Wcześniejszy projekt z podpisami odłączonymi, rolą `reviewer` i podpisanym manifestem
został porzucony (decyzja właściciela, 2026-10-27); pomysły z niego, które mają sens później, są w sekcji „Możliwe rozszerzenia”.
Format jest publiczny celowo — bezpieczeństwo opiera się na kluczu prywatnym, nie na tajności schematu.

## Co dziś działa

- Wtyczka oficjalna ma w swoim folderze plik **`plugin.sig`**: podpis Ed25519 odcisku palca wszystkich plików folderu.
- Klient sprawdza podpis kluczem publicznym wbudowanym w program (`OFFICIAL_PUBLIC_KEYS_B64` w `plugin_trust.py`) i rozróżnia trzy stany:

| Stan | Warunek | Skutek w kliencie |
|---|---|---|
| **Oficjalna** | `plugin.sig` poprawny, zbiór i zawartość plików zgodne co do jednego | plakietka „oficjalna”, bez skanu AST, uprawnienia natywne bez pytania |
| **Niepodpisana** | brak `plugin.sig` | zwykła ścieżka: skan AST, zgoda użytkownika na uprawnienia |
| **Zablokowana** | `plugin.sig` jest, ale podpis się nie zgadza (zmieniony / dodany / brakujący plik, inna nazwa folderu, obcy klucz, uszkodzony plik) | wtyczka blokowana |

Poziomu „zweryfikowana przez społeczność” klient **nie ma**. Zablokowanej wtyczki nie da się uruchomić „mimo to”.

## Format `plugin.sig`

JSON w korzeniu folderu wtyczki (w ZIP-ie: `<id>/plugin.sig`):

```json
{
  "key_id": "<16 znaków hex>",
  "payload": {
    "schema": 1, "id": "AutoLan", "name": "AutoLan", "version": "1.0.1", "publisher": "official",
    "signed_at": "2026-10-27T12:00:00Z",
    "files": { "logic.py": "<sha256 hex>", "sub/plik.txt": "<sha256 hex>" }
  },
  "signature": "<base64, 64 bajty>"
}
```

- Podpisywane bajty: `b"AddonsLoader-plugin-signature-v1\n"` + `payload` jako JSON (`sort_keys`, separatory `,` i `:`, `ensure_ascii=False`, UTF-8).
  Prefiks domenowy sprawia, że podpis nie jest ważny w żadnym innym protokole (np. licencje używają innego klucza).
- `files` obejmuje wszystkie pliki folderu **oprócz** `plugin.sig` w korzeniu, katalogów `__pycache__` i plików `.pyc` / `.pyo`.
  Ścieżki względne, separator `/`.
- `key_id` = pierwsze 16 znaków hex SHA-256 surowego (32 B) klucza publicznego; służy tylko do wyboru klucza.
- Klient odrzuca (blokuje), gdy: podpis nie pasuje do `payload`, `payload.id` ≠ nazwa folderu, w folderze jest plik spoza `files`,
  brakuje pliku z `files`, albo skrót którego pliku się różni. Dowiązania symboliczne w folderze = błąd.
- Chroni to przed: zmianą bajtu, dołożeniem lub usunięciem pliku, skopiowaniem `plugin.sig` do innej wtyczki, skopiowaniem całej
  oficjalnej wtyczki pod inną nazwą. **Nie** chroni przed kimś, kto ma klucz prywatny.

## Klucz

- Jest jeden klucz „oficjalny”, wygenerowany przez właściciela 2026-10-08. Jego część publiczna jest w `client/plugin_trust.py`.
  Klucz prywatny jest poza wszystkimi repozytoriami; **nie generuj ani nie wklejaj go w czatach, issue ani CI**.
- Rotacja: nowy klucz publiczny dopisuje się do `OFFICIAL_PUBLIC_KEYS_B64` jako kolejny element; starego nie usuwa się, dopóki istnieją
  wtyczki nim podpisane. Klient nie ma jeszcze statusów `retired` / `revoked` (patrz niżej).
- `tools/sign_plugin.py keygen` służy do kluczy **testowych**. Klucza produkcyjnego nie zmieniaj bez powodu — zmiana wymaga nowego
  wydania klienta i ponownego podpisania wszystkich wtyczek.

## Paczka ZIP w Workshopie

Układ: wszystkie wpisy w folderze `<id>/`, razem z `<id>/plugin.sig`; nazwa pliku `<id>-<wersja>.zip`; obecny `logic.py`.
Podpis liczy się na **rozpakowanych plikach**, więc ZIP trzeba budować dopiero po podpisaniu folderu `src/<id>/`
(podpis zmienia zawartość paczki, a więc jej sumę SHA-256 w manifeście).

Zasady, które narzędzie sprawdza przed rozpakowaniem (zalecane też dla klienta, gdy powstanie kod pobierania):
maks. 200 plików, 5 MiB na plik, 20 MiB łącznie, stosunek rozpakowania do skompresowanego ≤ 100; segmenty ścieżki `[A-Za-z0-9._-]`,
bez `..`, `\`, `:`, końcowej kropki i nazw zarezerwowanych Windows (`CON`, `NUL`, `COM1`…); bez duplikatów po porównaniu bez względu na
wielkość liter; bez dowiązań, wpisów zaszyfrowanych i wpisów poza `<id>/`; **bez `__pycache__` i plików `.pyc`/`.pyo`** (podpis ich nie obejmuje,
a Python mógłby je załadować). Serwer (`scan_workshop_zip`) ma własne, nieco luźniejsze limity (10 MB na plik) i odrzuca zgłoszenia z `plugin.sig`:
podpis oficjalny dodaje wyłącznie właściciel, po przeglądzie.

## Wydanie oficjalnej wtyczki

1. Zmień kod w `src/<id>/`, opisz w `meta/<id>.json`, **podnieś wersję** (opublikowanej wersji nie zmieniamy — nowy kod = nowa wersja).
2. `python tools/sign_plugin.py sign src/<id> --key <klucz.pem> --version <wersja>` — zapisuje `src/<id>/plugin.sig`
   (hasło: zmienna `SIGN_KEY_PASSWORD` albo pytanie w terminalu).
3. `python tools/build_manifest.py` — buduje ZIP z `src/<id>/` **razem z `plugin.sig`** i aktualizuje manifest.
   *Do sprawdzenia przy pierwszym wydaniu: że builder nie pomija `plugin.sig` i że nie dodaje innych plików poza podpisanymi.*
4. `python tools/sign_plugin.py verify plugins/<id>/<id>-<wersja>.zip --pub <klucz_publiczny_base64>` — kod 0 = oficjalna.
5. Commit i push.

Istniejące paczki (AutoLan 1.0.0, SystemInfo 0.0.1) nie mają `plugin.sig`; dołożenie go zmieniłoby ich sumę, a wersje są niezmienne —
podpisane trzeba wydać jako nowe wersje (np. AutoLan 1.0.1). `SystemInfo` nie ma `src/SystemInfo/` (`build_manifest.py` go wymaga).

## Narzędzie `tools/sign_plugin.py`

Zależność: `cryptography`. Testy: `python -m unittest discover -s tests`.

| Polecenie | Działanie |
|---|---|
| `keygen --out <ścieżka bez rozszerzenia>` | para kluczy testowych: `.pem` (szyfrowany hasłem, tryb 600) i `.pub`; nie nadpisuje |
| `sign <folder> --key <pem> --version X.Y.Z [--id] [--name]` | zapisuje `plugin.sig` w folderze; odmawia, gdy w folderze jest `__pycache__`/`.pyc` |
| `verify <folder\|zip> --pub <b64> [--pub …] [--pubfile plik]` | jak klient; dla ZIP-a najpierw zasady paczki, potem rozpakowanie do katalogu tymczasowego. Kod wyjścia: 0 oficjalna, 2 niepodpisana, 1 zablokowana lub błąd |
| `pubkey --key <pem>` | wypisuje klucz publiczny (base64) |

Algorytm narzędzia jest kopią algorytmu klienta. Test zgodności (`TestZgodnoscZKlientem`) sprawdza stały wektor policzony przez klienta, a po ustawieniu
`ADDONS_LOADER_SHARED` (katalog z `plugin_signature.py` klienta) także podpisy w obie strony. **Każda zmiana algorytmu musi iść w parze w obu miejscach.**

## Znane ograniczenia (stan na dziś)

- **Klient nie pobiera jeszcze wtyczek z Workshopu** (brak kodu pobierania w `client/`), więc sumy SHA-256 z manifestu, zasady paczki i `plugin.sig` nie są egzekwowane przy instalacji.
  Do czasu wdrożenia to jest tylko plan; sprawdzanie `plugin.sig` działa dla wtyczek leżących w folderze klienta.
- Brak podpisu manifestu, numeru sekwencyjnego i daty wygaśnięcia: kto zmieni repozytorium, może podmienić paczkę i sumę. Podpis `plugin.sig` ogranicza
  szkody tylko tyle, że podmieniona paczka nie dostanie statusu „oficjalna”.
- Brak odwołania pojedynczej wersji i klucza oraz blokady downgrade'u (nowsza wersja nie jest wymuszana).
- Podpis wiąże wtyczkę z nazwą folderu i wersją z `payload`, ale klient nie porównuje wersji z manifestem.
- `.pyc` i `__pycache__` nie są objęte podpisem — klient powinien je ignorować albo usuwać przed uruchomieniem wtyczki.
- Serwer wymaga w manifeście `schema == 1` (`_workshop_oczysc`); każda zmiana schematu manifestu musi iść razem ze zmianą serwera.

## Możliwe rozszerzenia (nie robione)

Podpisy odłączone i kilka podpisów na wersję (rola `reviewer`); podpisany manifest (`seq`, `expires`, `revoked`); `retired`/`revoked` dla kluczy;
`schema 2` z listą wersji jednej wtyczki; kontrola w `build_manifest.py --check` odmawiająca zmiany opublikowanej wersji; ponowna weryfikacja przy każdym starcie wtyczki.
Każde z nich wymaga zmiany w kliencie i serwerze, nie tylko w tym repozytorium.
