# AddonsLoader-Workshop

Publiczny rejestr wtyczek Addons Loadera. Klient pobiera stąd `manifest.json` i paczki `.zip` bez udziału serwera; strona
serwera (`/workshop.html`) pokazuje ten sam manifest w przeglądarce.

```
manifest.json                       katalog wtyczek (generowany: tools/build_manifest.py)
plugins/<id>/<id>-<wersja>.zip      paczka (w środku folder <id>/ z logic.py)
src/<id>/                           źródło wtyczki (publiczne)
meta/<id>.json                      opis: nazwa, wersja, autor, kategoria, uprawnienia
tools/build_manifest.py             budowa paczek i manifestu (stdlib)
```

## Wtyczki
| Id | Wersja | Opis |
|---|---|---|
| `AutoLan` | 1.0.0 | automatyczne odnawianie 3-godzinnego dostępu LAN z obsługą Proton VPN |

## Dodanie lub aktualizacja wtyczki
1. Skopiuj pliki do `src/<id>/` (folder = identyfikator), opisz w `meta/<id>.json`, podnieś `version`.
2. Wtyczki oficjalne podpisz: `python dev/plugin_signing/sign_plugin.py sign src/<id> --key <klucz> --version <wersja>`.
3. `python tools/build_manifest.py`, potem `python tools/build_manifest.py --check` (musi zwrócić AKTUALNE).
4. Commit i push na `main`. Strona serwera odświeża manifest co kilka minut.

## Zasady
- Nie wrzucaj tu loginów, haseł, tokenów ani danych z `plugin_data` — repozytorium jest publiczne.
- Paczka bez `plugin.sig` ma w manifeście `"signed": false`; klient pokaże ją jako niepodpisaną.
- Suma SHA-256 w manifeście dotyczy dokładnie pliku `.zip`; klient powinien ją sprawdzić przed rozpakowaniem.
