# Zgłaszanie problemów bezpieczeństwa

Dotyczy wtyczek Workshopu, manifestu, podpisów (`docs/SIGNING.md`) i narzędzi w tym repozytorium.

## Jak zgłosić
- **Prywatnie:** zakładka **Security → Report a vulnerability** w tym repozytorium (zgłoszenie widzi tylko właściciel).
- **Nie zakładaj publicznego issue** dla luk i złośliwego kodu — zgłoszenie publiczne ujawnia problem wszystkim.
- Docelowo będzie osobna strona zgłoszeń na serwerze Addons Loader; link pojawi się tutaj.

## Co podać
Nazwę i wersję wtyczki (`id` + `version`), opis problemu, kroki odtworzenia, wpływ (co może zrobić napastnik). Dla złośliwej paczki podaj sumę SHA-256 z manifestu.

## Co się dzieje po zgłoszeniu
1. Potwierdzamy zgłoszenie i weryfikujemy problem.
2. Groźną wersję usuwamy z katalogu (manifestu) i publikujemy poprawioną wersję z nowym podpisem `plugin.sig`.
3. Gdy wyciekł klucz podpisujący, wydajemy nową wersję klienta z nowym kluczem i podpisujemy wtyczki od nowa.
4. Opisujemy sprawę w ogłoszeniu po wydaniu poprawki.

Nie gwarantujemy czasu odpowiedzi; zgłoszenia dotyczące złośliwego kodu mają pierwszeństwo.

## Co oznacza podpis wtyczki
Poprawny `plugin.sig` oznacza, że kod pochodzi od właściciela projektu i nie został zmieniony po podpisaniu. To nie jest gwarancja braku błędów.
