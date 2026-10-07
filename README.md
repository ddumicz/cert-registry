# Rejestr certyfikatów X.509/TLS (DORA)

Minimalna aplikacja Django; interfejsem jest Django Admin.

## Uruchomienie (devcontainer)
1. Otwórz folder w VS Code → *Reopen in Container* (compose: `app` + PostgreSQL 16). Lokalny `.env` jest opcjonalny; aby zmienić ustawienia lub skonfigurować Tenable.sc, skopiuj `.env.example` do `.env` (plik `.env` nie jest commitowany) i uzupełnij potrzebne wartości.
2. `python manage.py migrate && python manage.py createsuperuser`
3. `python manage.py runserver 0.0.0.0:8000` → http://localhost:8000/

Bez VS Code: `docker compose up -d && docker compose exec app bash`.

## Użycie
- **Certyfikaty → Dodaj**: wklej PEM (tylko certyfikat; klucz prywatny jest odrzucany) – pola uzupełnią się automatycznie.
- W formularzu certyfikatu dodaj dowolną liczbę lokalizacji instalacji jako DNS lub IP Address; wartości są walidowane zależnie od typu i dostępne w wyszukiwaniu oraz eksporcie CSV. Pole „lokalizacja / użycie” pozostaje opisem tekstowym.
- **CMDB → Zasoby CMDB**: powiąż adres IP i identyfikator CI z systemem ICT. System ma własne `CMDB_ID`, a zasób CMDB wskazuje na ten system; importer używa ID do utrzymywania jednego systemu mimo zmian nazwy. Zasobami możesz zarządzać ręcznie w Django Admin albo zaimportować plik CSV:
  `python manage.py import_cmdb_ip_mappings --file cmdb-ip.csv [--dry-run]`
  Wymagane kolumny: `ip,cmdb_ci_id,ict_system`; opcjonalna kolumna `ict_system_cmdb_id` podaje `CMDB_ID` systemu (separator przecinek, średnik lub tabulator; UTF-8). Jeśli system o podanym ID istnieje, importer wiąże zasób z nim; jeśli nie, tworzy go lub uzupełnia istniejący system o tej samej nazwie. Brakujący System ICT jest tworzony automatycznie. Ten sam IP może mieć wiele wpisów CI, ale wtedy dopasowanie odkrycia jest uznane za niejednoznaczne i system ICT nie jest przypisywany.
- Dodaj dane dostępu do Tenable.sc do lokalnego `.env` na podstawie `.env.example`: `TENABLE_SC_URL`, `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`. TLS jest weryfikowany domyślnie (`TENABLE_VERIFY_SSL=true`); nie wyłączaj tej opcji w środowisku produkcyjnym. Rozmiar strony i timeout można ustawić przez `TENABLE_PAGE_SIZE` i `TENABLE_TIMEOUT`.
- Ręczne odkrywanie certyfikatów pluginem 10863 uruchom poleceniem:
  `python manage.py sync_tenable_certificates [--dry-run]`
  Wyniki są stronicowane z `/rest/analysis`; PEM i fingerprint SHA-256 są sprawdzane, a istniejący certyfikat jest aktualizowany po fingerprintcie. Możesz wywoływać polecenie z crona, np. co noc. Przy jednym mapowaniu IP instalacja dostaje System ICT z CMDB; bez mapowania albo przy wielu mapowaniach system pozostaje pusty. Polecenie nie nadpisuje ręcznego statusu, właściciela, notatek ani nazwy certyfikatu.
- Filtry wygaśnięcia, wyszukiwanie, akcja eksportu CSV.
- Panel Django Admin używa czerwonej kolorystyki inspirowanej identyfikacją Banku Pekao; działa również w ciemnym motywie.
- Każda zmiana zapisywana w historii (kto/kiedy) – ślad audytowy.
- `python manage.py check_expiry --days 30 [--email]` (cron); odbiorcy: `EXPIRY_ALERT_RECIPIENTS`.
- Testy: `python manage.py test`.

## Mapowanie na DORA
| Wymaganie | Realizacja |
|---|---|
| Art. 8 – identyfikacja i inwentaryzacja aktywów ICT | rejestr certyfikatów powiązany z systemami ICT i ich krytycznością |
| Art. 9 – ochrona i zapobieganie | monitorowanie ważności, algorytm/rozmiar klucza, `check_expiry` |
| Art. 6 – ramy zarządzania ryzykiem ICT / dokumentacja | właściciel, status, historia zmian |

Poza zakresem: rejestr dostawców ICT (art. 28), przechowywanie kluczy prywatnych. Narzędzie wspiera zgodność, nie gwarantuje jej.
