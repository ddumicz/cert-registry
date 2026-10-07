import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import DomainNameValidator, validate_ipv46_address
from django.utils.dateparse import parse_datetime

from .services import PEMError, parse_pem

PLUGIN_ID = "10863"
PEM_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


class TenableError(RuntimeError):
    pass


class TenableDataError(ValueError):
    pass


def get_headers():
    access_key = settings.TENABLE_ACCESS_KEY
    secret_key = settings.TENABLE_SECRET_KEY
    if not access_key or not secret_key:
        raise TenableError("Ustaw TENABLE_ACCESS_KEY i TENABLE_SECRET_KEY.")
    return {
        "x-apikey": f"accesskey={access_key}; secretkey={secret_key};",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def fetch_certificates():
    try:
        parsed_url = urlsplit(settings.TENABLE_SC_URL)
    except ValueError as exc:
        raise TenableError("TENABLE_SC_URL ma nieprawidłowy format.") from exc
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise TenableError("TENABLE_SC_URL musi być pełnym adresem HTTPS Tenable.sc.")
    if settings.TENABLE_PAGE_SIZE <= 0:
        raise TenableError("TENABLE_PAGE_SIZE musi być większe od zera.")
    if settings.TENABLE_TIMEOUT <= 0:
        raise TenableError("TENABLE_TIMEOUT musi być większe od zera.")

    headers = get_headers()
    findings = []
    start = 0
    seen_pages = set()
    while True:
        payload = {
            "type": "vuln",
            "sourceType": "cumulative",
            "query": {
                "type": "vuln",
                "tool": "vulndetails",
                "filters": [
                    {"filterName": "pluginID", "operator": "=", "value": PLUGIN_ID},
                ],
                "startOffset": start,
                "endOffset": start + settings.TENABLE_PAGE_SIZE,
            },
        }
        try:
            response = requests.post(
                f"{settings.TENABLE_SC_URL}/rest/analysis",
                headers=headers,
                json=payload,
                verify=settings.TENABLE_VERIFY_SSL,
                timeout=settings.TENABLE_TIMEOUT,
                allow_redirects=False,
            )
            if 300 <= response.status_code < 400:
                raise TenableError("Tenable.sc przekierował żądanie; przekierowania są blokowane.")
            response.raise_for_status()
            data = response.json()
        except TenableError:
            raise
        except requests.RequestException as exc:
            raise TenableError(f"Błąd połączenia z Tenable.sc: {exc}") from exc
        except ValueError as exc:
            raise TenableError("Tenable.sc zwrócił nieprawidłowy JSON.") from exc

        if not isinstance(data, dict):
            raise TenableError("Tenable.sc zwrócił nieprawidłowy format odpowiedzi.")
        error_code = data.get("error_code", 0)
        if str(error_code) != "0":
            raise TenableError(f"Błąd Tenable.sc {error_code}: {data.get('error_msg', 'brak opisu')}")

        response_data = data.get("response", {})
        if not isinstance(response_data, dict):
            raise TenableError("Nieprawidłowy format sekcji response w odpowiedzi Tenable.sc.")
        page = response_data.get("results", [])
        if not isinstance(page, list):
            raise TenableError("Nieprawidłowy format wyników Tenable.sc.")
        if not page:
            break
        page_signature = hashlib.sha256(
            json.dumps(page, sort_keys=True, default=str).encode("utf-8")
        ).digest()
        if page_signature in seen_pages:
            raise TenableError("Tenable.sc zwrócił powtórzoną stronę; przerwano paginację.")
        seen_pages.add(page_signature)
        findings.extend(page)
        if len(page) < settings.TENABLE_PAGE_SIZE:
            break
        start += len(page)
    return findings


def _text_value(value):
    return value.strip() if isinstance(value, str) else ""


def _extract(patterns, text):
    for pattern in patterns:
        match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _fingerprint(value):
    hex_value = value.lower().strip().replace(":", "").replace(" ", "")
    if len(hex_value) != 64 or re.fullmatch(r"[0-9a-f]{64}", hex_value) is None:
        return ""
    return hex_value


def _find_fingerprint(result, text):
    for key in ("fingerprint_sha256", "sha256Fingerprint", "certFingerprint", "fingerprint"):
        value = _text_value(result.get(key))
        if value:
            normalized = _fingerprint(value)
            if normalized:
                return normalized
    value = _extract(
        (
            r"(?:SHA[- ]?256\s+)?(?:Certificate\s+)?Fingerprint\s*[:=]\s*([0-9a-f: ]{64,})",
            r"SHA[- ]?256\s*[:=]\s*([0-9a-f: ]{64,})",
        ),
        text,
    )
    return _fingerprint(value)


def _parse_date(value, label):
    value = value.strip()
    if not value:
        return None
    result = parse_datetime(value)
    if result is None:
        normalized = value.replace(" UTC", "+00:00").replace(" GMT", "+00:00")
        try:
            result = datetime.fromisoformat(normalized)
        except ValueError:
            for date_format in (
                "%b %d %H:%M:%S %Y %Z",
                "%b %d %H:%M:%S %Y",
                "%Y-%m-%d",
            ):
                try:
                    result = datetime.strptime(value, date_format)
                    break
                except ValueError:
                    continue
    if result is None:
        raise TenableDataError(f"Nie można sparsować pola {label}: {value}")
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def _extract_fallback_fields(text):
    subject_cn = _extract(
        (
            r"Subject.*?Common Name\s*[:=]\s*([^\n,]+)",
            r"Subject.*?CN\s*=\s*([^,\n/]+)",
        ),
        text,
    )
    issuer_cn = _extract(
        (
            r"Issuer.*?Common Name\s*[:=]\s*([^\n,]+)",
            r"Issuer.*?CN\s*=\s*([^,\n/]+)",
        ),
        text,
    )
    issuer_org = _extract(
        (
            r"Issuer.*?Organization\s*[:=]\s*([^\n,]+)",
            r"Issuer.*?O\s*=\s*([^,\n/]+)",
        ),
        text,
    )
    issuer = ", ".join(value for value in (issuer_cn, issuer_org) if value)
    return {
        "common_name": subject_cn,
        "san": _extract(
            (r"Subject Alternative Name[s]?\s*[:=]\s*(.+)",),
            text,
        ),
        "serial_number": _extract(
            (r"Serial(?: Number)?\s*[:=]\s*(.+)",),
            text,
        ),
        "issuer": issuer,
        "not_before": _parse_date(
            _extract((r"(?:Not Before|Valid From)\s*[:=]\s*(.+)",), text),
            "Not Before",
        ),
        "not_after": _parse_date(
            _extract((r"(?:Not After|Valid (?:To|Until))\s*[:=]\s*(.+)",), text),
            "Not After",
        ),
        "key_algorithm": "",
        "key_size": 0,
        "pem": "",
    }


def _validate_endpoint(address_type, address):
    try:
        if address_type == "ip":
            validate_ipv46_address(address)
        else:
            try:
                ip_address(address)
            except ValueError:
                pass
            else:
                raise ValidationError("Wartość DNS jest adresem IP.")
            DomainNameValidator()(address)
    except ValidationError as exc:
        raise TenableDataError(f"Nieprawidłowy adres {address}: {exc}") from exc


def parse_finding(result):
    if not isinstance(result, dict):
        raise TenableDataError("Wynik pluginu nie jest obiektem JSON.")
    text = _text_value(result.get("pluginText") or result.get("pluginOutput")).replace("\\n", "\n")
    pem_blocks = PEM_PATTERN.findall(text)
    parsed_pem = None
    if pem_blocks:
        try:
            parsed_pem = parse_pem(pem_blocks[0])
        except PEMError as exc:
            raise TenableDataError(str(exc)) from exc

    explicit_fingerprint = _find_fingerprint(result, text)
    if parsed_pem:
        if explicit_fingerprint and explicit_fingerprint != parsed_pem["fingerprint_sha256"]:
            raise TenableDataError("Fingerprint z pluginu nie zgadza się z fingerprintem PEM.")
        certificate = parsed_pem
    else:
        certificate = _extract_fallback_fields(text)
        if not explicit_fingerprint:
            raise TenableDataError("Plugin nie zwrócił PEM ani poprawnego fingerprintu SHA-256.")
        certificate["fingerprint_sha256"] = explicit_fingerprint

    for field, limit in (
        ("common_name", 255),
        ("issuer", 512),
        ("serial_number", 128),
        ("key_algorithm", 32),
    ):
        if len(certificate[field]) > limit:
            raise TenableDataError(f"Pole certyfikatu {field} przekracza limit {limit} znaków.")

    address_values = []
    ip = _text_value(result.get("ip"))
    dns = _text_value(result.get("dnsName"))
    if ip:
        _validate_endpoint("ip", ip)
        address_values.append(("ip", str(ip_address(ip))))
    if dns:
        _validate_endpoint("dns", dns)
        address_values.append(("dns", dns))
    if not address_values:
        raise TenableDataError("Wynik pluginu nie zawiera adresu IP ani DNS.")

    port_value = result.get("port")
    try:
        port = int(port_value) if port_value not in (None, "") else 0
    except (TypeError, ValueError) as exc:
        raise TenableDataError(f"Nieprawidłowy port: {port_value}") from exc
    if not 0 <= port <= 65535:
        raise TenableDataError(f"Port poza zakresem 0–65535: {port}")

    repository_value = result.get("repository", "")
    repository = (
        _text_value(repository_value.get("name"))
        if isinstance(repository_value, dict)
        else _text_value(repository_value)
    )
    if len(repository) > 128:
        raise TenableDataError("Nazwa repozytorium Tenable przekracza 128 znaków.")

    last_seen_value = _text_value(result.get("lastSeen"))
    last_seen = _parse_date(last_seen_value, "Last Seen") if last_seen_value else None
    return {
        **certificate,
        "addresses": address_values,
        "port": port,
        "protocol": _text_value(result.get("protocol"))[:32],
        "repository": repository,
        "last_seen": last_seen,
        "plugin_output": text,
    }
