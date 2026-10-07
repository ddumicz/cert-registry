from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from registry.models import CMDBIPMapping, Certificate, CertificateInstallation
from registry.tenable import TenableDataError, TenableError, fetch_certificates, parse_finding


class Command(BaseCommand):
    help = "Pobiera z Tenable.sc certyfikaty znalezione przez plugin 10863."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Pobiera i waliduje wyniki, ale nie zapisuje zmian.",
        )

    def handle(self, *args, dry_run, **options):
        try:
            findings = fetch_certificates()
        except TenableError as exc:
            raise CommandError(str(exc)) from exc

        counts = {
            "created": 0,
            "updated": 0,
            "installations": 0,
            "unmapped": 0,
            "ambiguous": 0,
            "skipped": 0,
        }
        with transaction.atomic():
            for index, finding in enumerate(findings, start=1):
                try:
                    parsed = parse_finding(finding)
                    with transaction.atomic():
                        certificate, created = self._upsert_certificate(parsed)
                        warnings, mapping_status = self._upsert_installations(certificate, parsed)
                except (TenableDataError, ValidationError, ValueError) as exc:
                    counts["skipped"] += 1
                    self.stderr.write(f"Wynik {index}: pominięto — {exc}")
                    continue

                for warning in warnings:
                    self.stderr.write(f"Wynik {index}: {warning}")
                counts["created" if created else "updated"] += 1
                counts["installations"] += len(parsed["addresses"])
                if mapping_status:
                    counts[mapping_status] += 1
                if index % 100 == 0:
                    self.stdout.write(f"Przetworzono {index} z {len(findings)} wyników.")

            if dry_run:
                transaction.set_rollback(True)

        mode = "Podgląd" if dry_run else "Synchronizacja"
        self.stdout.write(
            f"{mode} Tenable.sc: {len(findings)} wyników, "
            f"{counts['created']} nowych certyfikatów, "
            f"{counts['updated']} zaktualizowanych, "
            f"{counts['installations']} lokalizacji, "
            f"{counts['unmapped']} bez mapowania IP, "
            f"{counts['ambiguous']} niejednoznacznych IP, "
            f"{counts['skipped']} pominiętych."
        )
        if counts["skipped"]:
            raise CommandError(f"Pominięto {counts['skipped']} nieprawidłowych wyników Tenable.")

    @staticmethod
    def _upsert_certificate(parsed):
        defaults = {
            "name": parsed["common_name"],
            "common_name": parsed["common_name"],
            "san": parsed["san"],
            "serial_number": parsed["serial_number"],
            "issuer": parsed["issuer"],
            "not_before": parsed["not_before"],
            "not_after": parsed["not_after"],
            "key_algorithm": parsed["key_algorithm"],
            "key_size": parsed["key_size"],
            "pem": parsed["pem"],
        }
        defaults = {
            field: value
            for field, value in defaults.items()
            if value not in ("", None, 0)
        }
        certificate, created = Certificate.objects.get_or_create(
            fingerprint_sha256=parsed["fingerprint_sha256"],
            defaults=defaults,
        )
        if created:
            return certificate, True

        changed_fields = []
        for field, value in defaults.items():
            if field == "name":
                continue
            current = getattr(certificate, field)
            if current != value:
                setattr(certificate, field, value)
                changed_fields.append(field)
        if not certificate.name and parsed["common_name"]:
            certificate.name = parsed["common_name"]
            changed_fields.append("name")
        if changed_fields:
            certificate.save(update_fields=tuple(dict.fromkeys(changed_fields)))
        return certificate, False

    @staticmethod
    def _upsert_installations(certificate, parsed):
        ip_address = next(
            (address for address_type, address in parsed["addresses"] if address_type == "ip"),
            "",
        )
        mappings = list(
            CMDBIPMapping.objects.filter(address=ip_address).select_related("ict_system")
        ) if ip_address else []
        mapping = mappings[0] if len(mappings) == 1 else None
        warnings = []
        if len(mappings) > 1:
            warnings.append(
                f"IP {ip_address} pasuje do {len(mappings)} zasobów CMDB; "
                "System ICT pozostawiono pusty."
            )
        mapping_status = "ambiguous" if len(mappings) > 1 else "unmapped" if not mappings else None
        if not ip_address:
            mapping_status = "unmapped"

        for address_type, address in parsed["addresses"]:
            installation, _ = CertificateInstallation.objects.get_or_create(
                certificate=certificate,
                address_type=address_type,
                address=address,
                source=CertificateInstallation.Source.TENABLE,
                port=parsed["port"],
                protocol=parsed["protocol"],
                repository=parsed["repository"],
                defaults={
                    "ict_system": mapping.ict_system if mapping else None,
                    "cmdb_mapping": mapping if address_type == "ip" else None,
                    "last_seen": parsed["last_seen"],
                },
            )
            if installation.pk:
                changed_fields = []
                values = {
                    "ict_system": mapping.ict_system if mapping else None,
                    "cmdb_mapping": mapping if address_type == "ip" else None,
                }
                if parsed["last_seen"] is not None:
                    values["last_seen"] = parsed["last_seen"]
                for field, value in values.items():
                    if field == "last_seen":
                        changed = installation.last_seen != value
                    else:
                        changed = getattr(installation, f"{field}_id") != getattr(value, "pk", None)
                    if changed:
                        setattr(installation, field, value)
                        changed_fields.append(field)
                if changed_fields:
                    installation.save(update_fields=changed_fields)
        return warnings, mapping_status
