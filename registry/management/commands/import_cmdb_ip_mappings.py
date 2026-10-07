import csv
import ipaddress
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from registry.models import CMDBIPMapping, ICTSystem

REQUIRED_COLUMNS = {"ip", "cmdb_ci_id", "ict_system"}
SYSTEM_ID_COLUMN = "ict_system_cmdb_id"


class Command(BaseCommand):
    help = "Importuje mapowania IP, ID CI i Systemu ICT z pliku CSV."

    def add_arguments(self, parser):
        parser.add_argument("--file", required=True, help="Ścieżka do CSV (UTF-8; separator przecinek).")
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Waliduje i raportuje import bez zapisywania zmian.",
        )

    def handle(self, *args, file, dry_run, **options):
        path = Path(file)
        if not path.is_file():
            raise CommandError(f"Nie znaleziono pliku CSV: {path}")

        created = 0
        updated = 0
        errors = 0
        systems_by_mapping = {}
        try:
            csv_file = path.open(encoding="utf-8-sig", newline="")
        except OSError as exc:
            raise CommandError(f"Nie można otworzyć pliku CSV: {exc}") from exc

        with csv_file:
            sample = csv_file.read(4096)
            csv_file.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(csv_file, dialect=dialect)
            if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
                expected = ", ".join(sorted(REQUIRED_COLUMNS))
                raise CommandError(f"CSV musi zawierać kolumny: {expected}.")

            with transaction.atomic():
                for line_number, row in enumerate(reader, start=2):
                    address = (row.get("ip") or "").strip()
                    cmdb_ci_id = (row.get("cmdb_ci_id") or "").strip()
                    system_name = (row.get("ict_system") or "").strip()
                    system_cmdb_id = (row.get(SYSTEM_ID_COLUMN) or "").strip()
                    if not address or not cmdb_ci_id or not system_name:
                        errors += 1
                        self.stderr.write(f"Wiersz {line_number}: wymagane są ip, cmdb_ci_id i ict_system.")
                        continue
                    if len(cmdb_ci_id) > 128:
                        errors += 1
                        self.stderr.write(f"Wiersz {line_number}: cmdb_ci_id przekracza 128 znaków.")
                        continue
                    if len(system_name) > 200:
                        errors += 1
                        self.stderr.write(f"Wiersz {line_number}: nazwa ict_system przekracza 200 znaków.")
                        continue
                    if len(system_cmdb_id) > 128:
                        errors += 1
                        self.stderr.write(
                            f"Wiersz {line_number}: {SYSTEM_ID_COLUMN} przekracza 128 znaków."
                        )
                        continue
                    try:
                        address = str(ipaddress.ip_address(address))
                    except ValueError:
                        errors += 1
                        self.stderr.write(f"Wiersz {line_number}: nieprawidłowy adres IP {address!r}.")
                        continue

                    mapping_key = (address, cmdb_ci_id)
                    previous_system = systems_by_mapping.get(mapping_key)
                    current_system = (system_name, system_cmdb_id)
                    if previous_system and (
                        previous_system[0] != system_name
                        or (
                            previous_system[1]
                            and system_cmdb_id
                            and previous_system[1] != system_cmdb_id
                        )
                    ):
                        errors += 1
                        self.stderr.write(
                            f"Wiersz {line_number}: mapowanie {address}/{cmdb_ci_id} "
                            f"wskazuje sprzeczny System ICT ({current_system!r} i {previous_system!r})."
                        )
                        continue
                    systems_by_mapping[mapping_key] = (
                        system_name,
                        system_cmdb_id or (previous_system[1] if previous_system else ""),
                    )

                    ict_system, system_error = self._get_or_create_system(
                        system_name, system_cmdb_id,
                    )
                    if system_error:
                        errors += 1
                        self.stderr.write(f"Wiersz {line_number}: {system_error}")
                        continue
                    mapping, was_created = CMDBIPMapping.objects.get_or_create(
                        address=address,
                        cmdb_ci_id=cmdb_ci_id,
                        defaults={"ict_system": ict_system},
                    )
                    if was_created:
                        created += 1
                    elif mapping.ict_system_id != ict_system.pk:
                        mapping.ict_system = ict_system
                        mapping.save(update_fields=("ict_system",))
                        updated += 1

                if dry_run:
                    transaction.set_rollback(True)

        mode = "Podgląd" if dry_run else "Import"
        self.stdout.write(
            f"{mode}: {created} dodano, {updated} zaktualizowano, "
            f"{errors} wierszy z błędami."
        )
        if errors:
            raise CommandError(f"Import zakończony z {errors} błędnymi wierszami.")

    @staticmethod
    def _get_or_create_system(system_name, system_cmdb_id):
        by_name = ICTSystem.objects.filter(name=system_name).first()
        if system_cmdb_id:
            by_id = ICTSystem.objects.filter(cmdb_id=system_cmdb_id).first()
            if by_id:
                if by_id.name != system_name and by_name and by_name.pk != by_id.pk:
                    return None, (
                        f"CMDB_ID {system_cmdb_id!r} i nazwa {system_name!r} "
                        "wskazują różne istniejące systemy ICT."
                    )
                if by_id.name != system_name:
                    by_id.name = system_name
                    by_id.save(update_fields=("name",))
                return by_id, None
            if by_name:
                if by_name.cmdb_id and by_name.cmdb_id != system_cmdb_id:
                    return None, (
                        f"System {system_name!r} ma już inny CMDB_ID "
                        f"({by_name.cmdb_id!r})."
                    )
                by_name.cmdb_id = system_cmdb_id
                by_name.save(update_fields=("cmdb_id",))
                return by_name, None
            return ICTSystem.objects.create(name=system_name, cmdb_id=system_cmdb_id), None

        if by_name:
            return by_name, None
        return ICTSystem.objects.create(name=system_name), None
