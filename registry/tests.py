from datetime import datetime, timedelta, timezone as dt_tz
from io import StringIO
from tempfile import NamedTemporaryFile
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib import admin
from django.db import connection
from django.core.exceptions import ValidationError
from django.core.management import CommandError, call_command
from django.db.migrations.executor import MigrationExecutor
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from .models import CMDBIPMapping, Certificate, CertificateInstallation, ICTSystem
from .services import PEMError, parse_pem
from .tenable import TenableDataError, TenableError, fetch_certificates, parse_finding


def make_pem(days=90, cn="example.test"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(dt_tz.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return pem, priv


class ParseTests(TestCase):
    def test_parse(self):
        pem, _ = make_pem()
        p = parse_pem(pem)
        self.assertEqual(p["common_name"], "example.test")
        self.assertEqual(p["key_algorithm"], "RSA")
        self.assertEqual(p["key_size"], 2048)
        self.assertEqual(len(p["fingerprint_sha256"]), 64)

    def test_rejects_private_key(self):
        pem, priv = make_pem()
        with self.assertRaises(PEMError):
            parse_pem(pem + priv)

    def test_rejects_garbage(self):
        with self.assertRaises(PEMError):
            parse_pem("nope")


class TenableParserTests(TestCase):
    def test_parse_finding_from_pem_and_endpoint_metadata(self):
        pem, _ = make_pem(cn="gateway.example.test")
        certificate = parse_pem(pem)
        finding = {
            "ip": "192.0.2.15",
            "dnsName": "gateway.example.test",
            "port": "65535",
            "protocol": "tcp",
            "lastSeen": "2026-10-04T12:30:00Z",
            "repository": {"name": "Production"},
            "pluginOutput": (
                f"SHA256 Fingerprint: {certificate['fingerprint_sha256']}\n{pem}"
            ),
        }

        parsed = parse_finding(finding)
        self.assertEqual(parsed["fingerprint_sha256"], certificate["fingerprint_sha256"])
        self.assertEqual(parsed["common_name"], "gateway.example.test")
        self.assertEqual(parsed["addresses"], [
            ("ip", "192.0.2.15"),
            ("dns", "gateway.example.test"),
        ])
        self.assertEqual(parsed["port"], 65535)
        self.assertEqual(parsed["protocol"], "tcp")
        self.assertEqual(parsed["repository"], "Production")
        self.assertEqual(parsed["last_seen"], datetime(2026, 10, 4, 12, 30, tzinfo=dt_tz.utc))

    def test_parse_finding_from_text_fingerprint(self):
        finding = {
            "ip": "2001:0db8:0:0::15",
            "port": 443,
            "pluginOutput": (
                "Subject: CN=api.example.test\n"
                "Issuer: CN=Example CA, O=Example Org\n"
                "Serial Number: 1234\n"
                "Not Before: 2026-01-01\n"
                "Not After: 2027-01-01\n"
                "SHA256 Fingerprint: " + "ab" * 32
            ),
        }
        parsed = parse_finding(finding)
        self.assertEqual(parsed["fingerprint_sha256"], "ab" * 32)
        self.assertEqual(parsed["addresses"], [("ip", "2001:db8::15")])
        self.assertEqual(parsed["common_name"], "api.example.test")

    def test_rejects_pem_fingerprint_mismatch(self):
        pem, _ = make_pem()
        with self.assertRaises(TenableDataError):
            parse_finding({
                "ip": "192.0.2.15",
                "fingerprint_sha256": "ab" * 32,
                "pluginOutput": pem,
            })

    def test_rejects_missing_fingerprint_and_invalid_endpoint(self):
        with self.assertRaisesMessage(TenableDataError, "fingerprint"):
            parse_finding({"ip": "192.0.2.15", "pluginOutput": "Subject CN=host"})
        with self.assertRaisesMessage(TenableDataError, "Nieprawidłowy adres"):
            parse_finding({
                "ip": "not-an-ip",
                "fingerprint_sha256": "ab" * 32,
                "pluginOutput": "",
            })


class TenableClientTests(TestCase):
    @override_settings(
        TENABLE_SC_URL="https://tenable.example",
        TENABLE_ACCESS_KEY="access",
        TENABLE_SECRET_KEY="secret",
        TENABLE_VERIFY_SSL=True,
        TENABLE_PAGE_SIZE=2,
        TENABLE_TIMEOUT=30,
    )
    @patch("registry.tenable.requests.post")
    def test_fetches_all_pages_with_tls_verification(self, post):
        first = Mock()
        first.status_code = 200
        first.raise_for_status.return_value = None
        first.json.return_value = {"error_code": 0, "response": {"results": [{"ip": "1"}, {"ip": "2"}]}}
        second = Mock()
        second.status_code = 200
        second.raise_for_status.return_value = None
        second.json.return_value = {"error_code": 0, "response": {"results": [{"ip": "3"}]}}
        post.side_effect = [first, second]

        results = fetch_certificates()
        self.assertEqual(len(results), 3)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args_list[0].kwargs["json"]["query"]["startOffset"], 0)
        self.assertEqual(post.call_args_list[1].kwargs["json"]["query"]["startOffset"], 2)
        self.assertEqual(post.call_args_list[0].kwargs["verify"], True)
        self.assertFalse(post.call_args_list[0].kwargs["allow_redirects"])
        self.assertIn("accesskey=access; secretkey=secret;", post.call_args_list[0].kwargs["headers"]["x-apikey"])

    @override_settings(
        TENABLE_SC_URL="https://tenable.example",
        TENABLE_ACCESS_KEY="access",
        TENABLE_SECRET_KEY="secret",
        TENABLE_VERIFY_SSL=True,
        TENABLE_PAGE_SIZE=1000,
        TENABLE_TIMEOUT=30,
    )
    @patch("registry.tenable.requests.post")
    def test_raises_on_tenable_api_error(self, post):
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "error_code": 403,
            "error_msg": "Forbidden",
        }
        post.return_value = response
        with self.assertRaisesMessage(TenableError, "Forbidden"):
            fetch_certificates()

    @override_settings(
        TENABLE_SC_URL="https://tenable.example",
        TENABLE_ACCESS_KEY="access",
        TENABLE_SECRET_KEY="secret",
        TENABLE_VERIFY_SSL=True,
        TENABLE_PAGE_SIZE=1000,
        TENABLE_TIMEOUT=30,
    )
    @patch("registry.tenable.requests.post")
    def test_does_not_follow_redirects_with_api_credentials(self, post):
        response = Mock()
        response.status_code = 302
        post.return_value = response
        with self.assertRaisesMessage(TenableError, "przekierował"):
            fetch_certificates()

    @override_settings(
        TENABLE_SC_URL="",
        TENABLE_ACCESS_KEY="",
        TENABLE_SECRET_KEY="",
    )
    def test_requires_credentials_and_url(self):
        with self.assertRaisesMessage(TenableError, "TENABLE_SC_URL"):
            fetch_certificates()


class ExpiryTests(TestCase):
    def test_states(self):
        now = timezone.now()
        for days, state in [(90, "ok"), (20, "warning"), (3, "critical"), (-1, "expired")]:
            c = Certificate(name="x", not_after=now + timedelta(days=days, hours=1))
            self.assertEqual(c.expiry_state, state)

    def test_command(self):
        now = timezone.now()
        Certificate.objects.create(name="soon", not_after=now + timedelta(days=5))
        Certificate.objects.create(name="later", not_after=now + timedelta(days=200))
        out = StringIO()
        call_command("check_expiry", stdout=out)
        self.assertIn("soon", out.getvalue())
        self.assertNotIn("later", out.getvalue())


class CertificateInstallationTests(TestCase):
    def setUp(self):
        self.certificate = Certificate.objects.create(name="gateway")

    def test_cmdb_asset_labels(self):
        self.assertEqual(CMDBIPMapping._meta.verbose_name, "zasób CMDB")
        self.assertEqual(CMDBIPMapping._meta.verbose_name_plural, "zasoby CMDB")
        self.assertEqual(CMDBIPMapping._meta.get_field("name").verbose_name, "nazwa")
        self.assertTrue(CMDBIPMapping._meta.get_field("name").blank)
        self.assertEqual(CMDBIPMapping._meta.get_field("cmdb_ci_id").verbose_name, "ID Zasobu")
        self.assertEqual(
            CertificateInstallation._meta.get_field("cmdb_mapping").verbose_name,
            "powiązanie z zasobem CMDB (IP)",
        )

    def test_accepts_dns_and_ip_addresses(self):
        for address_type, address in (
            (CertificateInstallation.AddressType.DNS, "api.example.test"),
            (CertificateInstallation.AddressType.IP, "192.0.2.10"),
            (CertificateInstallation.AddressType.IP, "2001:db8::10"),
        ):
            installation = CertificateInstallation(
                certificate=self.certificate,
                address_type=address_type,
                address=address,
            )
            installation.full_clean()

    def test_rejects_invalid_address_for_type(self):
        for address_type, address in (
            (CertificateInstallation.AddressType.DNS, "https://example.test"),
            (CertificateInstallation.AddressType.DNS, "192.0.2.10"),
            (CertificateInstallation.AddressType.IP, "not-an-ip"),
        ):
            installation = CertificateInstallation(
                certificate=self.certificate,
                address_type=address_type,
                address=address,
            )
            with self.subTest(address_type=address_type):
                with self.assertRaises(ValidationError):
                    installation.full_clean()

    def test_port_must_be_in_valid_range(self):
        installation = CertificateInstallation(
            certificate=self.certificate,
            address_type=CertificateInstallation.AddressType.IP,
            address="192.0.2.10",
            port=65535,
        )
        installation.full_clean()

        installation.port = 65536
        with self.assertRaises(ValidationError) as error:
            installation.full_clean()
        self.assertIn("port", error.exception.message_dict)

    def test_installation_changes_are_historized(self):
        installation = CertificateInstallation.objects.create(
            certificate=self.certificate,
            address_type=CertificateInstallation.AddressType.DNS,
            address="api.example.test",
        )
        self.assertEqual(installation.history.count(), 1)

    def test_cmdb_ci_id_links_ip_installation_to_certificate_system(self):
        system = ICTSystem.objects.create(name="Payments")
        certificate = Certificate.objects.create(name="gateway", ict_system=system)
        mapping = CMDBIPMapping.objects.create(
            address="192.0.2.10",
            cmdb_ci_id="CI-1042",
            ict_system=system,
        )
        installation = CertificateInstallation(
            certificate=certificate,
            ict_system=system,
            address_type=CertificateInstallation.AddressType.IP,
            address="192.0.2.10",
            cmdb_mapping=mapping,
        )

        installation.full_clean()
        installation.save()
        self.assertEqual(installation.certificate.ict_system, system)
        self.assertEqual(certificate.installations.get(), installation)

    def test_cmdb_ci_id_is_only_valid_for_ip_locations(self):
        mapping = CMDBIPMapping.objects.create(
            address="192.0.2.10",
            cmdb_ci_id="CI-1042",
        )
        installation = CertificateInstallation(
            certificate=self.certificate,
            address_type=CertificateInstallation.AddressType.DNS,
            address="api.example.test",
            cmdb_mapping=mapping,
        )
        with self.assertRaises(ValidationError) as error:
            installation.full_clean()
        self.assertIn("cmdb_mapping", error.exception.message_dict)

    def test_export_includes_installation_addresses(self):
        CertificateInstallation.objects.create(
            certificate=self.certificate,
            address_type=CertificateInstallation.AddressType.DNS,
            address="api.example.test",
        )
        CertificateInstallation.objects.create(
            certificate=self.certificate,
            address_type=CertificateInstallation.AddressType.IP,
            address="192.0.2.10",
        )
        model_admin = admin.site._registry[Certificate]
        response = model_admin.export_csv(
            RequestFactory().post("/registry/certificate/"),
            Certificate.objects.filter(pk=self.certificate.pk),
        )
        content = response.content.decode()
        self.assertIn("DNS: api.example.test", content)
        self.assertIn("IP Address: 192.0.2.10", content)

    def test_export_includes_cmdb_ci_id(self):
        mapping = CMDBIPMapping.objects.create(
            address="192.0.2.10",
            cmdb_ci_id="CI-1042",
        )
        CertificateInstallation.objects.create(
            certificate=self.certificate,
            address_type=CertificateInstallation.AddressType.IP,
            address="192.0.2.10",
            cmdb_mapping=mapping,
        )
        model_admin = admin.site._registry[Certificate]
        response = model_admin.export_csv(
            RequestFactory().post("/registry/certificate/"),
            Certificate.objects.filter(pk=self.certificate.pk),
        )
        self.assertIn("ID Zasobu: CI-1042", response.content.decode())

    def test_registry_groups_have_installation_permissions(self):
        from django.contrib.auth.models import Group

        editor_permissions = set(
            Group.objects.get(name="Rejestr: Edytor").permissions.values_list("codename", flat=True)
        )
        auditor_permissions = set(
            Group.objects.get(name="Rejestr: Audytor").permissions.values_list("codename", flat=True)
        )
        self.assertIn("add_certificateinstallation", editor_permissions)
        self.assertIn("view_certificateinstallation", auditor_permissions)
        self.assertIn("view_historicalcertificateinstallation", auditor_permissions)
        self.assertNotIn("add_certificateinstallation", auditor_permissions)
        self.assertIn("add_cmdbipmapping", editor_permissions)
        self.assertIn("view_historicalcmdbipmapping", auditor_permissions)
        self.assertNotIn("add_cmdbconfigurationitem", editor_permissions)
        self.assertNotIn("add_cmdbipaddress", editor_permissions)


class CMDBImportTests(TestCase):
    def _run_import(self, contents, dry_run=False):
        with NamedTemporaryFile(mode="w+", encoding="utf-8", suffix=".csv") as csv_file:
            csv_file.write(contents)
            csv_file.flush()
            out = StringIO()
            err = StringIO()
            args = ["--file", csv_file.name]
            if dry_run:
                args.append("--dry-run")
            try:
                call_command("import_cmdb_ip_mappings", *args, stdout=out, stderr=err)
            except CommandError as exc:
                return out.getvalue(), err.getvalue(), exc
        return out.getvalue(), err.getvalue(), None

    def test_import_creates_system_and_allows_ambiguous_ip(self):
        out, err, error = self._run_import(
            "ip,cmdb_ci_id,cmdb_name,ict_system\n"
            "192.0.2.10,CI-1,Payments DB,Payments\n"
            "192.0.2.10,CI-2,Reports DB,Reporting\n"
        )
        self.assertIsNone(error)
        self.assertIn("2 dodano", out)
        self.assertEqual(err, "")
        self.assertEqual(CMDBIPMapping.objects.filter(address="192.0.2.10").count(), 2)
        self.assertEqual(ICTSystem.objects.count(), 2)
        self.assertEqual(
            CMDBIPMapping.objects.get(cmdb_ci_id="CI-1").name,
            "Payments DB",
        )

    def test_import_links_assets_to_system_by_cmdb_snsi(self):
        out, err, error = self._run_import(
            "ip,cmdb_ci_id,ict_system,ict_system_cmdb_snsi\n"
            "192.0.2.10,CI-1,Payments,SYS-100\n"
            "192.0.2.11,CI-2,Payments,SYS-100\n"
        )
        self.assertIsNone(error)
        self.assertEqual(err, "")
        self.assertIn("2 dodano", out)

        system = ICTSystem.objects.get(cmdb_snsi="SYS-100")
        mappings = CMDBIPMapping.objects.filter(ict_system=system)
        self.assertEqual(system.name, "Payments")
        self.assertEqual(mappings.count(), 2)
        self.assertEqual(ICTSystem.objects.count(), 1)

    def test_import_adds_cmdb_snsi_to_an_existing_system_by_name(self):
        system = ICTSystem.objects.create(name="Payments")
        out, _, error = self._run_import(
            "ip,cmdb_ci_id,ict_system,ict_system_cmdb_snsi\n"
            "192.0.2.10,CI-1,Payments,SYS-100\n"
        )
        self.assertIsNone(error)
        self.assertIn("1 dodano", out)

        system.refresh_from_db()
        self.assertEqual(system.cmdb_snsi, "SYS-100")
        self.assertEqual(CMDBIPMapping.objects.get().ict_system, system)
        self.assertEqual(ICTSystem.objects.count(), 1)

    def test_import_rejects_cmdb_snsi_longer_than_10_characters(self):
        out, err, error = self._run_import(
            "ip,cmdb_ci_id,ict_system,ict_system_cmdb_snsi\n"
            "192.0.2.10,CI-1,Payments,TOO-LONG-VALUE\n"
        )
        self.assertIsInstance(error, CommandError)
        self.assertIn("przekracza 10 znaków", err)
        self.assertEqual(CMDBIPMapping.objects.count(), 0)
        self.assertEqual(ICTSystem.objects.count(), 0)

    def test_import_dry_run_does_not_save(self):
        out, _, error = self._run_import(
            "ip,cmdb_ci_id,ict_system\n192.0.2.10,CI-1,Payments\n",
            dry_run=True,
        )
        self.assertIsNone(error)
        self.assertIn("Podgląd: 1 dodano", out)
        self.assertEqual(CMDBIPMapping.objects.count(), 0)
        self.assertEqual(ICTSystem.objects.count(), 0)

    def test_import_reports_invalid_rows_and_updates_existing_mapping(self):
        CMDBIPMapping.objects.create(
            address="192.0.2.10",
            cmdb_ci_id="CI-1",
        )
        out, err, error = self._run_import(
            "ip;cmdb_ci_id;cmdb_name;ict_system\n"
            "192.0.2.10;CI-1;Payments database;Payments\n"
            "not-an-ip;CI-2;Reporting database;Payments\n"
        )
        self.assertIsInstance(error, CommandError)
        self.assertIn("1 zaktualizowano", out)
        self.assertIn("1 wierszy z błędami", out)
        self.assertIn("nieprawidłowy adres IP", err)
        self.assertEqual(
            CMDBIPMapping.objects.get(cmdb_ci_id="CI-1").ict_system.name,
            "Payments",
        )
        self.assertEqual(CMDBIPMapping.objects.get(cmdb_ci_id="CI-1").name, "Payments database")


class TenableSyncTests(TestCase):
    def setUp(self):
        self.pem, _ = make_pem(cn="discovered.example.test")
        self.parsed_pem = parse_pem(self.pem)
        self.finding = {
            "ip": "192.0.2.30",
            "dnsName": "discovered.example.test",
            "port": "65535",
            "protocol": "tcp",
            "lastSeen": "2026-10-04T12:30:00Z",
            "repository": {"name": "Production"},
            "pluginOutput": (
                f"SHA256 Fingerprint: {self.parsed_pem['fingerprint_sha256']}\n{self.pem}"
            ),
        }

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_imports_fingerprint_and_maps_endpoint_to_ict(self, fetch):
        system = ICTSystem.objects.create(name="Payments")
        mapping = CMDBIPMapping.objects.create(
            address="192.0.2.30",
            cmdb_ci_id="CI-30",
            ict_system=system,
        )
        fetch.return_value = [self.finding]
        out = StringIO()
        call_command("sync_tenable_certificates", stdout=out)

        certificate = Certificate.objects.get()
        self.assertEqual(certificate.fingerprint_sha256, self.parsed_pem["fingerprint_sha256"])
        self.assertIsNone(certificate.ict_system)
        ip_installation = certificate.installations.get(address_type="ip")
        dns_installation = certificate.installations.get(
            address_type="dns", source=CertificateInstallation.Source.TENABLE
        )
        self.assertEqual(ip_installation.ict_system, system)
        self.assertEqual(ip_installation.cmdb_mapping, mapping)
        self.assertEqual(dns_installation.ict_system, system)
        self.assertEqual(ip_installation.source, CertificateInstallation.Source.TENABLE)
        self.assertEqual(ip_installation.port, 65535)
        self.assertEqual(ip_installation.protocol, "tcp")
        self.assertEqual(ip_installation.repository, "Production")
        self.assertIn("1 nowych certyfikatów", out.getvalue())

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_is_idempotent_and_preserves_manual_fields(self, fetch):
        certificate = Certificate.objects.create(
            name="Hand-maintained name",
            fingerprint_sha256=self.parsed_pem["fingerprint_sha256"],
            status=Certificate.Status.REVOKED,
            notes="Keep this note",
        )
        fetch.return_value = [self.finding, self.finding]
        call_command("sync_tenable_certificates", stdout=StringIO())

        certificate.refresh_from_db()
        self.assertEqual(Certificate.objects.count(), 1)
        self.assertEqual(certificate.name, "Hand-maintained name")
        self.assertEqual(certificate.status, Certificate.Status.REVOKED)
        self.assertEqual(certificate.notes, "Keep this note")
        self.assertEqual(certificate.installations.count(), 2)

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_deactivates_missing_tenable_installations_and_reactivates_returning_ones(self, fetch):
        fetch.return_value = [self.finding]
        call_command("sync_tenable_certificates", stdout=StringIO())
        certificate = Certificate.objects.get()
        manual_installation = CertificateInstallation.objects.create(
            certificate=certificate,
            address_type=CertificateInstallation.AddressType.DNS,
            address="manual.example.test",
            source=CertificateInstallation.Source.MANUAL,
        )

        dns_finding = {**self.finding, "ip": ""}
        fetch.return_value = [dns_finding]
        out = StringIO()
        call_command("sync_tenable_certificates", stdout=out)

        ip_installation = certificate.installations.get(
            address_type="ip", source=CertificateInstallation.Source.TENABLE
        )
        dns_installation = certificate.installations.get(
            address_type="dns", source=CertificateInstallation.Source.TENABLE
        )
        self.assertFalse(ip_installation.is_active)
        self.assertTrue(dns_installation.is_active)
        manual_installation.refresh_from_db()
        self.assertTrue(manual_installation.is_active)
        self.assertIn("1 dezaktywowanych", out.getvalue())

        fetch.return_value = [self.finding]
        call_command("sync_tenable_certificates", stdout=StringIO())
        ip_installation.refresh_from_db()
        self.assertTrue(ip_installation.is_active)

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_does_not_deactivate_on_empty_or_incomplete_results(self, fetch):
        fetch.return_value = [self.finding]
        call_command("sync_tenable_certificates", stdout=StringIO())
        installation = CertificateInstallation.objects.get(address_type="ip")

        fetch.return_value = []
        call_command("sync_tenable_certificates", stdout=StringIO(), stderr=StringIO())
        installation.refresh_from_db()
        self.assertTrue(installation.is_active)

        fetch.return_value = [{"ip": "192.0.2.30", "pluginOutput": "missing certificate"}]
        with self.assertRaises(CommandError):
            call_command("sync_tenable_certificates", stdout=StringIO(), stderr=StringIO())
        installation.refresh_from_db()
        self.assertTrue(installation.is_active)

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_leaves_system_unset_for_unmatched_or_ambiguous_ip(self, fetch):
        CMDBIPMapping.objects.create(address="192.0.2.30", cmdb_ci_id="CI-1")
        CMDBIPMapping.objects.create(address="192.0.2.30", cmdb_ci_id="CI-2")
        fetch.return_value = [self.finding]
        err = StringIO()
        call_command("sync_tenable_certificates", stdout=StringIO(), stderr=err)
        installations = Certificate.objects.get().installations.all()
        self.assertTrue(all(item.ict_system_id is None for item in installations))
        self.assertTrue(all(item.cmdb_mapping_id is None for item in installations))
        self.assertIn("pasuje do 2 zasobów CMDB", err.getvalue())

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_leaves_system_unset_when_ip_is_not_in_cmdb(self, fetch):
        fetch.return_value = [self.finding]
        out = StringIO()
        call_command("sync_tenable_certificates", stdout=out)
        installations = Certificate.objects.get().installations.all()
        self.assertTrue(all(item.ict_system_id is None for item in installations))
        self.assertIn("1 bez mapowania IP", out.getvalue())

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_dry_run_does_not_persist(self, fetch):
        fetch.return_value = [self.finding]
        out = StringIO()
        call_command("sync_tenable_certificates", "--dry-run", stdout=out)
        self.assertIn("Podgląd Tenable.sc", out.getvalue())
        self.assertEqual(Certificate.objects.count(), 0)

    @patch("registry.management.commands.sync_tenable_certificates.fetch_certificates")
    def test_sync_reports_and_skips_findings_without_fingerprint(self, fetch):
        fetch.return_value = [{"ip": "192.0.2.30", "pluginOutput": "no certificate details"}]
        out = StringIO()
        err = StringIO()
        with self.assertRaises(CommandError):
            call_command("sync_tenable_certificates", stdout=out, stderr=err)
        self.assertIn("1 pominiętych", out.getvalue())
        self.assertIn("fingerprint", err.getvalue())
        self.assertEqual(Certificate.objects.count(), 0)


class AdminTests(TestCase):
    def test_admin_links_cmdb_ci_id_to_installation(self):
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.create_superuser("cmdb-admin", "cmdb@x.pl", "pw")
        self.client.force_login(user)
        system = ICTSystem.objects.create(name="Payments")
        mapping = CMDBIPMapping.objects.create(
            address="192.0.2.10",
            cmdb_ci_id="CI-1042",
            ict_system=system,
        )
        form_response = self.client.get("/registry/certificate/add/")
        self.assertContains(form_response, "installation-inline.js")
        self.assertContains(form_response, "Powiązanie z zasobem CMDB (IP)")
        self.assertContains(form_response, "wybranie zasobu uzupełni adres IP")
        response = self.client.post(
            "/registry/certificate/add/",
            {
                "name": "gateway-cert",
                "kind": "tls_server",
                "environment": "prod",
                "ict_system": str(system.pk),
                "status": "active",
                "installations-TOTAL_FORMS": "1",
                "installations-INITIAL_FORMS": "0",
                "installations-MIN_NUM_FORMS": "0",
                "installations-MAX_NUM_FORMS": "1000",
                "installations-0-address_type": "ip",
                "installations-0-address": "192.0.2.10",
                "installations-0-cmdb_mapping": str(mapping.pk),
                "installations-0-source": "manual",
            },
        )
        self.assertEqual(response.status_code, 302)
        installation = Certificate.objects.get(name="gateway-cert").installations.get()
        self.assertEqual(installation.cmdb_mapping, mapping)
        self.assertEqual(installation.ict_system, system)
        self.assertEqual(installation.address, "192.0.2.10")

    def test_add_via_pem(self):
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.create_superuser("a", "a@x.pl", "pw")
        self.client.force_login(user)
        admin_index = self.client.get("/registry/")
        self.assertContains(admin_index, "registry/admin.css")
        self.assertContains(admin_index, "Rejestr certyfikatów (DORA)")
        pem, priv = make_pem()
        url = "/registry/certificate/add/"
        base = {
            "kind": "tls_server", "environment": "prod", "status": "active", "name": "",
            "installations-TOTAL_FORMS": "1", "installations-INITIAL_FORMS": "0",
            "installations-MIN_NUM_FORMS": "0", "installations-MAX_NUM_FORMS": "1000",
            "installations-0-address_type": "dns",
            "installations-0-address": "api.example.test",
            "installations-0-source": "manual",
        }
        r = self.client.post(url, {**base, "pem": pem + priv})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Certificate.objects.count(), 0)
        r = self.client.post(url, {**base, "pem": pem})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Certificate.objects.get().common_name, "example.test")
        self.assertEqual(
            Certificate.objects.get().installations.get().address,
            "api.example.test",
        )
        r = self.client.post(url, {**base, "pem": pem})
        self.assertEqual(r.status_code, 200)


class CMDBDataMigrationTests(TransactionTestCase):
    migrate_from = ("registry", "0007_remove_historicalcmdbipaddress_configuration_item_and_more")
    migrate_to = ("registry", "0010_remove_legacy_cmdb_models")

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        ICTSystemBefore = old_apps.get_model("registry", "ICTSystem")
        CertificateBefore = old_apps.get_model("registry", "Certificate")
        InstallationBefore = old_apps.get_model("registry", "CertificateInstallation")
        HistoricalInstallationBefore = old_apps.get_model(
            "registry", "HistoricalCertificateInstallation",
        )
        LegacyCI = old_apps.get_model("registry", "CMDBConfigurationItem")
        LegacyIP = old_apps.get_model("registry", "CMDBIPAddress")
        HistoricalLegacyCI = old_apps.get_model("registry", "HistoricalCMDBConfigurationItem")
        HistoricalLegacyIP = old_apps.get_model("registry", "HistoricalCMDBIPAddress")

        system = ICTSystemBefore.objects.create(name="Legacy payments")
        certificate = CertificateBefore.objects.create(name="legacy-cert", ict_system_id=system.pk)
        self.installation_id = InstallationBefore.objects.create(
            certificate_id=certificate.pk,
            address_type="ip",
            address="192.0.2.99",
            cmdb_ci_id="CI-LEGACY-99",
        ).pk
        HistoricalInstallationBefore.objects.create(
            id=self.installation_id,
            certificate_id=certificate.pk,
            address_type="ip",
            address="192.0.2.99",
            cmdb_ci_id="CI-LEGACY-99",
            history_date=timezone.now(),
            history_type="+",
        )

        unrelated_ci = LegacyCI.objects.create(
            cmdb_id="CI-NOT-INSTALLATION",
            name="Unrelated server",
            ict_system_id=system.pk,
        )
        unrelated_ip = LegacyIP.objects.create(
            configuration_item_id=unrelated_ci.pk,
            address="2001:0db8::42",
        )
        HistoricalLegacyCI.objects.create(
            id=unrelated_ci.pk,
            cmdb_id=unrelated_ci.cmdb_id,
            name=unrelated_ci.name,
            ict_system_id=system.pk,
            history_date=timezone.now(),
            history_type="+",
        )
        HistoricalLegacyIP.objects.create(
            id=unrelated_ip.pk,
            address=unrelated_ip.address,
            configuration_item_id=unrelated_ci.pk,
            history_date=timezone.now(),
            history_type="+",
        )

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        self.apps = executor.loader.project_state([self.migrate_to]).apps

    def tearDown(self):
        MigrationExecutor(connection).migrate([self.migrate_to])
        super().tearDown()

    def test_migration_preserves_ci_ip_system_and_history(self):
        Installation = self.apps.get_model("registry", "CertificateInstallation")
        HistoricalInstallation = self.apps.get_model(
            "registry", "HistoricalCertificateInstallation",
        )
        Mapping = self.apps.get_model("registry", "CMDBIPMapping")
        installation = Installation.objects.get(pk=self.installation_id)
        mapping = Mapping.objects.get(pk=installation.cmdb_mapping_id)
        self.assertEqual((mapping.address, mapping.cmdb_ci_id), ("192.0.2.99", "CI-LEGACY-99"))
        self.assertEqual(mapping.ict_system_id, installation.ict_system_id)
        self.assertEqual(installation.ict_system.name, "Legacy payments")

        Mapping = self.apps.get_model("registry", "CMDBIPMapping")
        unrelated_mapping = Mapping.objects.get(
            address="2001:db8::42",
            cmdb_ci_id="CI-NOT-INSTALLATION",
        )
        self.assertEqual(unrelated_mapping.ict_system_id, installation.ict_system_id)
        HistoricalMapping = self.apps.get_model("registry", "HistoricalCMDBIPMapping")
        self.assertTrue(HistoricalMapping.objects.filter(
            address="2001:db8::42",
            cmdb_ci_id="CI-NOT-INSTALLATION",
        ).exists())

        historical = HistoricalInstallation.objects.get(address="192.0.2.99")
        self.assertEqual(historical.cmdb_mapping.cmdb_ci_id, "CI-LEGACY-99")
        self.assertEqual(historical.ict_system_id, installation.ict_system_id)


class ICTSystemCriticalityMigrationTests(TransactionTestCase):
    migrate_from = ("registry", "0017_rename_ict_system_cmdb_id_to_snsi")
    migrate_to = ("registry", "0018_alter_historicalictsystem_criticality_and_more")

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        ICTSystemBefore = old_apps.get_model("registry", "ICTSystem")
        self.system_id = ICTSystemBefore.objects.create(
            name="Important system",
            criticality="important",
        ).pk

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        self.apps = executor.loader.project_state([self.migrate_to]).apps

    def tearDown(self):
        MigrationExecutor(connection).migrate([self.migrate_to])
        super().tearDown()

    def test_important_systems_become_standard_and_choice_is_removed(self):
        ICTSystem = self.apps.get_model("registry", "ICTSystem")
        system = ICTSystem.objects.get(pk=self.system_id)
        self.assertEqual(system.criticality, "standard")
        self.assertNotIn("important", dict(ICTSystem._meta.get_field("criticality").choices))
