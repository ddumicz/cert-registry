from datetime import timedelta
from ipaddress import ip_address

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import DomainNameValidator, MaxValueValidator, validate_ipv46_address
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords

WARN_DAYS = 30
CRITICAL_DAYS = 7


class ICTSystem(models.Model):
    class Criticality(models.TextChoices):
        CRITICAL = "critical", "Krytyczna funkcja"
        IMPORTANT = "important", "Ważna funkcja"
        STANDARD = "standard", "Standardowa"

    name = models.CharField("nazwa", max_length=200, unique=True)
    cmdb_id = models.CharField(
        "CMDB_ID", max_length=128, unique=True, null=True, blank=True,
        help_text="Stabilny identyfikator systemu w zewnętrznej CMDB.",
    )
    description = models.TextField("opis", blank=True)
    criticality = models.CharField(
        "krytyczność", max_length=16, choices=Criticality.choices, default=Criticality.STANDARD
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, verbose_name="właściciel", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    history = HistoricalRecords()

    class Meta:
        verbose_name = "system ICT"
        verbose_name_plural = "systemy ICT"
        ordering = ["name"]

    def __str__(self):
        return self.name


class CMDBIPMapping(models.Model):
    address = models.GenericIPAddressField("adres IP")
    cmdb_ci_id = models.CharField("ID CI zasobu", max_length=128)
    ict_system = models.ForeignKey(
        ICTSystem, verbose_name="system ICT", null=True, blank=True,
        on_delete=models.PROTECT, related_name="cmdb_ip_mappings",
    )
    history = HistoricalRecords()

    class Meta:
        verbose_name = "zasób CMDB"
        verbose_name_plural = "zasoby CMDB"
        ordering = ["address", "cmdb_ci_id"]
        constraints = [
            models.UniqueConstraint(
                fields=("address", "cmdb_ci_id"),
                name="unique_cmdb_ip_ci_mapping",
            ),
        ]

    def __str__(self):
        return f"{self.address} — {self.cmdb_ci_id}"


class Certificate(models.Model):
    class Kind(models.TextChoices):
        TLS_SERVER = "tls_server", "TLS serwer"
        TLS_CLIENT = "tls_client", "TLS klient"
        SIGNING = "signing", "Podpisywanie"
        OTHER = "other", "Inny"

    class Status(models.TextChoices):
        ACTIVE = "active", "Aktywny"
        RENEWED = "renewed", "Odnowiony"
        REVOKED = "revoked", "Odwołany"
        RETIRED = "retired", "Wycofany"

    class Environment(models.TextChoices):
        PROD = "prod", "Produkcja"
        TEST = "test", "Test"
        DEV = "dev", "Dev"

    pem = models.TextField(
        "certyfikat PEM", blank=True,
        help_text="Wklej certyfikat (bez klucza prywatnego) – pola zostaną uzupełnione automatycznie.",
    )
    name = models.CharField("nazwa", max_length=200, blank=True)
    common_name = models.CharField("CN", max_length=255, blank=True)
    san = models.TextField("SAN", blank=True)
    serial_number = models.CharField("numer seryjny", max_length=128, blank=True)
    issuer = models.CharField("wystawca", max_length=512, blank=True)
    fingerprint_sha256 = models.CharField("odcisk SHA-256", max_length=64, unique=True, blank=True, null=True)
    not_before = models.DateTimeField("ważny od", null=True, blank=True)
    not_after = models.DateTimeField("ważny do", null=True, blank=True, db_index=True)
    key_algorithm = models.CharField("algorytm klucza", max_length=32, blank=True)
    key_size = models.PositiveIntegerField("rozmiar klucza", default=0)
    kind = models.CharField("typ", max_length=16, choices=Kind.choices, default=Kind.TLS_SERVER)
    environment = models.CharField("środowisko", max_length=8, choices=Environment.choices, default=Environment.PROD)
    ict_system = models.ForeignKey(
        ICTSystem, verbose_name="system ICT", null=True, blank=True,
        on_delete=models.PROTECT, related_name="certificates",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, verbose_name="właściciel", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    location = models.CharField("lokalizacja / użycie", max_length=255, blank=True)
    status = models.CharField("status", max_length=16, choices=Status.choices, default=Status.ACTIVE)
    renewed_at = models.DateField("data odnowienia", null=True, blank=True)
    notes = models.TextField("notatki", blank=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "certyfikat"
        verbose_name_plural = "certyfikaty"
        ordering = ["not_after"]

    def __str__(self):
        return self.name or self.common_name or f"Certyfikat #{self.pk}"

    @property
    def days_left(self):
        if not self.not_after:
            return None
        return (self.not_after - timezone.now()).days

    @property
    def expiry_state(self):
        d = self.days_left
        if d is None:
            return "unknown"
        if self.not_after <= timezone.now():
            return "expired"
        if d < CRITICAL_DAYS:
            return "critical"
        if d < WARN_DAYS:
            return "warning"
        return "ok"


def expiring_within(days):
    limit = timezone.now() + timedelta(days=days)
    return Certificate.objects.filter(status=Certificate.Status.ACTIVE, not_after__lte=limit)


class CertificateInstallation(models.Model):
    class AddressType(models.TextChoices):
        DNS = "dns", "DNS"
        IP = "ip", "IP Address"

    class Source(models.TextChoices):
        MANUAL = "manual", "Ręcznie"
        TENABLE = "tenable", "Tenable.sc"

    certificate = models.ForeignKey(
        Certificate, verbose_name="certyfikat", on_delete=models.CASCADE,
        related_name="installations",
    )
    ict_system = models.ForeignKey(
        ICTSystem, verbose_name="system ICT", null=True, blank=True,
        on_delete=models.PROTECT, related_name="certificate_installations",
    )
    address_type = models.CharField(
        "typ adresu", max_length=3, choices=AddressType.choices,
    )
    address = models.CharField("DNS / IP Address", max_length=253)
    cmdb_mapping = models.ForeignKey(
        CMDBIPMapping,
        verbose_name="powiązanie z zasobem CMDB (IP)",
        help_text=(
            "Dotyczy lokalizacji IP Address. Łączy znaleziony adres IP z rekordem CI; "
            "wybranie zasobu uzupełni adres IP, a system ICT zostanie uzupełniony przy zapisie."
        ),
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="certificate_installations",
    )
    source = models.CharField(
        "źródło", max_length=8, choices=Source.choices, default=Source.MANUAL,
    )
    port = models.PositiveIntegerField(
        "port", default=0, blank=True, validators=[MaxValueValidator(65535)],
    )
    protocol = models.CharField("protokół", max_length=32, blank=True)
    repository = models.CharField("repozytorium Tenable", max_length=128, blank=True)
    last_seen = models.DateTimeField("ostatnio widziano", null=True, blank=True)
    is_active = models.BooleanField("aktywna", default=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "lokalizacja instalacji"
        verbose_name_plural = "lokalizacje instalacji"
        ordering = ["address_type", "address"]
        constraints = [
            models.UniqueConstraint(
                fields=(
                    "certificate", "address_type", "address", "source",
                    "port", "protocol", "repository",
                ),
                name="unique_certificate_installation_endpoint",
            ),
        ]

    def clean(self):
        super().clean()
        if self.cmdb_mapping_id:
            if self.address_type != self.AddressType.IP:
                raise ValidationError({
                    "cmdb_mapping": "Zasób CMDB można przypisać tylko do lokalizacji typu IP Address.",
                })
            if not self.address:
                self.address = self.cmdb_mapping.address
            else:
                try:
                    normalized_address = str(ip_address(self.address))
                except ValueError as exc:
                    raise ValidationError({
                        "address": "Podaj prawidłowy adres IP zgodny z wybranym zasobem CMDB.",
                    }) from exc
                if normalized_address != self.cmdb_mapping.address:
                    raise ValidationError({
                        "address": "Adres IP musi być zgodny z wybranym zasobem CMDB.",
                    })
                self.address = normalized_address
            if self.cmdb_mapping.ict_system_id:
                self.ict_system = self.cmdb_mapping.ict_system

        if not self.address:
            raise ValidationError({"address": "Podaj DNS lub adres IP."})
        try:
            if self.address_type == self.AddressType.DNS:
                try:
                    ip_address(self.address)
                except ValueError:
                    pass
                else:
                    raise ValidationError(
                        "Adres IP należy zapisać jako typ IP Address.",
                    )
                DomainNameValidator()(self.address)
            elif self.address_type == self.AddressType.IP:
                validate_ipv46_address(self.address)
        except ValidationError as exc:
            raise ValidationError({"address": exc.messages}) from exc

    def __str__(self):
        return f"{self.get_address_type_display()}: {self.address}"
