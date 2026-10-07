import csv
from datetime import timedelta

from django import forms
from django.contrib import admin
from django.http import HttpResponse
from django.utils import timezone
from django.utils.html import format_html
from simple_history.admin import SimpleHistoryAdmin

from .models import (
    CRITICAL_DAYS,
    WARN_DAYS,
    CMDBIPMapping,
    Certificate,
    CertificateInstallation,
    ICTSystem,
)
from .services import PEMError, parse_pem

PARSED_FIELDS = (
    "common_name", "san", "serial_number", "issuer", "fingerprint_sha256",
    "not_before", "not_after", "key_algorithm", "key_size",
)
COLORS = {"ok": "green", "warning": "orange", "critical": "red", "expired": "darkred", "unknown": "gray"}


class ExpiryFilter(admin.SimpleListFilter):
    title = "wygaśnięcie"
    parameter_name = "expiry"

    def lookups(self, request, model_admin):
        return [
            ("expired", "Wygasłe"),
            ("7", f"< {CRITICAL_DAYS} dni"),
            ("30", f"< {WARN_DAYS} dni"),
            ("90", "< 90 dni"),
        ]

    def queryset(self, request, queryset):
        v = self.value()
        now = timezone.now()
        if v == "expired":
            return queryset.filter(not_after__lte=now)
        if v in ("7", "30", "90"):
            return queryset.filter(not_after__gt=now, not_after__lte=now + timedelta(days=int(v)))
        return queryset


class CertificateForm(forms.ModelForm):
    class Meta:
        model = Certificate
        fields = "__all__"

    def clean(self):
        data = super().clean()
        pem = (data.get("pem") or "").strip()
        if pem:
            try:
                parsed = parse_pem(pem)
            except PEMError as exc:
                raise forms.ValidationError(str(exc))
            duplicates = Certificate.objects.filter(fingerprint_sha256=parsed["fingerprint_sha256"])
            if self.instance.pk:
                duplicates = duplicates.exclude(pk=self.instance.pk)
            if duplicates.exists():
                raise forms.ValidationError("Ten certyfikat jest już w rejestrze.")
            data["pem"] = parsed["pem"]
            if not data.get("name"):
                data["name"] = parsed["common_name"]
            for f in PARSED_FIELDS:
                setattr(self.instance, f, parsed[f])
        elif not (data.get("name") or "").strip():
            raise forms.ValidationError("Podaj nazwę albo wklej certyfikat PEM.")
        return data


@admin.register(ICTSystem)
class ICTSystemAdmin(SimpleHistoryAdmin):
    list_display = ("name", "cmdb_id", "criticality", "owner")
    list_filter = ("criticality",)
    search_fields = ("name", "cmdb_id", "description")


@admin.register(CMDBIPMapping)
class CMDBIPMappingAdmin(SimpleHistoryAdmin):
    list_display = ("address", "cmdb_ci_id", "ict_system")
    list_filter = ("ict_system",)
    search_fields = ("address", "cmdb_ci_id", "ict_system__name")
    autocomplete_fields = ("ict_system",)


class CertificateInstallationInlineForm(forms.ModelForm):
    class Meta:
        model = CertificateInstallation
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["address"].required = False


class CertificateInstallationInline(admin.TabularInline):
    model = CertificateInstallation
    form = CertificateInstallationInlineForm
    extra = 1
    autocomplete_fields = ("ict_system", "cmdb_mapping")
    fields = (
        "address_type", "address", "ict_system", "cmdb_mapping",
        "source", "port", "protocol", "repository", "last_seen", "is_active",
    )

    class Media:
        js = ("registry/installation-inline.js",)


@admin.register(CertificateInstallation)
class CertificateInstallationAdmin(SimpleHistoryAdmin):
    list_display = (
        "certificate", "ict_system", "address_type", "address", "source", "port", "last_seen",
        "is_active",
    )
    list_filter = ("address_type", "source", "ict_system", "is_active")
    search_fields = (
        "address", "certificate__name", "certificate__common_name", "cmdb_mapping__cmdb_ci_id",
    )
    autocomplete_fields = ("certificate", "ict_system", "cmdb_mapping")


@admin.register(Certificate)
class CertificateAdmin(SimpleHistoryAdmin):
    form = CertificateForm
    inlines = (CertificateInstallationInline,)
    list_display = (
        "__str__", "ict_systems", "environment", "kind", "status", "not_after", "expiry", "owner",
    )
    list_filter = (ExpiryFilter, "status", "environment", "kind", "ict_system__criticality", "ict_system")
    search_fields = (
        "name", "common_name", "san", "serial_number", "issuer", "fingerprint_sha256",
        "installations__address", "installations__cmdb_mapping__cmdb_ci_id",
    )
    autocomplete_fields = ("ict_system",)
    actions = ["export_csv"]
    readonly_fields = PARSED_FIELDS

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("ict_system").prefetch_related(
            "installations__ict_system",
        )

    fieldsets = (
        ("Import", {"fields": ("pem",)}),
        ("Identyfikacja", {"fields": (
            "name", "kind", "environment", "ict_system", "owner", "location", "status", "renewed_at", "notes",
        )}),
        ("Dane z certyfikatu (automatyczne)", {"fields": PARSED_FIELDS}),
    )

    @admin.display(description="ważność")
    def expiry(self, obj):
        d = obj.days_left
        label = "—" if d is None else ("wygasł" if d < 0 else f"{d} dni")
        return format_html('<b style="color:{}">{}</b>', COLORS[obj.expiry_state], label)

    @admin.display(description="systemy ICT")
    def ict_systems(self, obj):
        systems = {installation.ict_system for installation in obj.installations.all() if installation.ict_system_id}
        if obj.ict_system_id:
            systems.add(obj.ict_system)
        return ", ".join(sorted(system.name for system in systems)) or "—"

    @admin.action(description="Eksportuj zaznaczone do CSV")
    def export_csv(self, request, queryset):
        resp = HttpResponse(content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = 'attachment; filename="certificates.csv"'
        w = csv.writer(resp)
        cols = ["name", "common_name", "san", "issuer", "serial_number", "fingerprint_sha256",
                "not_before", "not_after", "key_algorithm", "key_size", "kind", "environment",
                "ict_system", "owner", "status", "installations"]
        w.writerow(cols)
        for c in (
            queryset.select_related("ict_system", "owner")
            .prefetch_related("installations")
        ):
            row = []
            for col in cols:
                if col == "installations":
                    value = "; ".join(
                        f"{installation.get_address_type_display()}: {installation.address}"
                        + (f":{installation.port}" if installation.port else "")
                        + (
                            f" [ICT: {installation.ict_system}]"
                            if installation.ict_system_id else ""
                        )
                        + (
                            f" [CMDB CI: {installation.cmdb_mapping.cmdb_ci_id}]"
                            if installation.cmdb_mapping_id else ""
                        )
                        + (
                            f" [{installation.protocol}]"
                            if installation.protocol else ""
                        )
                        + (f" [Tenable: {installation.repository}]" if installation.repository else "")
                        + (" [nieaktywna]" if not installation.is_active else "")
                        for installation in c.installations.all()
                    )
                else:
                    value = getattr(c, col)
                row.append(_safe(value))
            w.writerow(row)
        return resp


def _safe(value):
    s = "" if value is None else str(value)
    # neutralise spreadsheet formula injection
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s
