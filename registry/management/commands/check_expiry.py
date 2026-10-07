from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand

from registry.models import expiring_within


class Command(BaseCommand):
    help = "Wypisuje aktywne certyfikaty wygasające w ciągu N dni (domyślnie 30) i opcjonalnie wysyła e-mail."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=30)
        parser.add_argument("--email", action="store_true", help="Wyślij do EXPIRY_ALERT_RECIPIENTS")

    def handle(self, *args, days, email, **opts):
        certs = list(expiring_within(days).select_related("ict_system"))
        if not certs:
            self.stdout.write("Brak certyfikatów wygasających w zadanym okresie.")
            return
        body = "\n".join(
            f"{c.not_after:%Y-%m-%d} ({c.days_left} dni) {c} [{c.ict_system or '-'}] {c.get_environment_display()}"
            for c in certs
        )
        self.stdout.write(body)
        if email and settings.EXPIRY_ALERT_RECIPIENTS:
            send_mail(
                f"[Rejestr certyfikatów] {len(certs)} wygasających w {days} dni",
                body, None, settings.EXPIRY_ALERT_RECIPIENTS,
            )
