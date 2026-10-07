from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0015_clarify_cmdb_asset_ci_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificateinstallation",
            name="is_active",
            field=models.BooleanField(default=True, verbose_name="aktywna"),
        ),
        migrations.AddField(
            model_name="historicalcertificateinstallation",
            name="is_active",
            field=models.BooleanField(default=True, verbose_name="aktywna"),
        ),
    ]
