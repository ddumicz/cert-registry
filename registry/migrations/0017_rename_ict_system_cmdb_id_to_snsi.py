from django.db import migrations, models


def validate_cmdb_snsi_length(apps, schema_editor):
    database = schema_editor.connection.alias
    for model_name in ("ICTSystem", "HistoricalICTSystem"):
        system_model = apps.get_model("registry", model_name)
        identifiers = (
            system_model.objects.using(database)
            .exclude(cmdb_id__isnull=True)
            .exclude(cmdb_id="")
            .values_list("cmdb_id", flat=True)
            .iterator()
        )
        for identifier in identifiers:
            if len(identifier) > 10:
                raise RuntimeError(
                    f"Cannot migrate {model_name}: a CMDB_ID exceeds 10 characters. "
                    "Shorten or clear the value before retrying the migration."
                )


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0016_certificateinstallation_is_active"),
    ]

    operations = [
        migrations.RunPython(validate_cmdb_snsi_length, migrations.RunPython.noop),
        migrations.RenameField(
            model_name="historicalictsystem",
            old_name="cmdb_id",
            new_name="cmdb_snsi",
        ),
        migrations.RenameField(
            model_name="ictsystem",
            old_name="cmdb_id",
            new_name="cmdb_snsi",
        ),
        migrations.AlterField(
            model_name="historicalictsystem",
            name="cmdb_snsi",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Stabilny identyfikator systemu w zewnętrznej CMDB.",
                max_length=10,
                null=True,
                verbose_name="CMDB_SNSI",
            ),
        ),
        migrations.AlterField(
            model_name="ictsystem",
            name="cmdb_snsi",
            field=models.CharField(
                blank=True,
                help_text="Stabilny identyfikator systemu w zewnętrznej CMDB.",
                max_length=10,
                null=True,
                unique=True,
                verbose_name="CMDB_SNSI",
            ),
        ),
    ]
