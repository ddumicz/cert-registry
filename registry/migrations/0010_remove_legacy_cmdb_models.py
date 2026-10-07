import django.core.validators
from django.db import migrations, models


def remove_cmdb_ip_columns_if_present(apps, schema_editor):
    connection = schema_editor.connection
    tables = set(connection.introspection.table_names())
    for model_name in (
        "CertificateInstallation",
        "HistoricalCertificateInstallation",
    ):
        Model = apps.get_model("registry", model_name)
        if Model._meta.db_table not in tables:
            continue
        with connection.cursor() as cursor:
            columns = {
                column.name
                for column in connection.introspection.get_table_description(
                    cursor, Model._meta.db_table,
                )
            }
        if "cmdb_ip_id" in columns:
            schema_editor.remove_field(Model, Model._meta.get_field("cmdb_ip"))


def restore_cmdb_ip_columns_if_missing(apps, schema_editor):
    connection = schema_editor.connection
    tables = set(connection.introspection.table_names())
    for model_name in (
        "CertificateInstallation",
        "HistoricalCertificateInstallation",
    ):
        Model = apps.get_model("registry", model_name)
        if Model._meta.db_table not in tables:
            continue
        with connection.cursor() as cursor:
            columns = {
                column.name
                for column in connection.introspection.get_table_description(
                    cursor, Model._meta.db_table,
                )
            }
        if "cmdb_ip_id" not in columns:
            schema_editor.add_field(Model, Model._meta.get_field("cmdb_ip"))


def delete_legacy_cmdb_tables_if_present(apps, schema_editor):
    existing_tables = set(schema_editor.connection.introspection.table_names())
    for model_name in (
        "HistoricalCMDBIPAddress",
        "HistoricalCMDBConfigurationItem",
        "CMDBIPAddress",
        "CMDBConfigurationItem",
    ):
        Model = apps.get_model("registry", model_name)
        if Model._meta.db_table in existing_tables:
            schema_editor.delete_model(Model)


def restore_legacy_cmdb_tables_if_missing(apps, schema_editor):
    existing_tables = set(schema_editor.connection.introspection.table_names())
    for model_name in (
        "CMDBConfigurationItem",
        "CMDBIPAddress",
        "HistoricalCMDBConfigurationItem",
        "HistoricalCMDBIPAddress",
    ):
        Model = apps.get_model("registry", model_name)
        if Model._meta.db_table not in existing_tables:
            schema_editor.create_model(Model)
            existing_tables.add(Model._meta.db_table)


class Migration(migrations.Migration):

    dependencies = [
        ("registry", "0009_cmdb_mapping_permissions"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    remove_cmdb_ip_columns_if_present,
                    restore_cmdb_ip_columns_if_missing,
                ),
            ],
            state_operations=[
                migrations.RemoveField(
                    model_name="certificateinstallation",
                    name="cmdb_ip",
                ),
                migrations.RemoveField(
                    model_name="historicalcertificateinstallation",
                    name="cmdb_ip",
                ),
            ],
        ),
        migrations.AlterField(
            model_name="certificateinstallation",
            name="port",
            field=models.PositiveIntegerField(
                blank=True,
                default=0,
                validators=[django.core.validators.MaxValueValidator(65535)],
                verbose_name="port",
            ),
        ),
        migrations.AlterField(
            model_name="historicalcertificateinstallation",
            name="port",
            field=models.PositiveIntegerField(
                blank=True,
                default=0,
                validators=[django.core.validators.MaxValueValidator(65535)],
                verbose_name="port",
            ),
        ),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    delete_legacy_cmdb_tables_if_present,
                    restore_legacy_cmdb_tables_if_missing,
                ),
            ],
            state_operations=[
                migrations.DeleteModel(name="HistoricalCMDBIPAddress"),
                migrations.DeleteModel(name="HistoricalCMDBConfigurationItem"),
                migrations.DeleteModel(name="CMDBIPAddress"),
                migrations.DeleteModel(name="CMDBConfigurationItem"),
            ],
        ),
    ]
