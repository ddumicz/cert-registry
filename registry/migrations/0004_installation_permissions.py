from django.contrib.auth.management import create_permissions
from django.db import migrations


GROUP_PERMISSIONS = {
    "Rejestr: Administrator": ("view", "add", "change", "delete"),
    "Rejestr: Edytor": ("view", "add", "change"),
    "Rejestr: Audytor": ("view",),
}


def grant_installation_permissions(apps, schema_editor):
    for app_config in apps.get_app_configs():
        if app_config.label == "registry":
            app_config.models_module = True
            create_permissions(app_config, verbosity=0)
            app_config.models_module = None

    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for group_name, actions in GROUP_PERMISSIONS.items():
        group = Group.objects.get(name=group_name)
        permissions = Permission.objects.filter(
            content_type__app_label="registry",
            codename__regex=r"^(%s)_(certificateinstallation|historicalcertificateinstallation)$"
            % "|".join(actions),
        )
        group.permissions.add(*permissions)


def revoke_installation_permissions(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    permissions = Permission.objects.filter(
        content_type__app_label="registry",
        codename__regex=r"^(view|add|change|delete)_(certificateinstallation|historicalcertificateinstallation)$",
    )
    for group_name in GROUP_PERMISSIONS:
        Group.objects.get(name=group_name).permissions.remove(*permissions)


class Migration(migrations.Migration):
    dependencies = [
        ("registry", "0003_historicalcertificateinstallation_and_more"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunPython(grant_installation_permissions, revoke_installation_permissions),
    ]
