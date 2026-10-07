from django.contrib.auth.management import create_permissions
from django.db import migrations


GROUP_PERMISSIONS = {
    "Rejestr: Administrator": ("view", "add", "change", "delete"),
    "Rejestr: Edytor": ("view", "add", "change"),
    "Rejestr: Audytor": ("view",),
}


def grant_mapping_permissions(apps, schema_editor):
    for app_config in apps.get_app_configs():
        if app_config.label == "registry":
            app_config.models_module = True
            create_permissions(app_config, verbosity=0)
            app_config.models_module = None

    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for group_name, actions in GROUP_PERMISSIONS.items():
        permissions = Permission.objects.filter(
            content_type__app_label="registry",
            codename__regex=r"^(%s)_(cmdbipmapping|historicalcmdbipmapping)$"
            % "|".join(actions),
        )
        Group.objects.get(name=group_name).permissions.add(*permissions)


def revoke_mapping_permissions(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    permissions = Permission.objects.filter(
        content_type__app_label="registry",
        codename__regex=r"^(view|add|change|delete)_(cmdbipmapping|historicalcmdbipmapping)$",
    )
    for group_name in GROUP_PERMISSIONS:
        Group.objects.get(name=group_name).permissions.remove(*permissions)


class Migration(migrations.Migration):
    dependencies = [
        ("registry", "0008_cmdbipmapping_historicalcmdbipmapping_and_more"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunPython(grant_mapping_permissions, revoke_mapping_permissions),
    ]
