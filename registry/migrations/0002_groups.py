from django.db import migrations

GROUPS = {
    "Rejestr: Administrator": ("view", "add", "change", "delete"),
    "Rejestr: Edytor": ("view", "add", "change"),
    "Rejestr: Audytor": ("view",),
}


def create_groups(apps, schema_editor):
    from django.contrib.auth.management import create_permissions

    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, verbosity=0)
        app_config.models_module = None

    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for name, actions in GROUPS.items():
        group, _ = Group.objects.get_or_create(name=name)
        perms = Permission.objects.filter(
            content_type__app_label="registry",
            codename__regex=r"^(%s)_(certificate|ictsystem|historical)" % "|".join(actions),
        )
        group.permissions.set(perms)


def remove_groups(apps, schema_editor):
    apps.get_model("auth", "Group").objects.filter(name__in=GROUPS).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("registry", "0001_initial"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]
    operations = [migrations.RunPython(create_groups, remove_groups)]
