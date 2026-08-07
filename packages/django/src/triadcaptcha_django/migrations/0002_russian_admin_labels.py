from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("triadcaptcha_django", "0001_initial")]

    operations = [
        migrations.AlterModelOptions(
            name="protectionconfiguration",
            options={
                "verbose_name": "конфигурация защиты",
                "verbose_name_plural": "Конфигурация защиты",
            },
        ),
        migrations.AlterModelOptions(
            name="protectedaction",
            options={
                "ordering": ("action",),
                "verbose_name": "защищаемое действие",
                "verbose_name_plural": "Защищаемые действия",
            },
        ),
        migrations.AlterModelOptions(
            name="sitekeyversion",
            options={
                "ordering": ("-created_at",),
                "verbose_name": "версия публичного ключа",
                "verbose_name_plural": "Публичные ключи",
            },
        ),
        migrations.AlterModelOptions(
            name="blockrule",
            options={
                "ordering": ("-created_at",),
                "verbose_name": "правило блокировки",
                "verbose_name_plural": "Правила блокировки",
            },
        ),
        migrations.AlterModelOptions(
            name="securityevent",
            options={
                "ordering": ("-created_at",),
                "verbose_name": "событие безопасности",
                "verbose_name_plural": "Журнал безопасности",
            },
        ),
    ]
