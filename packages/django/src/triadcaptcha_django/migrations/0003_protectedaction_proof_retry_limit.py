from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("triadcaptcha_django", "0002_russian_admin_labels")]

    operations = [
        migrations.AddField(
            model_name="protectedaction",
            name="proof_retry_limit",
            field=models.PositiveSmallIntegerField(
                default=3,
                validators=[MinValueValidator(1), MaxValueValidator(10)],
            ),
        ),
    ]
