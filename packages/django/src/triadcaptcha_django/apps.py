from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class TriadCaptchaConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "triadcaptcha_django"
    verbose_name = _("TriadCAPTCHA")

    def ready(self) -> None:
        # Import registers Django's deployment/system checks.
        from . import checks  # noqa: F401
