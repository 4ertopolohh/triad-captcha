import json

from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path

from triadcaptcha_django.decorators import protect


def _identity(request):
    if request.content_type == "application/json" and request.body:
        return {"type": "email", "value": json.loads(request.body).get("email", "")}
    return request.headers.get("X-Test-Identity")


@protect("register", identity_getter=_identity)
def protected_view(request):
    return JsonResponse({"ok": True})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/triadcaptcha/", include("triadcaptcha_django.urls")),
    path("protected/", protected_view),
]
