import json
import threading

from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path

from triadcaptcha_django.decorators import protect

_business_invocation_lock = threading.Lock()
_business_invocations = 0


def _identity(request):
    if request.content_type == "application/json" and request.body:
        return {"type": "email", "value": json.loads(request.body).get("email", "")}
    return request.headers.get("X-Test-Identity")


@protect("register", identity_getter=_identity)
def protected_view(request):
    global _business_invocations
    with _business_invocation_lock:
        _business_invocations += 1
    return JsonResponse({"ok": True})


def reset_business_invocations():
    global _business_invocations
    with _business_invocation_lock:
        _business_invocations = 0


def get_business_invocations():
    with _business_invocation_lock:
        return _business_invocations


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/triadcaptcha/", include("triadcaptcha_django.urls")),
    path("protected/", protected_view),
    path("protected-alias/", protected_view),
]
