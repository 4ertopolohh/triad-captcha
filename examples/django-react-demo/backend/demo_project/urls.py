from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/triadcaptcha/", include("triadcaptcha_django.urls")),
    path("api/", include("demo_api.urls")),
]

