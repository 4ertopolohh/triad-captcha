from django.urls import path

from .views import challenge_view

app_name = "triadcaptcha"

urlpatterns = [
    path("challenge/", challenge_view, name="challenge"),
]
