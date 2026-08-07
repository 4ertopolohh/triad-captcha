from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.health, name="health"),
    path("csrf/", views.csrf, name="csrf"),
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("lead/", views.lead, name="lead"),
]
