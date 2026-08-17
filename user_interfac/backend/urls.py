from django.urls import path, include, re_path
from .views import home

urlpatterns = [
    path("reactpy/", include("reactpy_django.http.urls")),
    path("", home, name='home'),
    re_path(
        r"^.*$",home, name="network-ai-router"),
		]
