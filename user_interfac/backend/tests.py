import os
from unittest import TestCase, skipUnless

DJANGO_CONFIGURED = bool(os.environ.get("DJANGO_SETTINGS_MODULE"))
if DJANGO_CONFIGURED:
    from django.test import SimpleTestCase as DjangoSimpleTestCase
else:  # pragma: no cover - repo-root unittest discovery has no Django settings
    DjangoSimpleTestCase = TestCase


@skipUnless(DJANGO_CONFIGURED, "django settings are configured by manage.py")
class AnalystUiTests(DjangoSimpleTestCase):
    def test_home_embeds_reactpy_shell(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "components.comp.app")
        self.assertContains(response, "Network AI analyst")

