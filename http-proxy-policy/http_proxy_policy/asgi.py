# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""
ASGI config for http_proxy_policy project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "http_proxy_policy.settings")

application = get_asgi_application()
