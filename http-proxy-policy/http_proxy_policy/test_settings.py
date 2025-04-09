# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from .settings import *

SECRET_KEY = "django-insecure-rd0s27&7ps_oeq_$1$mfh195!#xjeg!c73*3j^i5aza$7#(ngh"

DEBUG = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}
