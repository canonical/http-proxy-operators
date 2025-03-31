# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import contextlib

from django.db import transaction, connection


@contextlib.contextmanager
def serializable_isolation_transaction():
    with transaction.atomic():
        with connection.cursor() as cursor:
            if connection.settings_dict["ENGINE"] != "django.db.backends.sqlite3":
                cursor.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;")
        yield
