# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import django.db.models.signals as signals
import django.dispatch as dispatch
import policy.models as models
import policy.engine as engine


@dispatch.receiver(signals.post_save, sender=models.Rule)
@dispatch.receiver(signals.post_delete, sender=models.Rule)
def on_rule_change(sender, instance, **kwargs):
    rules = list(models.Rule.objects.all())
    for request in models.Request.objects.all():
        before = request.status, request.accepted_auth
        engine.apply_rules(rules=rules, request=request)
        after = request.status, request.accepted_auth
        if before != after:
            request.save()
