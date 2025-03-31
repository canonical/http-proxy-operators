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
    request_ids = []
    for request in models.Request.objects.all():
        engine.apply_rules(rules=rules, request=request)
        request_ids.append(request.requirer)
        request.save()
