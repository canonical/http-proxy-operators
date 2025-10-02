# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the http-proxy-configurator charm."""

import ops.testing


def test_config_changed_no_http_proxy_relation(context):
    """
    arrange: prepare some valid state without haproxy-route relation.
    act: trigger a config changed event.
    assert: status is blocked.
    """
    charm_state = ops.testing.State(
        config={"http-proxy-domains": "example.com"},
        leader=True,
    )

    out = context.run(context.on.config_changed(), charm_state)
    assert out.unit_status == ops.testing.BlockedStatus("relation not found")
