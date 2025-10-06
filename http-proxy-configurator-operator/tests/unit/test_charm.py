# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the http-proxy-configurator charm."""

import json
import uuid
from unittest.mock import MagicMock

import ops.testing
import pytest

from lib.charms.squid_forward_proxy.v0.http_proxy import HTTPProxyUnavailableError
from state import BackendRequestMissingError, InvalidCharmConfigError


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


def test_config_changed(context):
    """
    arrange: prepare some valid state without haproxy-route relation.
    act: trigger a config changed event.
    assert: status is blocked.
    """
    charm_state = ops.testing.State(
        config={"http-proxy-domains": "example.com"},
        leader=True,
        relations=[
            ops.testing.Relation(
                endpoint="http-proxy",
            )
        ],
    )

    out = context.run(context.on.config_changed(), charm_state)
    assert out.unit_status == ops.testing.ActiveStatus()


def test_get_proxies_action(context):
    """
    arrange: prepare some valid state without haproxy-route relation.
    act: trigger a config changed event.
    assert: status is blocked.
    """
    requirer_id = str(uuid.uuid4())
    proxy_address = "http://10.0.0.1:3128/"
    charm_state = ops.testing.State(
        config={"http-proxy-domains": "example.com"},
        leader=True,
        relations=[
            ops.testing.Relation(
                endpoint="http-proxy",
                local_app_data={
                    "requests": json.dumps(
                        [
                            {
                                "group": 1,
                                "requirer": requirer_id,
                                "domains": ["example.com:80", "example.com:443"],
                                "auth": ["none"],
                                "src_ips": ["10.251.46.148"],
                                "implicit_src_ips": True,
                            }
                        ]
                    )
                },
                remote_app_data={
                    "responses": json.dumps(
                        [
                            {
                                "auth": "none",
                                "http_proxy": proxy_address,
                                "https_proxy": proxy_address,
                                "requirer": requirer_id,
                                "status": "ready",
                            }
                        ]
                    )
                },
            )
        ],
    )

    context.run(context.on.action("get-proxies"), charm_state)
    assert context.action_results.get("http-proxy") == proxy_address
    assert context.action_results.get("https-proxy") == proxy_address


@pytest.mark.parametrize(
    "error_with_status",
    [
        (InvalidCharmConfigError, ops.testing.BlockedStatus()),
        (BackendRequestMissingError, ops.testing.WaitingStatus()),
    ],
)
def test_config_changed_state_error(context, monkeypatch: pytest.MonkeyPatch, error_with_status):
    """
    arrange: prepare some valid state without haproxy-route relation.
    act: trigger a config changed event.
    assert: status is blocked.
    """
    error, status = error_with_status
    monkeypatch.setattr("state.State.from_charm", MagicMock(side_effect=error))
    charm_state = ops.testing.State(
        config={"http-proxy-domains": "example.com"},
        leader=True,
        relations=[
            ops.testing.Relation(
                endpoint="http-proxy",
            )
        ],
    )

    out = context.run(context.on.config_changed(), charm_state)
    assert out.unit_status == status
