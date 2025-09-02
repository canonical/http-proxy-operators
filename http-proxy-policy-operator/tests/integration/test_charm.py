#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import logging

import pytest

import http_proxy

logger = logging.getLogger(__name__)


async def test_http_proxy_policy_server(policy_client):
    """
    arrange: deploy the http-proxy-policy charm.
    act: connect to the http-proxy-policy on the charm machine.
    assert: the server should respond correctly.
    """
    for rule in policy_client.list_rules():
        policy_client.delete_rule(rule["id"])
    policy_client.create_rule(domains=["example.com"], verdict="accept")
    rules = policy_client.list_rules()
    assert rules


async def test_proxy_requests(
    ops_test, policy_client, requirer_charm_a, requirer_charm_b, requirer_charm_c
):
    """
    arrange: deploy the http-proxy-policy charm with some proxy requirer charms.
    act: add some rules to the http-proxy-policy and integrate the requirer charms.
    assert: the requirer charm should receive the http proxy response according to the rules.
    """
    for rule in policy_client.list_rules():
        policy_client.delete_rule(rule["id"])
    policy_client.create_rule(domains=["example.com"], verdict="accept")
    policy_client.create_rule(domains=["example.org"], verdict="reject")

    await requirer_charm_a.request_proxy(
        domains=["example.com"],
        auth=[
            http_proxy.AUTH_METHOD_SRCIP_USERPASS,
            http_proxy.AUTH_METHOD_USERPASS,
            http_proxy.AUTH_METHOD_SRCIP,
            http_proxy.AUTH_METHOD_NONE,
        ],
    )
    await requirer_charm_b.request_proxy(
        domains=["example.org"],
        auth=[
            http_proxy.AUTH_METHOD_NONE,
        ],
    )
    await requirer_charm_c.request_proxy(
        domains=["example.net"],
        auth=[
            http_proxy.AUTH_METHOD_USERPASS,
            http_proxy.AUTH_METHOD_NONE,
        ],
    )

    await ops_test.model.wait_for_idle()

    assert await requirer_charm_a.get_proxies() == {
        "http": "http://test:test@proxy.test",
        "https": "https://test:test@proxy.test",
    }
    with pytest.raises(http_proxy.HTTPProxyNotAvailableError) as exc_info:
        await requirer_charm_b.get_proxies()
    assert "rejected" == exc_info.status
    with pytest.raises(http_proxy.HTTPProxyNotAvailableError) as exc_info:
        await requirer_charm_c.get_proxies()
    assert "pending" == exc_info.status
