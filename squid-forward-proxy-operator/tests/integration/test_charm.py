#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import logging

import pytest
import requests

import http_proxy

logger = logging.getLogger(__name__)


async def test_proxy(ops_test, any_charm_a):
    """
    arrange: create the testing model and deploy the Squid proxy charm and any-charm
    act: instruct any-charm to request an HTTP proxy from the Squid proxy charm
    assert: the returned proxy should satisfy the request
    """
    await any_charm_a.request_proxy(
        domains=["example.com"],
        auth=[http_proxy.AUTH_METHOD_NONE],
    )

    await ops_test.model.wait_for_idle()

    assert await any_charm_a.test_proxy("https://example.com") == 200
    assert await any_charm_a.test_proxy("https://example.org") != 200


async def test_proxy_src_ips(ops_test, any_charm_a, any_charm_b):
    """
    arrange: create the testing model and deploy the Squid proxy charm and any charm
    act: instruct any-charm to request an HTTP proxy with restricted src_ips
    assert: the returned proxy should satisfy the request
    """
    await any_charm_a.request_proxy(
        domains=["example.com"],
        auth=[http_proxy.AUTH_METHOD_SRCIP],
    )
    await any_charm_b.request_proxy(
        domains=["example.org"],
        auth=[http_proxy.AUTH_METHOD_SRCIP],
    )

    await ops_test.model.wait_for_idle()

    proxies = await any_charm_a.get_proxies()
    assert "@" not in proxies["http"]

    assert await any_charm_a.test_proxy("https://example.com") == 200
    assert await any_charm_b.test_proxy("https://example.com") != 200

    assert await any_charm_a.test_proxy("https://example.org") != 200
    assert await any_charm_b.test_proxy("https://example.org") == 200


async def test_proxy_userpass(ops_test, any_charm_a, any_charm_b):
    """
    arrange: create the testing model and deploy the Squid proxy charm and any charm
    act: instruct any-charm to request an HTTP proxy with proxy authentication
    assert: the returned proxy should satisfy the request
    """
    await any_charm_a.request_proxy(
        domains=["example.com"],
        auth=[http_proxy.AUTH_METHOD_USERPASS],
    )
    await any_charm_b.request_proxy(
        domains=["example.org"],
        auth=[http_proxy.AUTH_METHOD_USERPASS],
    )

    await ops_test.model.wait_for_idle()

    proxies = await any_charm_a.get_proxies()
    assert "@" in proxies["http"]
    requests.get("https://example.com", proxies=proxies, timeout=5).raise_for_status()
    with pytest.raises(requests.exceptions.ProxyError):
        requests.get("https://example.net", proxies=proxies, timeout=5)

    assert await any_charm_a.test_proxy("https://example.com") == 200
    assert await any_charm_b.test_proxy("https://example.com") != 200

    assert await any_charm_a.test_proxy("https://example.org") != 200
    assert await any_charm_b.test_proxy("https://example.org") == 200


async def test_proxy_auth(ops_test, any_charm_a, any_charm_b, any_charm_c, any_charm_d):
    """
    arrange: create the testing model and deploy the Squid proxy charm and any charm
    act: instruct any-charm to request an HTTP proxy with different restrictions
    assert: the returned proxy should satisfy the request
    """
    await any_charm_a.request_proxy(
        domains=["ubuntu.com"],
        auth=[http_proxy.AUTH_METHOD_NONE],
    )
    await any_charm_b.request_proxy(
        domains=["example.com"],
        auth=[http_proxy.AUTH_METHOD_USERPASS],
    )
    await any_charm_c.request_proxy(
        domains=["example.net"],
        auth=[http_proxy.AUTH_METHOD_SRCIP],
    )
    await any_charm_d.request_proxy(
        domains=["example.org"],
        auth=[http_proxy.AUTH_METHOD_SRCIP_USERPASS],
    )

    await ops_test.model.wait_for_idle()

    assert await any_charm_a.test_proxy("https://ubuntu.com") == 200
    assert await any_charm_b.test_proxy("https://ubuntu.com") == 200
    assert await any_charm_c.test_proxy("https://ubuntu.com") == 200
    assert await any_charm_d.test_proxy("https://ubuntu.com") == 200

    assert await any_charm_a.test_proxy("https://example.com") != 200
    assert await any_charm_b.test_proxy("https://example.com") == 200
    assert await any_charm_c.test_proxy("https://example.com") != 200
    assert await any_charm_d.test_proxy("https://example.com") != 200

    assert await any_charm_a.test_proxy("https://example.net") != 200
    assert await any_charm_b.test_proxy("https://example.net") != 200
    assert await any_charm_c.test_proxy("https://example.net") == 200
    assert await any_charm_d.test_proxy("https://example.net") != 200

    assert await any_charm_a.test_proxy("https://example.org") != 200
    assert await any_charm_b.test_proxy("https://example.org") != 200
    assert await any_charm_c.test_proxy("https://example.org") != 200
    assert await any_charm_d.test_proxy("https://example.org") == 200


async def test_prometheus_exporter(ops_test, squid_proxy):
    """
    arrange: deploy the Squid proxy charm
    act: get prometheus-squid-exporter metrics endpoint
    assert: metrics endpoint returns squid metrics
    """
    for unit in squid_proxy.units:
        _, stdout, _ = await ops_test.juju(
            "ssh", unit.name, "curl", "-m", "10", "http://localhost:9301/metrics"
        )
        assert "squid_server_http_requests_total" in stdout
