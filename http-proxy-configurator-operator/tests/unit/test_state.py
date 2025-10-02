# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
# pylint: disable=protected-access

"""Unit tests for the state module."""

from unittest.mock import Mock

import pytest
from ops import CharmBase

import state


def test_state_from_charm():
    """
    arrange: mock a charm with valid proxy configuration
    act: instantiate a State
    assert: the data matches the charm configuration
    """
    charm = Mock(CharmBase)
    charm.config = {
        "http-proxy-domains": "example.com,test.org",
        "http-proxy-auth": "none,srcip",
        "http-proxy-source-ips": "192.168.1.1,10.0.0.1",
    }
    charm_state = state.State.from_charm(charm)

    assert charm_state.http_proxy_domains == charm.config.get("http-proxy-domains").split(",")
    assert charm_state.http_proxy_auth == [
        state.ProxyAuthMethod.NONE,
        state.ProxyAuthMethod.SRC_IP,
    ]
    assert [str(ip) for ip in charm_state.http_proxy_source_ips] == charm.config.get(
        "http-proxy-source-ips"
    ).split(",")


def test_state_from_charm_empty_source_ips():
    """
    arrange: mock a charm with empty source IPs
    act: instantiate a State
    assert: source IPs list is empty
    """
    charm = Mock(CharmBase)
    charm.config = {
        "http-proxy-domains": "example.com",
        "http-proxy-auth": "none",
        "http-proxy-source-ips": "",
    }
    charm_state = state.State.from_charm(charm)

    assert not charm_state.http_proxy_source_ips


@pytest.mark.parametrize(
    "invalid_config",
    [
        pytest.param(
            {
                "http-proxy-domains": "",
                "http-proxy-auth": "none",
                "http-proxy-source-ips": "192.168.1.1",
            },
            id="missing-domains",
        ),
        pytest.param(
            {
                "http-proxy-domains": "example.com",
                "http-proxy-auth": "invalid",
                "http-proxy-source-ips": "192.168.1.1",
            },
            id="invalid-auth",
        ),
        pytest.param(
            {
                "http-proxy-domains": "example.com",
                "http-proxy-auth": "none,invalid,srcip",
                "http-proxy-source-ips": "192.168.1.1",
            },
            id="invalid-auth-list",
        ),
        pytest.param(
            {
                "http-proxy-domains": "example.com",
                "http-proxy-auth": "none",
                "http-proxy-source-ips": "999.999.999.999",
            },
            id="invalid-ip-address",
        ),
        pytest.param(
            {
                "http-proxy-domains": "example.com",
                "http-proxy-auth": "none",
                "http-proxy-source-ips": "not-an-ip",
            },
            id="invalid-ip-value",
        ),
        pytest.param(
            {
                "http-proxy-domains": None,
                "http-proxy-auth": None,
                "http-proxy-source-ips": None,
            },
            id="none-value",
        ),
        pytest.param(
            {
                "http-proxy-domains": "example.com",
                "http-proxy-auth": "srcip+userpass",
                "http-proxy-source-ips": "",
            },
            id="missing-source-ips-with-auth",
        ),
    ],
)
def test_state_from_charm_invalid_config(invalid_config):
    """
    arrange: mock a charm without domain configuration
    act: instantiate a State
    assert: an InvalidCharmConfigError is raised
    """
    charm = Mock(CharmBase)
    charm.config = invalid_config
    with pytest.raises(state.InvalidCharmConfigError):
        state.State.from_charm(charm)


def test_state_from_charm_ipv6_address():
    """
    arrange: mock a charm with valid IPv6 address
    act: instantiate a State
    assert: the IPv6 address is correctly parsed
    """
    charm = Mock(CharmBase)
    charm.config = {
        "http-proxy-domains": "example.com",
        "http-proxy-auth": "none",
        "http-proxy-source-ips": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    }
    charm_state = state.State.from_charm(charm)

    assert len(charm_state.http_proxy_source_ips) == 1
    assert str(charm_state.http_proxy_source_ips[0]) == "2001:db8:85a3::8a2e:370:7334"


def test_state_from_charm_mixed_ipv4_ipv6():
    """
    arrange: mock a charm with both IPv4 and IPv6 addresses
    act: instantiate a State
    assert: both address types are correctly parsed
    """
    charm = Mock(CharmBase)
    charm.config = {
        "http-proxy-domains": "example.com",
        "http-proxy-auth": "none",
        "http-proxy-source-ips": "192.168.1.1,2001:db8::1",
    }
    charm_state = state.State.from_charm(charm)

    assert len(charm_state.http_proxy_source_ips) == 2


def test__parse_charm_config_values_empty_string():
    """
    arrange: provide an empty string
    act: call _parse_charm_config_values
    assert: an empty list is returned
    """
    result = state._parse_charm_config_values("")
    assert result == []


def test__parse_charm_config_values_none():
    """
    arrange: provide None value
    act: call _parse_charm_config_values
    assert: an empty list is returned
    """
    result = state._parse_charm_config_values(None)
    assert result == []


def test__parse_charm_config_values_single_value():
    """
    arrange: provide a single value string
    act: call _parse_charm_config_values
    assert: a list with one element is returned
    """
    result = state._parse_charm_config_values("single")
    assert result == ["single"]


def test__parse_charm_config_values_multiple_values():
    """
    arrange: provide a comma-separated string
    act: call _parse_charm_config_values
    assert: a list with all values is returned
    """
    result = state._parse_charm_config_values("value1,value2,value3")
    assert result == ["value1", "value2", "value3"]


def test_proxy_auth_method_all():
    """
    arrange: N/A
    act: call ProxyAuthMethod.all()
    assert: all enum values are returned
    """
    all_methods = state.ProxyAuthMethod.all()
    assert all_methods == ["none", "srcip", "userpass", "srcip+userpass"]
    assert len(all_methods) == 4
