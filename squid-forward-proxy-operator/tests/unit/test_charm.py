# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the squid proxy charm."""

# pylint: disable=protected-access,line-too-long

import json
import secrets
import textwrap
import typing
import uuid

import ops.testing

import http_proxy
import squid
from charm import SquidProxyCharm


def test_squid_charm_basic(mock_squid):
    """
    arrange: Set up the charm with an http-proxy integration.
    act: Simulate a config-changed event.
    assert: The charm updates configuration and password based on the request in the integration.
    """
    ctx = ops.testing.Context(SquidProxyCharm)
    integration = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": ["example.com", "example.org"],
                        "auth": [http_proxy.AUTH_METHOD_SRCIP_USERPASS],
                    }
                ]
            )
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[integration, ops.testing.PeerRelation(endpoint="squid-peer")],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert mock_squid.read_config() == textwrap.dedent(
        """\
        http_port 3128
        logfile_rotate 10000

        auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
        auth_param basic credentialsttl 60 seconds

        cache deny all

        # group: 1, id: 00000000-0000-4000-8000-000000000000
        acl rel1_00000000-0000-4000-8000-000000000000_0_domain dstdomain -n example.com
        acl rel1_00000000-0000-4000-8000-000000000000_0_port port 80 443
        acl rel1_00000000-0000-4000-8000-000000000000_0_src src 192.0.2.0
        acl rel1_00000000-0000-4000-8000-000000000000_0_user proxy_auth u1-1d7tmz9j2abdrls0
        http_access allow rel1_00000000-0000-4000-8000-000000000000_0_domain rel1_00000000-0000-4000-8000-000000000000_0_port rel1_00000000-0000-4000-8000-000000000000_0_src rel1_00000000-0000-4000-8000-000000000000_0_user
        acl rel1_00000000-0000-4000-8000-000000000000_1_domain dstdomain -n example.org
        acl rel1_00000000-0000-4000-8000-000000000000_1_port port 80 443
        acl rel1_00000000-0000-4000-8000-000000000000_1_src src 192.0.2.0
        acl rel1_00000000-0000-4000-8000-000000000000_1_user proxy_auth u1-1d7tmz9j2abdrls0
        http_access allow rel1_00000000-0000-4000-8000-000000000000_1_domain rel1_00000000-0000-4000-8000-000000000000_1_port rel1_00000000-0000-4000-8000-000000000000_1_src rel1_00000000-0000-4000-8000-000000000000_1_user

        access_log /var/log/squid/access.log squid

        http_access allow localhost manager
        http_access deny manager
        http_access deny all
        """  # noqa: E501 (line too long)
    )
    assert len(list(state_out.secrets)) == 1
    secret = [
        secret
        for secret in typing.cast(set, state_out.secrets)
        if "username" in secret.tracked_content
    ][0]
    assert json.loads(
        typing.cast(dict, state_out.get_relation(integration.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_SRCIP_USERPASS,
            "http_proxy": "http://192.0.2.0:3128",
            "https_proxy": "http://192.0.2.0:3128",
            "user": secret.id,
        }
    ]
    secret_content = typing.cast(dict, secret.latest_content)
    assert len(mock_squid.read_passwd().splitlines()) == 1
    passwd_user, passwd_hash = mock_squid.read_passwd().strip().split(":", maxsplit=1)
    assert passwd_user == secret_content["username"]
    assert squid._crypt_verify(passwd_hash, secret_content["password"])


def test_squid_charm_multiple_integrations(mock_squid):
    """
    arrange: Set up the charm with multiple http-proxy integration.
    act: Simulate a config-changed event.
    assert: The charm updates the configuration and password based on requests in integrations.
    """
    ctx = ops.testing.Context(SquidProxyCharm)
    integration1 = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": ["example.com"],
                        "auth": [http_proxy.AUTH_METHOD_SRCIP_USERPASS],
                    }
                ]
            )
        },
    )
    integration2 = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "domains": ["example.org"],
                        "auth": [http_proxy.AUTH_METHOD_NONE],
                    }
                ]
            )
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[integration1, integration2, ops.testing.PeerRelation(endpoint="squid-peer")],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert "00000000-0000-4000-8000-000000000000" in mock_squid.read_config()
    assert "00000000-0000-4000-9000-000000000000" in mock_squid.read_config()
    assert len(mock_squid.read_passwd().splitlines()) == 1
    assert len(list(state_out.secrets)) == 1


def test_squid_charm_handle_bad_integration(mock_squid):
    """
    arrange: Set up the charm with a bad integration.
    act: Simulate a config-changed event.
    assert: The charm detects the error in the integration.
    """
    ctx = ops.testing.Context(SquidProxyCharm)
    integration = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": ["example.com", "example.org"],
                        "auth": [http_proxy.AUTH_METHOD_NONE],
                    }
                ]
            )
        },
    )
    bad_integration = ops.testing.Relation(
        endpoint="http-proxy", remote_app_data={"requests": "{}"}
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[integration, bad_integration, ops.testing.PeerRelation(endpoint="squid-peer")],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert json.loads(
        typing.cast(dict, state_out.get_relation(integration.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_NONE,
            "http_proxy": "http://192.0.2.0:3128",
            "https_proxy": "http://192.0.2.0:3128",
        },
    ]
    assert (
        json.loads(
            typing.cast(dict, state_out.get_relation(bad_integration.id).local_app_data).get(
                "responses", "[]"
            )
        )
        == []
    )
    assert "00000000-0000-4000-8000-000000000000" in mock_squid.read_config()


def test_squid_charm_handle_invalid_request(mock_squid):
    """
    arrange: Set up the charm with a http-proxy integration using both valid and invalid requests.
    act: Simulate a config-changed event.
    assert: The charm should respond to the requests accordingly.
    """
    ctx = ops.testing.Context(SquidProxyCharm)
    integration = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": ["example.com"],
                        "auth": [http_proxy.AUTH_METHOD_NONE],
                    },
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "domains": ["example.com:123456"],
                        "auth": [http_proxy.AUTH_METHOD_NONE],
                    },
                ]
            )
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[integration, ops.testing.PeerRelation(endpoint="squid-peer")],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert json.loads(
        typing.cast(dict, state_out.get_relation(integration.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_NONE,
            "http_proxy": "http://192.0.2.0:3128",
            "https_proxy": "http://192.0.2.0:3128",
        },
        {
            "requirer": "00000000-0000-4000-9000-000000000000",
            "status": http_proxy.PROXY_STATUS_INVALID,
        },
    ]
    assert "00000000-0000-4000-8000-000000000000" in mock_squid.read_config()
    assert "00000000-0000-4000-9000-000000000000" not in mock_squid.read_config()


def test_squid_charm_handle_unsupported_request(mock_squid):
    """
    arrange: Set up the charm with a http-proxy integration using unsupported requests.
    act: Simulate a config-changed event.
    assert: The charm should respond to the requests with the unsupported status.
    """
    ctx = ops.testing.Context(SquidProxyCharm)
    integration = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": [],
                        "auth": [http_proxy.AUTH_METHOD_NONE],
                    },
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "domains": ["example.com:80"],
                        "auth": [],
                    },
                    {
                        "requirer": "00000000-0000-5000-9000-000000000000",
                        "domains": [],
                        "auth": [],
                    },
                ]
            )
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[integration, ops.testing.PeerRelation(endpoint="squid-peer")],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    responses = json.loads(
        typing.cast(dict, state_out.get_relation(integration.id).local_app_data)["responses"]
    )
    assert responses == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_UNSUPPORTED,
        },
        {
            "requirer": "00000000-0000-4000-9000-000000000000",
            "status": http_proxy.PROXY_STATUS_UNSUPPORTED,
        },
        {
            "requirer": "00000000-0000-5000-9000-000000000000",
            "status": http_proxy.PROXY_STATUS_UNSUPPORTED,
        },
    ]
    for response in responses:
        assert response["requirer"] not in mock_squid.read_config()


def test_squid_charm_update(mock_squid):
    """
    arrange: Set up the charm with a http-proxy integration with responses.
    act: Update the requests in the integration.
    assert: The charm should update responds to the requests accordingly.
    """
    ctx = ops.testing.Context(SquidProxyCharm)
    integration_id = 1
    username1 = mock_squid.derive_proxy_username(
        http_proxy.HttpProxySpec(
            group=integration_id,
            id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
            domains=("example.com",),
            auth=(http_proxy.AUTH_METHOD_USERPASS,),
        )
    )
    password1 = secrets.token_urlsafe(16)
    user_secret_1 = ops.testing.Secret(
        tracked_content={"username": username1, "password": password1}, owner="app"
    )
    integration = ops.testing.Relation(
        id=integration_id,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": ["example.com"],
                        "auth": [http_proxy.AUTH_METHOD_USERPASS],
                    },
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "domains": ["example.org"],
                        "auth": [http_proxy.AUTH_METHOD_NONE],
                    },
                ]
            )
        },
        local_app_data={
            "responses": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "status": http_proxy.PROXY_STATUS_READY,
                        "auth": http_proxy.AUTH_METHOD_USERPASS,
                        "user": user_secret_1.id,
                        "http_proxy": "http://192.0.2.0:3128",
                        "https_proxy": "http://192.0.2.0:3128",
                    }
                ]
            )
        },
    )
    old_passwd = f"{username1}:{squid._crypt_hash(password1)}"
    mock_squid.write_passwd(old_passwd)
    state_in = ops.testing.State(
        leader=True,
        relations=[integration, ops.testing.PeerRelation(endpoint="squid-peer")],
        secrets=[user_secret_1],
    )
    ctx.run(ctx.on.config_changed(), state_in)

    assert "00000000-0000-4000-8000-000000000000" in mock_squid.read_config()
    assert "00000000-0000-4000-9000-000000000000" in mock_squid.read_config()
    assert mock_squid.read_passwd() == old_passwd

    username2 = mock_squid.derive_proxy_username(
        http_proxy.HttpProxySpec(
            group=integration.id,
            id=uuid.UUID("00000000-0000-4000-9000-000000000000"),
            domains=("example.com",),
            auth=(http_proxy.AUTH_METHOD_USERPASS,),
        )
    )

    integration = ops.testing.Relation(
        id=integration_id,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "domains": ["example.com"],
                        "auth": [http_proxy.AUTH_METHOD_USERPASS],
                    },
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "domains": ["example.org"],
                        "auth": [http_proxy.AUTH_METHOD_USERPASS],
                    },
                ]
            )
        },
        local_app_data={
            "responses": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "status": http_proxy.PROXY_STATUS_READY,
                        "auth": http_proxy.AUTH_METHOD_USERPASS,
                        "user": user_secret_1.id,
                        "http_proxy": "http://192.0.2.0:3128",
                        "https_proxy": "http://192.0.2.0:3128",
                    }
                ]
            )
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[integration, ops.testing.PeerRelation(endpoint="squid-peer")],
        secrets=[user_secret_1],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    assert old_passwd in mock_squid.read_passwd()
    assert username2 in mock_squid.read_passwd()
    assert "00000000-0000-4000-8000-000000000000" in mock_squid.read_config()
    assert "00000000-0000-4000-9000-000000000000" in mock_squid.read_config()
    assert len(list(state_out.secrets)) == 2
    responses = json.loads(
        typing.cast(dict, state_out.get_relation(integration.id).local_app_data)["responses"]
    )
    secret_id = [r for r in responses if r["requirer"] == "00000000-0000-4000-9000-000000000000"][
        0
    ]["user"]
    assert (
        typing.cast(dict, state_out.get_secret(id=secret_id).tracked_content)["username"]
        == username2
    )
