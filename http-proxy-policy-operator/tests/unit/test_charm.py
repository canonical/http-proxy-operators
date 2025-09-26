# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the squid proxy charm."""

# pylint: disable=protected-access,line-too-long

import json
import unittest.mock
import uuid
from typing import cast

import ops.testing
from charms.squid_forward_proxy.v0 import http_proxy

import policy
from charm import HttpProxyPolicyCharm

EXAMPLE_RAW_REQUESTS = [
    {
        "requirer": "00000000-0000-4000-8000-000000000000",
        "domains": ["example.com"],
        "auth": [http_proxy.AUTH_METHOD_SRCIP_USERPASS],
    },
    {
        "requirer": "00000000-0000-4000-9000-000000000000",
        "domains": ["example.org"],
        "auth": [http_proxy.AUTH_METHOD_NONE],
    },
    {
        "requirer": "00000000-0000-4000-a000-000000000000",
        "domains": ["example.net"],
        "auth": [
            http_proxy.AUTH_METHOD_SRCIP_USERPASS,
            http_proxy.AUTH_METHOD_USERPASS,
            http_proxy.AUTH_METHOD_SRCIP,
            http_proxy.AUTH_METHOD_NONE,
        ],
    },
]

EXAMPLE_EVALUATED_REQUESTS = [
    policy.EvaluatedHttpProxyRequest(
        group=111,
        id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
        domains=("example.com",),
        auth=(http_proxy.AUTH_METHOD_SRCIP_USERPASS,),
        src_ips=("192.0.2.0",),
        implicit_src_ips=True,
        status=http_proxy.PROXY_STATUS_ACCEPTED,
        accepted_auth=http_proxy.AUTH_METHOD_SRCIP_USERPASS,
    ),
    policy.EvaluatedHttpProxyRequest(
        group=222,
        id=uuid.UUID("00000000-0000-4000-9000-000000000000"),
        domains=("example.org",),
        auth=(http_proxy.AUTH_METHOD_NONE,),
        src_ips=("192.0.2.0",),
        implicit_src_ips=True,
        status=http_proxy.PROXY_STATUS_REJECTED,
        accepted_auth=None,
    ),
    policy.EvaluatedHttpProxyRequest(
        group=333,
        id=uuid.UUID("00000000-0000-4000-a000-000000000000"),
        domains=("example.net",),
        auth=(
            http_proxy.AUTH_METHOD_SRCIP_USERPASS,
            http_proxy.AUTH_METHOD_USERPASS,
            http_proxy.AUTH_METHOD_SRCIP,
            http_proxy.AUTH_METHOD_NONE,
        ),
        src_ips=("192.0.2.0",),
        implicit_src_ips=True,
        status=http_proxy.PROXY_STATUS_PENDING,
        accepted_auth=None,
    ),
]


def test_reply_requests(mock_policy):
    """
    arrange: prepare HTTP proxy requirer relation, and PostgreSQL relation.
    act: run the config-changed event
    assert: the charm should respond proxy requests based on the return from the policy server
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation1 = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    relation2 = ops.testing.Relation(
        id=222,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[1]],
            )
        },
    )
    relation3 = ops.testing.Relation(
        id=333,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[2]],
            )
        },
    )
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
    )
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = EXAMPLE_EVALUATED_REQUESTS
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation1,
            relation2,
            relation3,
            backend_relation,
            pgsql_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert json.loads(
        cast(dict, state_out.get_relation(relation1.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_ACCEPTED,
        },
    ]
    assert json.loads(
        cast(dict, state_out.get_relation(relation2.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-9000-000000000000",
            "status": http_proxy.PROXY_STATUS_REJECTED,
        },
    ]
    assert json.loads(
        cast(dict, state_out.get_relation(relation3.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-a000-000000000000",
            "status": http_proxy.PROXY_STATUS_PENDING,
        },
    ]
    assert json.loads(
        cast(dict, state_out.get_relation(backend_relation.id).local_app_data)["requests"]
    ) == [
        {
            "auth": ["srcip+userpass"],
            "domains": ["example.com:80", "example.com:443"],
            "requirer": "00000000-0000-4000-8000-000000000000",
            "src_ips": ["192.0.2.0"],
        }
    ]
    assert state_out.app_status == ops.testing.ActiveStatus("accepted: 1, rejected: 1, pending: 1")


def test_relay_responses(mock_policy):
    """
    arrange: prepare HTTP proxy requirer relation, proxy backend relation, and PostgreSQL relation.
    act: run the config-changed event
    assert: the charm should respond to and relay proxy requests based on the return from the
            policy server
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = [EXAMPLE_EVALUATED_REQUESTS[0]]
    backend_secret = ops.testing.Secret(tracked_content={"username": "test", "password": "test"})
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
        remote_app_data={
            "responses": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-8000-000000000000",
                        "status": http_proxy.PROXY_STATUS_READY,
                        "auth": http_proxy.AUTH_METHOD_SRCIP_USERPASS,
                        "http_proxy": "http://proxy.test",
                        "https_proxy": "https://proxy.test",
                        "user": backend_secret.id,
                    }
                ]
            )
        },
    )
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation,
            backend_relation,
            pgsql_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
        secrets=[backend_secret],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    response = json.loads(
        cast(dict, state_out.get_relation(relation.id).local_app_data)["responses"]
    )
    new_secret = response[0]["user"]
    assert new_secret != backend_secret.id
    assert response == [
        {
            "auth": "srcip+userpass",
            "http_proxy": "http://proxy.test/",
            "https_proxy": "https://proxy.test/",
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": "ready",
            "user": new_secret,
        }
    ]


def test_invalid_requests(mock_policy):
    """
    arrange: prepare HTTP proxy requirer relation with invalid requests
    act: run the config-changed event
    assert: the charm should set the request as invalid.
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation1 = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    relation2 = ops.testing.Relation(endpoint="http-proxy", remote_app_data={"requests": "{}"})
    relation3 = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps([{"requirer": "00000000-0000-4000-b000-000000000000"}])
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = [EXAMPLE_EVALUATED_REQUESTS[0]]
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation1,
            relation2,
            relation3,
            pgsql_relation,
            backend_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert json.loads(
        cast(dict, state_out.get_relation(backend_relation.id).local_app_data)["requests"]
    ) == [
        {
            "auth": ["srcip+userpass"],
            "domains": ["example.com:80", "example.com:443"],
            "requirer": "00000000-0000-4000-8000-000000000000",
            "src_ips": ["192.0.2.0"],
        }
    ]
    assert mock_policy.HttpProxyPolicyClient.refresh.call_args_list == [
        unittest.mock.call(
            [
                http_proxy.HttpProxyRequest(
                    group=111,
                    id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                    domains=("example.com:80", "example.com:443"),
                    auth=("srcip+userpass",),
                    src_ips=("192.0.2.0",),
                    implicit_src_ips=True,
                )
            ]
        )
    ]
    assert json.loads(
        cast(dict, state_out.get_relation(backend_relation.id).local_app_data)["requests"]
    ) == [
        {
            "auth": ["srcip+userpass"],
            "domains": ["example.com:80", "example.com:443"],
            "requirer": "00000000-0000-4000-8000-000000000000",
            "src_ips": ["192.0.2.0"],
        }
    ]
    assert json.loads(
        cast(dict, state_out.get_relation(relation3.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-b000-000000000000",
            "status": http_proxy.PROXY_STATUS_INVALID,
        },
    ]
    assert state_out.app_status == ops.testing.ActiveStatus(
        "accepted: 1, invalid requests: 1, invalid integrations: 1"
    )


def test_unsupported_requests(mock_policy):  # pylint: disable=unused-argument
    """
    arrange: prepare HTTP proxy requirer relation with unsupported requests
    act: run the config-changed event
    assert: the charm should set the request as unsupported.
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation1 = ops.testing.Relation(
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [{"requirer": "00000000-0000-4000-b000-000000000000", "domains": [], "auth": []}]
            )
        },
    )
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation1,
            pgsql_relation,
            backend_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert json.loads(
        cast(dict, state_out.get_relation(relation1.id).local_app_data)["responses"]
    ) == [
        {
            "requirer": "00000000-0000-4000-b000-000000000000",
            "status": http_proxy.PROXY_STATUS_UNSUPPORTED,
        },
    ]
    assert state_out.app_status == ops.testing.ActiveStatus("unsupported: 1")


def test_ignore_duplicate_requests(mock_policy):
    """
    arrange: prepare HTTP proxy requirer relation with duplicate requests.
    act: run the config-changed event
    assert: the charm should ignore duplicate requests
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation1 = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    relation2 = ops.testing.Relation(
        id=222,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = []
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation1,
            relation2,
            pgsql_relation,
            backend_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert mock_policy.HttpProxyPolicyClient.refresh.call_args_list == [unittest.mock.call([])]
    assert (
        json.loads(
            cast(dict, state_out.get_relation(backend_relation.id).local_app_data).get(
                "requests", "[]"
            )
        )
        == []
    )
    assert state_out.app_status == ops.testing.ActiveStatus("duplicated: 2")


def test_cleanup_responses(mock_policy):
    """
    arrange: Prepare a proxy backend relation with a request that does not match any request
             from the proxy requirer.
    act: Run the config-changed event.
    assert: The charm should withdraw the request to the backend server.
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = [EXAMPLE_EVALUATED_REQUESTS[0]]
    backend_secret = ops.testing.Secret(tracked_content={"username": "test", "password": "test"})
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
        local_app_data={
            "requests": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "domains": ["test.com"],
                        "auth": [http_proxy.AUTH_METHOD_SRCIP_USERPASS],
                    }
                ]
            )
        },
        remote_app_data={
            "responses": json.dumps(
                [
                    {
                        "requirer": "00000000-0000-4000-9000-000000000000",
                        "status": http_proxy.PROXY_STATUS_READY,
                        "auth": http_proxy.AUTH_METHOD_SRCIP_USERPASS,
                        "http_proxy": "http://proxy.test",
                        "https_proxy": "https://proxy.test",
                        "user": backend_secret.id,
                    }
                ]
            )
        },
    )
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation,
            backend_relation,
            pgsql_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
        secrets=[backend_secret],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    response = json.loads(
        cast(dict, state_out.get_relation(relation.id).local_app_data)["responses"]
    )
    assert response == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_ACCEPTED,
        }
    ]


def test_invalid_backend_response(mock_policy):
    """
    arrange: prepare HTTP proxy requirer relation, proxy backend relation with invalid response,
             and PostgreSQL relation.
    act: run the config-changed event
    assert: the charm should ignore invalid backend response
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = [EXAMPLE_EVALUATED_REQUESTS[0]]
    backend_secret = ops.testing.Secret(tracked_content={"username": "test", "password": "test"})
    backend_relation = ops.testing.Relation(
        endpoint="http-proxy-backend",
        remote_app_data={
            "responses": json.dumps([{"requirer": "00000000-0000-4000-8000-000000000000"}])
        },
    )
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation,
            backend_relation,
            pgsql_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
        secrets=[backend_secret],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    response = json.loads(
        cast(dict, state_out.get_relation(relation.id).local_app_data)["responses"]
    )
    assert response == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_ACCEPTED,
        }
    ]
    expected_status = "Invalid responses from http proxy backend. Check debug logs."
    assert state_out.app_status == ops.testing.BlockedStatus(expected_status)


def test_missing_backend_relation(mock_policy):
    """
    arrange: prepare HTTP proxy requirer relation, and PostgreSQL relation without proxy backend
             relation.
    act: run the config-changed event
    assert: the charm should set the unit status to waiting.
    """
    ctx = ops.testing.Context(HttpProxyPolicyCharm)
    relation = ops.testing.Relation(
        id=111,
        endpoint="http-proxy",
        remote_app_data={
            "requests": json.dumps(
                [EXAMPLE_RAW_REQUESTS[0]],
            )
        },
    )
    mock_policy.HttpProxyPolicyClient.refresh.return_value = [EXAMPLE_EVALUATED_REQUESTS[0]]
    pgsql_relation = ops.testing.Relation(
        endpoint="postgresql",
        remote_app_data={
            "database": "http-proxy-policy",
            "endpoints": "postgresql.test:5432",
            "username": "postgres",
            "password": "postgres",
        },
    )
    state_in = ops.testing.State(
        leader=True,
        relations=[
            relation,
            pgsql_relation,
            ops.testing.PeerRelation(endpoint="http-proxy-policy-peer"),
        ],
    )
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    response = json.loads(
        cast(dict, state_out.get_relation(relation.id).local_app_data)["responses"]
    )
    assert response == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_ACCEPTED,
        }
    ]
    expected_status = "Waiting for http-proxy-backend relation."
    assert state_out.app_status == ops.testing.WaitingStatus(expected_status)
