# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the squid proxy charm."""

# pylint: disable=protected-access,line-too-long

import json
import unittest.mock
import uuid
from typing import cast

import ops.testing

import http_proxy
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
                [EXAMPLE_RAW_REQUESTS[1]],
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


def test_relay_responses(mock_policy):
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
            "http_proxy": "http://proxy.test",
            "https_proxy": "https://proxy.test",
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": "ready",
            "user": new_secret,
        }
    ]


def test_ignore_invalid_requests(mock_policy):
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


def test_ignore_duplicate_requests(mock_policy):
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
