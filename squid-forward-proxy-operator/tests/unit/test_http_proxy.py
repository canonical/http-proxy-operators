# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the http_proxy module."""

# pylint: disable=protected-access

import json
import uuid

import pydantic
import pytest

import http_proxy


class PureHttpProxyRequestListReader(http_proxy._HttpProxyRequestListReader):
    """HttpProxyRequestListReader for unit tests."""

    # for test purpose only
    # pylint: disable=super-init-not-called
    def __init__(self, data: dict | None = None, remote_unit_ips: list[str] | None = None):
        """Initialize the object.

        Args:
            data: integration data.
            remote_unit_ips: list of remote unit ips.
        """
        self._integration_id = 123
        self._integration_data = data or {}
        self._remote_unit_ips = remote_unit_ips or ["10.0.0.1"]
        self._requests: dict[str, dict] = {}
        self._load()

    def _get_remote_unit_ips(self) -> list[str]:
        """Get remote unit ips."""
        return self._remote_unit_ips


class PureHttpProxyRequestListReadWriter(http_proxy._HttpProxyRequestListReadWriter):
    """HttpProxyRequestListReadWriter for unit tests."""

    # for test purpose only
    # pylint: disable=super-init-not-called
    def __init__(self, data: dict | None = None, remote_unit_ips: list[str] | None = None) -> None:
        """Initialize the object.

        Args:
            data: integration data.
            remote_unit_ips: list of remote unit ips.
        """
        self._integration_id = 123
        self._integration_data = data or {}
        self._remote_unit_ips = remote_unit_ips or ["10.0.0.1"]
        self._requests: dict[str, dict] = {}
        self._load()

    def _get_remote_unit_ips(self) -> list[str]:
        """Get remote unit ips."""
        return self._remote_unit_ips


class PureHttpProxyResponseListReader(http_proxy._HttpProxyResponseListReader):
    """HttpProxyResponseListReader for unit tests."""

    # for test purpose only
    # pylint: disable=super-init-not-called
    def __init__(self, data: dict | None = None, secrets: dict | None = None) -> None:
        """Initialize the object.

        Args:
            data: integration data
            secrets: juju secrets
        """
        self._integration_id = 123
        self._integration_data = data or {}
        self._test_secrets = secrets or {}
        self._responses: dict[str, dict] = {}
        self._load()

    def _read_secret(self, secret_id: str) -> dict[str, str]:
        """Read a juju secret."""
        return self._test_secrets[secret_id]


class PureHttpProxyResponseListReadWriter(http_proxy._HttpProxyResponseListReadWriter):
    """HttpProxyResponseListReadWriter for unit tests."""

    # for test purpose only
    # pylint: disable=super-init-not-called
    def __init__(self, data: dict | None = None, secrets: dict | None = None) -> None:
        """Initialize the object.

        Args:
            data: integration data
            secrets: juju secrets
        """
        self._integration_id = 123
        self._integration_data = data or {}
        self._test_secrets = secrets or {}
        self._responses: dict[str, dict] = {}
        self._load()

    def _read_secret(self, secret_id: str) -> dict[str, str]:
        """Read a juju secret."""
        return self._test_secrets[secret_id]

    def _create_secret(self, content: dict[str, str]) -> str:
        """Create a juju secret."""
        secret_id = f"secret:{uuid.uuid4()}"
        self._test_secrets[secret_id] = content
        return secret_id

    def _update_secret(self, secret_id: str, content: dict[str, str]) -> None:
        """Update a juju secret."""
        self._test_secrets[secret_id] = content

    def _delete_secret(self, secret_id: str) -> None:
        """Delete a juju secret."""
        del self._test_secrets[secret_id]


@pytest.mark.parametrize(
    "requests",
    [
        "foobar",
        json.dumps("foobar"),
        json.dumps(["foobar"]),
        json.dumps({}),
        json.dumps([{}]),
        json.dumps([{"requirer": "foobar"}, {"requirer": "foobar"}]),
    ],
)
def test_http_proxy_request_list_reader_validate_input(requests):
    """
    arrange: none
    act: provide an invalid integration with
    assert: the charm should raise an exception when it attempts to read the integration
    """
    with pytest.raises(http_proxy.IntegrationDataError):
        PureHttpProxyRequestListReadWriter({"requests": json.dumps(requests)})


@pytest.mark.parametrize(
    "proxy_request",
    [
        pytest.param(
            {
                "requirer": "test",
                "domains": ["example.com"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="invalid id",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
            },
            id="missing domains and auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="missing domains",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": "example.com",
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="domains type",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com:99999"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="domains port",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["user:password@example.com"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="domains format",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["10.0.0.0.1"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="invalid ipv4",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": [":::1"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="invalid ipv6",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["[:::1]"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="invalid ipv6 (2)",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
            },
            id="missing auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": http_proxy.AUTH_METHOD_NONE,
            },
            id="auth type",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": ["foobar"],
            },
            id="unknown auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": "example.com",
                "auth": [http_proxy.AUTH_METHOD_NONE],
                "src_ips": "10.0.0.1",
            },
            id="src_ips type",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": "example.com",
                "auth": [http_proxy.AUTH_METHOD_NONE],
                "src_ips": ["10.0.0.1.1"],
            },
            id="src_ips value",
        ),
    ],
)
def test_http_proxy_request_list_reader_validate_request(proxy_request):
    """
    arrange: none
    act: provide integration with an invalid request
    assert: the charm should raise an exception when it receives the invalid request
    """
    reader = PureHttpProxyRequestListReader({"requests": json.dumps([proxy_request])})
    for requirer_id in reader.get_requirer_ids():
        with pytest.raises(ValueError):
            reader.get(requirer_id)


@pytest.mark.parametrize(
    "proxy_request, parsed_request",
    [
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("example.com:80", "example.com:443"),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="normal request",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": [],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=(),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="empty domains",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": [],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("example.com:80", "example.com:443"),
                auth=(),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="empty auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": [],
                "auth": [],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=(),
                auth=(),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="empty domains and auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["1.example.com:80", "0.example.com:80"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("0.example.com:80", "1.example.com:80"),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="sort domains",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["1.example.com:80", "0.example.com:100", "0.example.com:80"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("0.example.com:80", "0.example.com:100", "1.example.com:80"),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="sort domain ports",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["127.0.0.1"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("127.0.0.1:80", "127.0.0.1:443"),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="ipv4",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["::1"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("[::1]:80", "[::1]:443"),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="ipv6",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["[::1]:8080"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("[::1]:8080",),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="ipv6 with port",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": [http_proxy.AUTH_METHOD_NONE, "userpass"],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("example.com:80", "example.com:443"),
                auth=("userpass", http_proxy.AUTH_METHOD_NONE),
                src_ips=("10.0.0.1",),
                implicit_src_ips=True,
            ),
            id="sort auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
                "src_ips": ["172.16.0.0/24"],
            },
            http_proxy.HttpProxyRequest(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                domains=("example.com:80", "example.com:443"),
                auth=(http_proxy.AUTH_METHOD_NONE,),
                src_ips=("172.16.0.0/24",),
                implicit_src_ips=False,
            ),
            id="explicit src_ips",
        ),
    ],
)
def test_http_proxy_request_list_reader_get_request(proxy_request, parsed_request):
    """
    arrange: none
    act: provide a http-proxy integration with HTTP proxy requests
    assert: the charm should get HTTP proxy requests from the integration
    """
    reader = PureHttpProxyRequestListReader({"requests": json.dumps([proxy_request])})
    assert reader.get("00000000-0000-4000-8000-000000000000") == parsed_request


@pytest.mark.parametrize(
    "request_args",
    [
        pytest.param(
            {
                "requirer_id": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com:123456"],
                "auth": [http_proxy.AUTH_METHOD_NONE],
            },
            id="invalid domains",
        ),
        pytest.param(
            {
                "requirer_id": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": ["foobar"],
            },
            id="unknown auth",
        ),
    ],
)
def test_http_proxy_request_list_read_writer_add_request_validation(request_args):
    """
    arrange: none
    act: add an invalid request to the integration
    assert: the charm should raise an exception
    """
    writer = PureHttpProxyRequestListReadWriter()
    with pytest.raises(ValueError):
        writer.add(**request_args)


def test_http_proxy_request_list_read_writer_add_delete_request():
    """
    arrange: none
    act: add an HTTP proxy request to the integration then delete it
    assert: data in the integration should reflect the change
    """
    writer = PureHttpProxyRequestListReadWriter()

    writer.add(
        requirer_id="00000000-0000-4000-8000-000000000000",
        domains=[],
        auth=[http_proxy.AUTH_METHOD_NONE],
    )
    assert writer.get("00000000-0000-4000-8000-000000000000") == http_proxy.HttpProxyRequest(
        group=123,
        id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
        domains=(),
        auth=(http_proxy.AUTH_METHOD_NONE,),
        src_ips=("10.0.0.1",),
        implicit_src_ips=True,
    )
    assert json.loads(writer._integration_data["requests"]) == [
        {
            "auth": [http_proxy.AUTH_METHOD_NONE],
            "domains": [],
            "requirer": "00000000-0000-4000-8000-000000000000",
        }
    ]

    writer.add(
        requirer_id="00000000-0000-4000-9000-000000000000",
        domains=["127.0.0.1:8080"],
        auth=[http_proxy.AUTH_METHOD_NONE],
        src_ips=["172.16.0.1"],
    )
    assert writer.get("00000000-0000-4000-9000-000000000000") == http_proxy.HttpProxyRequest(
        group=123,
        id=uuid.UUID("00000000-0000-4000-9000-000000000000"),
        domains=("127.0.0.1:8080",),
        auth=(http_proxy.AUTH_METHOD_NONE,),
        src_ips=("172.16.0.1",),
        implicit_src_ips=False,
    )
    assert json.loads(writer._integration_data["requests"]) == [
        {
            "auth": [http_proxy.AUTH_METHOD_NONE],
            "domains": [],
            "requirer": "00000000-0000-4000-8000-000000000000",
        },
        {
            "auth": [http_proxy.AUTH_METHOD_NONE],
            "domains": ["127.0.0.1:8080"],
            "requirer": "00000000-0000-4000-9000-000000000000",
            "src_ips": ["172.16.0.1"],
        },
    ]

    writer.delete("00000000-0000-4000-8000-000000000000")

    assert json.loads(writer._integration_data["requests"]) == [
        {
            "auth": [http_proxy.AUTH_METHOD_NONE],
            "domains": ["127.0.0.1:8080"],
            "requirer": "00000000-0000-4000-9000-000000000000",
            "src_ips": ["172.16.0.1"],
        },
    ]

    writer.delete("00000000-0000-4000-9000-000000000000")

    assert json.loads(writer._integration_data["requests"]) == []


@pytest.mark.parametrize(
    "requests",
    [
        "foobar",
        json.dumps("foobar"),
        json.dumps(["foobar"]),
        json.dumps({}),
        json.dumps([{}]),
        json.dumps([{"requirer": "foobar"}, {"requirer": "foobar"}]),
    ],
)
def test_http_proxy_response_list_reader_validate_input(requests):
    """
    arrange: none
    act: provide an invalid integration
    assert: the charm should raise an exception when it attempts to read the integration
    """
    with pytest.raises(http_proxy.IntegrationDataError):
        PureHttpProxyResponseListReadWriter({"responses": json.dumps(requests)})


@pytest.mark.parametrize(
    "proxy_response",
    [
        pytest.param({"requirer": "00000000-0000-4000-8000-000000000000"}, id="missing status"),
        pytest.param(
            {"requirer": "00000000-0000-4000-8000-000000000000", "status": "foobar"},
            id="unknown status",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_READY,
                "http_proxy": "http://squid.internal:3128",
                "https_proxy": "http://squid.internal:3128",
            },
            id="ready without auth",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_READY,
                "auth": http_proxy.AUTH_METHOD_NONE,
                "http_proxy": "http://squid.internal:3128",
            },
            id="ready without http_proxy",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_READY,
                "auth": http_proxy.AUTH_METHOD_NONE,
                "https_proxy": "http://squid.internal:3128",
            },
            id="ready without https_proxy",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_READY,
                "auth": http_proxy.AUTH_METHOD_USERPASS,
                "http_proxy": "http://squid.internal:3128",
                "https_proxy": "http://squid.internal:3128",
            },
            id="ready without user",
        ),
    ],
)
def test_http_proxy_response_list_reader_validate_response(proxy_response):
    """
    arrange: none
    act: provide integration with a bad response
    assert: the charm should raise an exception when it attempts to get the response
    """
    reader = PureHttpProxyResponseListReader(data={"responses": json.dumps([proxy_response])})
    with pytest.raises(ValueError):
        reader.get("00000000-0000-4000-8000-000000000000")


@pytest.mark.parametrize(
    "proxy_response, parsed_response, secrets",
    [
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_PENDING,
            },
            http_proxy.HttpProxyResponse(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                status=http_proxy.PROXY_STATUS_PENDING,
            ),
            {},
            id="pending",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_READY,
                "auth": http_proxy.AUTH_METHOD_NONE,
                "http_proxy": "http://squid.internal:3128",
                "https_proxy": "http://squid.internal:3128",
            },
            http_proxy.HttpProxyResponse(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                status=http_proxy.PROXY_STATUS_READY,
                auth=http_proxy.AUTH_METHOD_NONE,
                https_proxy="http://squid.internal:3128",
                http_proxy="http://squid.internal:3128",
            ),
            {},
            id="ready",
        ),
        pytest.param(
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "status": http_proxy.PROXY_STATUS_READY,
                "auth": http_proxy.AUTH_METHOD_USERPASS,
                "user": "secret:foobar",
                "http_proxy": "http://squid.internal:3128",
                "https_proxy": "http://squid.internal:3128",
            },
            http_proxy.HttpProxyResponse(
                group=123,
                id=uuid.UUID("00000000-0000-4000-8000-000000000000"),
                status=http_proxy.PROXY_STATUS_READY,
                auth=http_proxy.AUTH_METHOD_USERPASS,
                https_proxy="http://squid.internal:3128",
                http_proxy="http://squid.internal:3128",
                user=http_proxy.HttpProxyUser(username="foo", password=pydantic.SecretStr("bar")),
            ),
            {"secret:foobar": {"username": "foo", "password": "bar"}},
            id="ready with user",
        ),
    ],
)
def test_http_proxy_response_list_reader_get_response(proxy_response, parsed_response, secrets):
    """
    arrange: none
    act: provide a http-proxy integration with HTTP proxy responses
    assert: the charm should get HTTP proxy responses from the integration
    """
    reader = PureHttpProxyResponseListReader(
        data={"responses": json.dumps([proxy_response])}, secrets=secrets
    )
    assert reader.get("00000000-0000-4000-8000-000000000000") == parsed_response


def test_http_proxy_response_list_reader_add_delete_response():
    """
    arrange: none
    act: add an HTTP proxy response to the integration then delete it
    assert: data in the integration should reflect the change
    """
    writer = PureHttpProxyResponseListReadWriter()

    writer.add(
        requirer_id="00000000-0000-4000-8000-000000000000", status=http_proxy.PROXY_STATUS_PENDING
    )
    assert json.loads(writer._integration_data["responses"]) == [
        {"requirer": "00000000-0000-4000-8000-000000000000", "status": "pending"}
    ]

    writer.add(
        requirer_id="00000000-0000-4000-9000-000000000000",
        status=http_proxy.PROXY_STATUS_READY,
        auth=http_proxy.AUTH_METHOD_USERPASS,
        https_proxy="http://squid.internal:3128",
        http_proxy="http://squid.internal:3128",
        user={"username": "foo", "password": "bar"},
    )
    assert len(writer._test_secrets) == 1
    secret_id = list(writer._test_secrets)[0]
    assert writer._test_secrets[secret_id] == {"username": "foo", "password": "bar"}
    assert json.loads(writer._integration_data["responses"]) == [
        {"requirer": "00000000-0000-4000-8000-000000000000", "status": "pending"},
        {
            "auth": "userpass",
            "requirer": "00000000-0000-4000-9000-000000000000",
            "status": "ready",
            "http_proxy": "http://squid.internal:3128",
            "https_proxy": "http://squid.internal:3128",
            "user": secret_id,
        },
    ]

    writer.delete("00000000-0000-4000-8000-000000000000")
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "auth": "userpass",
            "requirer": "00000000-0000-4000-9000-000000000000",
            "status": "ready",
            "http_proxy": "http://squid.internal:3128",
            "https_proxy": "http://squid.internal:3128",
            "user": secret_id,
        },
    ]
    assert secret_id in writer._test_secrets

    writer.delete("00000000-0000-4000-9000-000000000000")
    assert json.loads(writer._integration_data["responses"]) == []
    assert not writer._test_secrets


def test_http_proxy_response_list_reader_update():
    """
    arrange: none
    act: update an HTTP proxy response in the integration
    assert: data in the integration should reflect the change
    """
    writer = PureHttpProxyResponseListReadWriter()

    writer.add(
        requirer_id="00000000-0000-4000-8000-000000000000", status=http_proxy.PROXY_STATUS_PENDING
    )
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_PENDING,
        }
    ]

    writer.update(
        requirer_id="00000000-0000-4000-8000-000000000000", status=http_proxy.PROXY_STATUS_ACCEPTED
    )
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_ACCEPTED,
        }
    ]

    writer.update(
        requirer_id="00000000-0000-4000-8000-000000000000",
        status=http_proxy.PROXY_STATUS_READY,
        auth=http_proxy.AUTH_METHOD_SRCIP,
        http_proxy="http://squid.internal:3128",
        https_proxy="http://squid.internal:3128",
    )
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_SRCIP,
            "http_proxy": "http://squid.internal:3128",
            "https_proxy": "http://squid.internal:3128",
        }
    ]

    writer.update(
        requirer_id="00000000-0000-4000-8000-000000000000",
        https_proxy="https://squid.internal:3128",
    )
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_SRCIP,
            "http_proxy": "http://squid.internal:3128",
            "https_proxy": "https://squid.internal:3128",
        }
    ]

    writer.update(
        requirer_id="00000000-0000-4000-8000-000000000000",
        auth=http_proxy.AUTH_METHOD_USERPASS,
        user={"username": "foo", "password": "bar"},
    )
    assert len(writer._test_secrets) == 1
    secret_id = list(writer._test_secrets)[0]
    assert writer._test_secrets[secret_id] == {"username": "foo", "password": "bar"}
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_USERPASS,
            "http_proxy": "http://squid.internal:3128",
            "https_proxy": "https://squid.internal:3128",
            "user": secret_id,
        }
    ]

    writer.update(
        requirer_id="00000000-0000-4000-8000-000000000000",
        user={"username": "foobar", "password": "foobar"},
    )
    assert writer._test_secrets[secret_id] == {"username": "foobar", "password": "foobar"}
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_READY,
            "auth": http_proxy.AUTH_METHOD_USERPASS,
            "http_proxy": "http://squid.internal:3128",
            "https_proxy": "https://squid.internal:3128",
            "user": secret_id,
        }
    ]

    writer.update(
        requirer_id="00000000-0000-4000-8000-000000000000",
        status=http_proxy.PROXY_STATUS_PENDING,
        auth=None,
        http_proxy=None,
        https_proxy=None,
        user=None,
    )
    assert json.loads(writer._integration_data["responses"]) == [
        {
            "requirer": "00000000-0000-4000-8000-000000000000",
            "status": http_proxy.PROXY_STATUS_PENDING,
        }
    ]
