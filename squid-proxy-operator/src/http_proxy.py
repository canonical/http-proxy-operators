# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""HTTP proxy charm library."""

import copy
import ipaddress
import json
import re
import uuid
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence, Tuple, cast

import ops
from pydantic import BaseModel, SecretStr, conint, field_validator, model_validator

AUTH_METHOD_SRCIP_USERPASS = "srcip+userpass"
AUTH_METHOD_USERPASS = "userpass"
AUTH_METHOD_SRCIP = "srcip"
AUTH_METHOD_NONE = "none"
AUTH_METHODS = [
    AUTH_METHOD_SRCIP_USERPASS,
    AUTH_METHOD_USERPASS,
    AUTH_METHOD_SRCIP,
    AUTH_METHOD_NONE,
]
PROXY_STATUS_PENDING = "pending"
PROXY_STATUS_ACCEPTED = "accepted"
PROXY_STATUS_DENIED = "denied"
PROXY_STATUS_INVALID = "invalid"
PROXY_STATUS_ERROR = "error"
PROXY_STATUS_READY = "ready"
PROXY_STATUSES = [
    PROXY_STATUS_PENDING,
    PROXY_STATUS_ACCEPTED,
    PROXY_STATUS_DENIED,
    PROXY_STATUS_INVALID,
    PROXY_STATUS_ERROR,
    PROXY_STATUS_READY,
]

NO_CHANGE = object()
UnsignedInt = conint(ge=0)


def dedup(input_list: list[str]) -> list[str]:
    """Deduplicate a list without changing the order.

    Args:
        input_list: The input list.

    Returns:
        The deduplicated list.
    """
    seen = set()
    result = []
    for i in input_list:
        if i in seen:
            continue
        seen.add(i)
        result.append(i)
    return result


class HttpProxySpec(BaseModel):
    """HTTP proxy model.

    Attributes:
        group: group id. Along with id, uniquely identifies the proxy request within a charm scope.
        id: id. Along with group, uniquely identifies the proxy request within a charm scope.
        domains: HTTP proxy destination domains.
        auth: HTTP proxy authentication methods.
        src_ips: HTTP proxy source IPs.
    """

    if TYPE_CHECKING:
        group: int
    else:
        group: conint(ge=0)  # type: ignore[valid-type]
    id: uuid.UUID
    domains: Tuple[str, ...]
    auth: Tuple[str, ...]
    src_ips: Tuple[str, ...] = tuple()

    @staticmethod
    def parse_domain(domain: str) -> Tuple[str, int]:
        """Parse a domain string in the form of host[:port].

        Args:
            domain: The domain string.

        Returns:
            A (host, port) tuple. Port is 0 if not specified.

        Raises:
            ValueError: If the domain string is invalid.
        """
        # ipv6 (the correct way), i.e. "[::1]:8080" or "[::1]"
        if domain.startswith("["):
            search = re.findall(r"^\[([a-f0-9:A-F]+)](:[0-9]+)?$", domain)
            if not search:
                raise ValueError(f"invalid domain: {domain}")
            host, port = search[0]
            ipaddress.ip_network(host, strict=False)
            host = f"[{host}]"
            port = port.removeprefix(":")
        # ipv6 (the "incorrect" way), i.e. "fe80::1", "::1"
        elif domain.count(":") >= 2:
            ipaddress.ip_network(domain, strict=False)
            host, port = f"[{domain}]", 0
        # ipv4
        elif re.match("^[0-9.:]+$", domain):
            if ":" in domain:
                host, port = domain.rsplit(":", 1)
            else:
                host, port = domain, 0
            ipaddress.ip_address(host)
        # DNS domain
        else:
            match = re.match(
                r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
                r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])"
                r"(:[0-9]+)?$",
                domain,
            )
            if not match:
                raise ValueError(f"invalid domain: {domain}")
            if ":" in domain:
                host, port = domain.rsplit(":", 1)
            else:
                host, port = domain, 0
        return host, int(port)

    @field_validator("domains", mode="before")
    @classmethod
    def _validate_and_transform_domains(cls, domains: Sequence[str]) -> Tuple[str, ...]:
        """Validate and transform the domains input.

        Args:
            domains: The input domains.

        Returns:
            The canonical representation of the domains.
        """
        valid_domains = []
        invalid_domains = []
        for domain in domains:
            try:
                host, port = cls.parse_domain(domain)
                if not 0 <= port <= 65535:
                    raise ValueError(f"invalid port: {port}")
                if port != 0:
                    valid_domains.append(f"{host}:{port}")
                else:
                    valid_domains.append(f"{host}:80")
                    valid_domains.append(f"{host}:443")
            except ValueError:
                invalid_domains.append(domain)
        if invalid_domains:
            raise ValueError(f"invalid domains: {invalid_domains}")
        if not valid_domains:
            raise ValueError("no domains specified")
        return tuple(dedup(sorted(valid_domains, key=cls.parse_domain)))

    @field_validator("auth", mode="before")
    @classmethod
    def _validate_and_transform_auth(cls, auth: Sequence[str]) -> Tuple[str, ...]:
        """Validate and transform the auth input.

        Args:
            auth: The input auth.

        Returns:
            The canonical representation of the auth.
        """
        invalid_auth = [a for a in auth if a not in AUTH_METHODS]
        if invalid_auth:
            raise ValueError(f"invalid auth type: {invalid_auth}")
        sorted_auth = dedup(sorted(auth, key=AUTH_METHODS.index))
        if not sorted_auth:
            raise ValueError("no auth method specified")
        return tuple(sorted_auth)

    @field_validator("src_ips", mode="before")
    @classmethod
    def _validate_and_sort_src_ip(cls, src_ips: Sequence[str]) -> Tuple[str, ...]:
        """Validate and transform the src_ips input.

        Args:
            src_ips: The input auth.

        Returns:
            The canonical representation of the src_ips.
        """
        if src_ips is None:
            return tuple()
        validated_ips = []
        invalid_ips = []
        for ip in src_ips:
            try:
                ipaddress.ip_network(ip, strict=False)
                validated_ips.append(ip)
            except ValueError:
                invalid_ips.append(ip)
        if invalid_ips:
            raise ValueError(f"invalid src_ips: {invalid_ips}")
        return tuple(dedup(sorted(validated_ips)))

    @model_validator(mode="after")
    def _validate(self) -> "HttpProxySpec":
        """Validate the object as a whole.

        Returns:
            The validated object.
        """
        if (
            any(auth in (AUTH_METHOD_SRCIP, AUTH_METHOD_SRCIP_USERPASS) for auth in self.auth)
            and not self.src_ips
        ):
            raise ValueError("no src_ips specified for srcip authentication")
        return self


class HttpProxyRequest(HttpProxySpec):
    """HTTP proxy request model.

    Attributes:
        implicit_src_ips: src_ips is provided implicitly.
    """

    implicit_src_ips: bool


class HttpProxyUser(BaseModel):
    """HTTP proxy user model.

    Attributes:
        username: username.
        password: password.
    """

    username: str
    password: SecretStr


class HttpProxyResponse(BaseModel):
    """HTTP proxy response model.

    Attributes:
        group: group id. Along with id, uniquely identifies the proxy request within a charm scope.
        id: id. Along with group, uniquely identifies the proxy request within a charm scope.
        status: HTTP proxy status.
        auth: HTTP proxy authentication method.
        http_proxy: HTTP proxy.
        https_proxy: HTTPS proxy.
        user: HTTP proxy user.
    """

    if TYPE_CHECKING:
        group: int
    else:
        group: conint(ge=0)  # type: ignore[valid-type]
    id: uuid.UUID
    status: str
    auth: Optional[str] = None
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    user: Optional[HttpProxyUser] = None

    class Config:  # pylint: disable=too-few-public-methods
        """Pydantic model configuration.

        Attributes:
            hide_input_in_errors: hide input in errors.
        """

        hide_input_in_errors = True

    @field_validator("status", mode="before")
    @classmethod
    def _validate_status(cls, status: str) -> str:
        """Validate the status input.

        Args:
            status: status input.

        Returns:
            The validated status.
        """
        if status not in PROXY_STATUSES:
            raise ValueError(f"invalid status: {status}")
        return status

    @field_validator("auth", mode="before")
    @classmethod
    def _validate_auth(cls, auth: str) -> str:
        """Validate the auth input.

        Args:
            auth: auth input.

        Returns:
            The validated auth.
        """
        if auth and auth not in AUTH_METHODS:
            raise ValueError(f"invalid auth type: {auth}")
        return auth

    @model_validator(mode="after")
    def _validate(self) -> "HttpProxyResponse":
        """Validate the object as a whole.

        Returns:
            The validated object.
        """
        if not self.http_proxy and self.https_proxy:
            raise ValueError("no http_proxy specified")
        if self.http_proxy and not self.https_proxy:
            raise ValueError("no https_proxy specified")
        if self.status == PROXY_STATUS_READY:
            if not self.auth:
                raise ValueError("auth type is missing")
            if not self.https_proxy or not self.http_proxy:
                raise ValueError("http_proxy or https_proxy is missing")
        if self.auth in (AUTH_METHOD_USERPASS, AUTH_METHOD_SRCIP_USERPASS) and not self.user:
            raise ValueError("user is missing for userpass authentication")
        return self


class BadIntegrationError(Exception):
    """Integration contains ill-formed data."""


class HttpProxyRequestListReader:
    """Integration helper: read request list."""

    def __init__(self, charm: ops.CharmBase, integration: ops.Relation) -> None:
        """Initialize the object.

        Args:
            charm: charm object.
            integration: integration object.
        """
        self._charm = charm
        self._integration = integration
        self._requests: Dict[str, dict] = {}
        self._load()

    @property
    def _integration_data(self) -> ops.RelationDataContent:
        """Get integration data.

        Returns:
            Integration data.
        """
        return self._integration.data[self._integration.app]

    @property
    def _integration_id(self) -> int:
        """Get integration id.

        Returns:
            Integration id.
        """
        return self._integration.id

    def _get_remote_unit_ips(self) -> List[str]:
        """Get IPs of the remote units.

        Returns:
            IPs of the remote units.
        """
        ips = []
        for unit in self._integration.units:
            address = self._integration.data[unit].get("private-address")
            if address:
                ips.append(address)
        return ips

    def _load(self) -> None:
        """Load data from integration.

        Raises:
            BadIntegrationError: ill-formed integration data.
        """
        data = self._integration_data.get("requests", "[]")
        try:
            requests = json.loads(data)
        except json.decoder.JSONDecodeError as exc:
            raise BadIntegrationError("not json") from exc
        if not isinstance(requests, list):
            raise BadIntegrationError("not a list")
        for request in requests:
            if not isinstance(request, dict):
                raise BadIntegrationError("not a dict")
            try:
                requirer_id = request["requirer"]
            except KeyError as exc:
                raise BadIntegrationError("missing requirer id") from exc
            if requirer_id in self._requests:
                raise BadIntegrationError(f"duplicate requirer id: {requirer_id}")
            self._requests[requirer_id] = request

    def get_requirer_ids(self) -> Iterable[str]:
        """Get all requirer ids.

        Returns:
            All requirer ids.
        """
        return self._requests.keys()

    def get(self, requirer_id: str) -> Optional[HttpProxyRequest]:
        """Get a specific HTTP proxy request.

        Args:
            requirer_id: requirer id of the proxy request.

        Returns:
            the proxy request.
        """
        if requirer_id not in self._requests:
            return None
        request = copy.deepcopy(self._requests[requirer_id])
        request["group"] = self._integration_id
        if not request.get("src_ips"):
            src_ips = self._get_remote_unit_ips()
            request["src_ips"] = src_ips
            request["implicit_src_ips"] = True
        else:
            request["implicit_src_ips"] = False
        request["id"] = request["requirer"]
        del request["requirer"]
        return HttpProxyRequest(**request)


class HttpProxyRequestListReadWriter(HttpProxyRequestListReader):
    """Integration helper: read and write request list."""

    @property
    def _integration_data(self) -> ops.RelationDataContent:
        """Get integration data.

        Returns:
            integration data.
        """
        return self._integration.data[self._charm.app]

    def _dump(self) -> None:
        """Write HTTP requests in the buffer to the integration."""
        requests = [self._requests[id] for id in sorted(self._requests)]
        self._integration_data["requests"] = json.dumps(
            requests, sort_keys=True, ensure_ascii=True
        )

    def delete(self, requirer_id: str) -> None:
        """Delete a HTTP proxy request.

        Args:
            requirer_id: requirer id of the proxy request.
        """
        self._requests.pop(requirer_id, None)
        self._dump()

    def add(
        self,
        requirer_id: str,
        domains: list[str],
        auth: list[str],
        src_ips: list[str] | None = None,
    ) -> None:
        """Add a new HTTP proxy request.

        Args:
            requirer_id: requirer id of the proxy request.
            domains: proxy request domains.
            auth: proxy request auth.
            src_ips: proxy request src_ips.

        Raises:
            KeyError: request already exists.
        """
        if requirer_id in self._requests:
            raise KeyError(
                f"http proxy request with requirer id {repr(requirer_id)} already exists"
            )
        # here to validate the inputs only
        HttpProxySpec(
            group=0,
            id=requirer_id,  # type: ignore
            domains=domains,  # type: ignore
            auth=auth,  # type: ignore
            src_ips=src_ips or ["10.0.0.1"],  # type: ignore
        )
        request = {
            "requirer": requirer_id,
            "domains": domains,
            "auth": auth,
        }
        if src_ips:
            request["src_ips"] = src_ips
        self._requests[requirer_id] = request
        self._dump()


class HttpProxyResponseListReader:
    """Integration helper: read response list."""

    def __init__(self, charm: ops.CharmBase, integration: ops.Relation):
        """Initialize the object.

        Args:
            charm: charm object.
            integration: integration object.
        """
        self._charm = charm
        self._integration = integration
        self._responses: Dict[str, dict] = {}
        self._load()

    @property
    def _integration_data(self) -> ops.RelationDataContent:
        """Get integration data.

        Returns:
            integration data.
        """
        return self._integration.data[self._integration.app]

    @property
    def _integration_id(self) -> int:
        """Get integration id.

        Returns:
            integration id.
        """
        return self._integration.id

    def _read_secret(self, secret_id: str) -> Dict[str, str]:
        """Read a juju secret.

        Args:
            secret_id: juju secret id.

        Returns:
            Juju secret content.
        """
        return self._charm.model.get_secret(id=secret_id).get_content(refresh=True)

    def _load(self) -> None:
        """Load responses from the integration.

        Raises:
            BadIntegrationError: ill-formed integration data.
        """
        data = self._integration_data.get("responses", "[]")
        try:
            responses = json.loads(data)
        except json.decoder.JSONDecodeError as exc:
            raise BadIntegrationError("not json") from exc
        if not isinstance(responses, list):
            raise BadIntegrationError("not a list")
        for response in responses:
            if not isinstance(response, dict):
                raise BadIntegrationError("not a dict")
            try:
                requirer_id = response["requirer"]
            except KeyError as exc:
                raise BadIntegrationError("missing requirer id") from exc
            if requirer_id in self._responses:
                raise BadIntegrationError(f"duplicate requirer id: {requirer_id}")
            self._responses[requirer_id] = response

    def _parse_response(self, data: dict, fetch_user_secrets: bool = True) -> HttpProxyResponse:
        """Parse an HTTP proxy response.

        Args:
            data: HTTP proxy response data.
            fetch_user_secrets: fetch user secrets during parsing.

        Returns:
            parsed HTTP proxy response.
        """
        data = copy.deepcopy(data)
        data["group"] = self._integration_id
        data["id"] = data["requirer"]
        del data["requirer"]
        user = data.get("user")
        if user and fetch_user_secrets:
            data["user"] = self._read_secret(secret_id=user)
        return HttpProxyResponse(**data)

    def get_requirer_ids(self) -> Iterable[str]:
        """Get all requirer ids.

        Return:
            all requirer ids.
        """
        return self._responses.keys()

    def get(self, requirer_id: str) -> Optional[HttpProxyResponse]:
        """Get a specific HTTP proxy response.

        Args:
            requirer_id: response requirer id.

        Returns:
            HTTP proxy response if exists.
        """
        if requirer_id not in self._responses:
            return None
        response = self._responses[requirer_id]
        return self._parse_response(response)


class HttpProxyResponseListReadWriter(HttpProxyResponseListReader):
    """Integration helper: read and write response list."""

    @property
    def _integration_data(self) -> ops.RelationDataContent:
        """Get integration data.

        Returns:
            integration data.
        """
        return self._integration.data[self._charm.app]

    def _create_secret(self, content: Dict[str, str]) -> str:
        """Create a juju secret.

        Args:
            content: juju secret content

        Returns:
            Juju secret id.
        """
        secret = self._charm.app.add_secret(content=content)
        secret.grant(self._integration)
        return cast(str, secret.id)

    def _update_secret(self, secret_id: str, content: Dict[str, str]) -> None:
        """Update a juju secret.

        Args:
            secret_id: juju secret id.
            content: juju secret content.
        """
        secret = self._charm.model.get_secret(id=secret_id)
        if dict(secret.get_content(refresh=True)) != content:
            secret.set_content(content)

    def _delete_secret(self, secret_id: str) -> None:
        """Delete a juju secret.

        Args:
            secret_id: juju secret id.
        """
        secret = self._charm.model.get_secret(id=secret_id)
        secret.remove_all_revisions()

    def _dump(self) -> None:
        """Write HTTP responses in the buffer to the integration."""
        responses = [self._responses[id] for id in sorted(self._responses)]
        self._integration_data["responses"] = json.dumps(
            responses, sort_keys=True, ensure_ascii=True
        )

    def add(  # pylint: disable=too-many-arguments
        self,
        requirer_id: str,
        *,
        status: str,
        auth: str | None = None,
        http_proxy: Optional[str] = None,
        https_proxy: Optional[str] = None,
        user: Dict[str, str] | None = None,
    ) -> None:
        """Add a new HTTP proxy response.

        Args:
            requirer_id: response requirer id.
            status: HTTP proxy status.
            auth: HTTP proxy auth.
            http_proxy: HTTP proxy url.
            https_proxy: HTTPS proxy url.
            user: HTTP proxy user.

        Raises:
            KeyError: if response already exists.
        """
        if requirer_id in self._responses:
            raise KeyError(
                f"http proxy response with requirer id {repr(requirer_id)} already exists"
            )
        # here to validate the inputs only
        HttpProxyResponse(
            group=0,
            id=requirer_id,  # type: ignore
            status=status,
            auth=auth,
            http_proxy=http_proxy,
            https_proxy=https_proxy,
            user=user,  # type: ignore
        )
        response = {
            "requirer": requirer_id,
            "status": status,
        }
        if auth is not None:
            response["auth"] = auth
        if user is not None:
            response["user"] = self._create_secret(user)
        if http_proxy is not None:
            response["http_proxy"] = http_proxy
        if https_proxy is not None:
            response["https_proxy"] = https_proxy
        self._responses[requirer_id] = response
        self._dump()

    def update(  # pylint: disable=too-many-arguments
        self,
        requirer_id: str,
        *,
        status: str | object = NO_CHANGE,
        auth: str | None | object = NO_CHANGE,
        http_proxy: str | None | object = NO_CHANGE,
        https_proxy: str | None | object = NO_CHANGE,
        user: Dict[str, str] | None | object = NO_CHANGE,
    ) -> None:
        """Update an HTTP proxy response.

        Args:
            requirer_id: response requirer id.
            status: HTTP proxy status.
            auth: HTTP proxy auth.
            http_proxy: HTTP proxy url.
            https_proxy: HTTPS proxy url.
            user: HTTP proxy user.
        """
        response = copy.deepcopy(self._responses[requirer_id])
        if status is not NO_CHANGE:
            response["status"] = status
        if auth is not NO_CHANGE:
            response["auth"] = auth
        if http_proxy is not NO_CHANGE:
            response["http_proxy"] = http_proxy
        if https_proxy is not NO_CHANGE:
            response["https_proxy"] = https_proxy
        test_response = copy.deepcopy(response)
        if user is not NO_CHANGE:
            test_response["user"] = user
        # validate the input only
        self._parse_response(test_response, fetch_user_secrets=False)
        if user and user is not NO_CHANGE:
            secret_id = response.get("user")
            # mypy doesn't handle the NO_CHANGE very well
            if secret_id is None:
                response["user"] = self._create_secret(user)  # type: ignore
            else:
                self._update_secret(secret_id, user)  # type: ignore
        if user is None and response.get("user"):
            self._delete_secret(response["user"])
            response["user"] = None
        self._responses[requirer_id] = {k: v for k, v in response.items() if v is not None}
        self._dump()

    def delete(self, requirer_id: str) -> None:
        """Delete a HTTP proxy response.

        Args:
            requirer_id: response requirer id.
        """
        if requirer_id not in self._responses:
            return
        response = self._responses[requirer_id]
        secret_id = response.get("user")
        if secret_id:
            self._delete_secret(secret_id)
        del self._responses[requirer_id]
        self._dump()


class HttpProxyPolyProvider:
    """HTTP proxy provider."""

    def __init__(self, charm: ops.CharmBase, integration_name: str) -> None:
        """Initialize the object.

        Args:
            charm: the charm instance.
            integration_name: HTTP proxy integration name.
        """
        self._charm = charm
        self._integration_name = integration_name

    def open_request_list(self, integration_id: int) -> HttpProxyRequestListReader:
        """Start reading the request list in the integration data.

        Args:
            integration_id: integration id.

        Returns:
            A instance of HttpProxyRequestListReader.

        Raises:
            ValueError: if the integration id is invalid.
        """
        integration = self._charm.model.get_relation(
            self._integration_name, relation_id=integration_id
        )
        if integration is None:
            raise ValueError("integration not found")
        return HttpProxyRequestListReader(charm=self._charm, integration=integration)

    def open_response_list(self, integration_id: int) -> HttpProxyResponseListReadWriter:
        """Start reading/writing the response list in the integration data.

        Args:
            integration_id: integration id.

        Returns:
            A instance of HttpProxyResponseListReadWriter.

        Raises:
            ValueError: if the integration id is invalid.
        """
        integration = self._charm.model.get_relation(
            self._integration_name, relation_id=integration_id
        )
        if integration is None:
            raise ValueError("integration not found")
        return HttpProxyResponseListReadWriter(charm=self._charm, integration=integration)


class HttpProxyPolyRequirer:
    """HTTP proxy requirer."""

    def __init__(self, charm: ops.CharmBase, integration_name: str):
        """Initialize the object.

        Args:
            charm: the charm instance.
            integration_name: HTTP proxy integration name.
        """
        self._charm = charm
        self._integration_name = integration_name

    def open_request_list(self, integration_id: int) -> HttpProxyRequestListReadWriter:
        """Start reading/writing the request list in the integration data.

        Args:
            integration_id: integration id.

        Returns:
            A instance of HttpProxyRequestListReadWriter.

        Raises:
            ValueError: if the integration id is invalid.
        """
        integration = self._charm.model.get_relation(
            self._integration_name, relation_id=integration_id
        )
        if integration is None:
            raise ValueError("integration not found")
        return HttpProxyRequestListReadWriter(charm=self._charm, integration=integration)

    def open_response_list(self, integration_id: int) -> HttpProxyResponseListReader:
        """Start reading the response list in the integration data.

        Args:
            integration_id: integration id.

        Returns:
            A instance of HttpProxyResponseListReader.

        Raises:
            ValueError: if the integration id is invalid.
        """
        integration = self._charm.model.get_relation(
            self._integration_name, relation_id=integration_id
        )
        if integration is None:
            raise ValueError("integration not found")
        return HttpProxyResponseListReader(charm=self._charm, integration=integration)
