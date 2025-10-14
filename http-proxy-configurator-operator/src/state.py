# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""http-proxy-configurator-operator charm state."""

import logging
from enum import StrEnum
from typing import Annotated, Optional, cast

import ops
from annotated_types import Len
from charms.squid_forward_proxy.v0.http_proxy import (
    HttpProxyPolyProvider,
)
from pydantic import ValidationError, model_validator
from pydantic.dataclasses import dataclass
from pydantic.networks import IPvAnyAddress

logger = logging.getLogger()
CHARM_CONFIG_DELIMITER = ","


class InvalidCharmConfigError(Exception):
    """Exception raised when the parsed charm config is invalid."""


class BackendRequestMissingError(Exception):
    """Exception raised when the parsed charm config is invalid."""


class ProxyAuthMethod(StrEnum):
    """http-route auth method.

    Attributes:
        NONE: No authentication.
        SRC_IP: Authentication with source IP address.
        USERPASS: Authentication with password.
        SRC_IP_AND_USERPASS: Authentication with both source IP address and password.
    """

    NONE = "none"
    SRC_IP = "srcip"
    USERPASS = "userpass"
    SRC_IP_AND_USERPASS = "srcip+userpass"

    @classmethod
    def all(cls) -> list[str]:
        """Return all values in enum.

        Returns:
            list[str]: List of all possible values.
        """
        return [c.value for c in cls]


@dataclass(frozen=True)
class State:
    """Charm state.

    Attributes:
        http_proxy_domains: Configured list of backend ip addresses.
        http_proxy_auth: Configured list of backend ports.
        http_proxy_source_ips: The configured protocol for the backend.
        delegate_http_proxy_relation_id: relation ID of the delegate-http-proxy relation.
        delegate_http_proxy_requirer_id: ID of the backend requirer.
    """

    http_proxy_domains: Annotated[list[str], Len(min_length=1)]
    http_proxy_auth: Annotated[list[ProxyAuthMethod], Len(min_length=1)]
    http_proxy_source_ips: list[IPvAnyAddress]
    delegate_http_proxy_relation_id: Optional[int]
    delegate_http_proxy_requirer_id: Optional[str]

    @model_validator(mode="after")
    def validate_source_ips_set_for_srcip_auth_method(self) -> "State":
        # Docstring here is weird to make pflake8 happy, this method raises `ValidationError`.
        """Validate that if srcip is set then http_proxy_source_ips must be also.

        Returns: this class instance.

        Raises:
            from_exception_data: if the validation doesn't pass.
        """
        if (
            any(
                auth in {ProxyAuthMethod.SRC_IP, ProxyAuthMethod.SRC_IP_AND_USERPASS}
                for auth in self.http_proxy_auth
            )
            and not self.http_proxy_source_ips
        ):
            raise ValidationError.from_exception_data(
                "Source IP address(es) must be provided if http_proxy_auth contains srcip.",
                line_errors=[
                    {
                        "type": "missing",
                        "input": (self.http_proxy_source_ips, self.http_proxy_auth),
                        "loc": (
                            (
                                "Source IP address(es) must be provided"
                                " if http_proxy_auth contains srcip."
                            ),
                        ),
                    }
                ],
            )
        return self

    # Disable this warning for now as the method is very straightforward.
    # pylint: disable=too-many-locals
    @classmethod
    def from_charm(
        cls, charm: ops.CharmBase, delegate_http_proxy_provider: HttpProxyPolyProvider
    ) -> "State":
        """Create an State class from a charm instance.

        Args:
            charm: the http-proxy-configurator charm.
            delegate_http_proxy_provider: http-proxy proivder class.

        Raises:
            InvalidCharmConfigError: when the integrator mode config is invalid.
            BackendRequestMissingError: when the charm is waiting for data in adapter mode.

        Returns:
            State: instance of the state component.
        """
        delegate_http_proxy_relation = charm.model.get_relation(
            delegate_http_proxy_provider._integration_name  # pylint: disable=protected-access
        )
        delegate_http_proxy_relation_id = (
            None if delegate_http_proxy_relation is None else delegate_http_proxy_relation.id
        )
        delegate_http_proxy_requirer_id = None
        configured_domains = cast(Optional[str], charm.config.get("http-proxy-domains"))
        configured_auth = cast(Optional[str], charm.config.get("http-proxy-auth"))
        configured_source_ips = cast(Optional[str], charm.config.get("http-proxy-source-ips"))
        if delegate_http_proxy_relation is not None and configured_source_ips is not None:
            logger.error("Cannot determine mode of operation.")
            raise InvalidCharmConfigError(
                (
                    "Setting both http-proxy-source-ips "
                    "and delegate-http-proxy relation is not allowed"
                )
            )
        http_proxy_source_ips = [
            cast(IPvAnyAddress, config)
            for config in _parse_charm_config_values(configured_source_ips)
        ]
        if delegate_http_proxy_relation:
            http_proxy_source_ips = []
            proxy_requests = delegate_http_proxy_provider.open_request_list(
                delegate_http_proxy_relation.id
            )
            requirer_ids = list(proxy_requests.get_requirer_ids())
            if not requirer_ids:
                raise BackendRequestMissingError("Waiting for complete requirer data.")

            if len(requirer_ids) > 1:
                raise InvalidCharmConfigError(
                    f"Only one request at a time is supported (found: {len(requirer_ids)})."
                )
            delegate_http_proxy_requirer_id = requirer_ids[0]
            # To reach this point we have ensured that requirer_ids exists and of len=1
            request = proxy_requests.get(requirer_ids[0])
            if request is None:
                raise BackendRequestMissingError("Waiting for complete requirer data.")
            http_proxy_source_ips = [cast(IPvAnyAddress, address) for address in request.src_ips]
        try:
            return cls(
                http_proxy_domains=_parse_charm_config_values(configured_domains),
                http_proxy_auth=[
                    ProxyAuthMethod(config)
                    for config in _parse_charm_config_values(configured_auth)
                ],
                http_proxy_source_ips=http_proxy_source_ips,
                delegate_http_proxy_relation_id=delegate_http_proxy_relation_id,
                delegate_http_proxy_requirer_id=delegate_http_proxy_requirer_id,
            )
        except ValidationError as exc:
            logger.error(str(exc))
            error_field_str = ",".join(f"{field}" for field in _get_invalid_config_fields(exc))
            raise InvalidCharmConfigError(
                f"Invalid charm configuration(s): {error_field_str}"
            ) from exc
        except ValueError as exc:
            # Error parsing str to ProxyAuthMethod
            invalid_proxy_auth_configs = ",".join(
                [
                    config
                    for config in _parse_charm_config_values(configured_auth)
                    if config not in ProxyAuthMethod
                ]
            )
            raise InvalidCharmConfigError(
                (
                    f"Invalid auth configuration(s): {invalid_proxy_auth_configs}. "
                    f"Supported methods are: {ProxyAuthMethod.all()}"
                )
            ) from exc


def _parse_charm_config_values(value: Optional[str]) -> list[str]:
    """Parse a charm config containing a list of values into a python list.

    Args:
        value: Raw charm config value.

    Returns:
        list[str]: The parsed list of config values, or an empty list
    """
    # We use `not value` here to also catch value = ""
    if not value:
        return []
    return [s.strip() for s in value.split(CHARM_CONFIG_DELIMITER)]


def _get_invalid_config_fields(exc: ValidationError) -> list[str]:
    """Return a list on invalid config from pydantic validation error.

    Args:
        exc: The validation error exception.

    Returns:
        str: list of fields that failed validation.
    """
    logger.info(exc.errors())
    error_fields = ["-".join([str(i) for i in error["loc"]]) for error in exc.errors()]
    return error_fields
