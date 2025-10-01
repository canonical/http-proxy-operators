# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""http-proxy-configurator-operator charm state."""

import logging
from enum import StrEnum
from typing import Annotated, Optional, cast

import ops
from annotated_types import Len
from pydantic import ValidationError
from pydantic.dataclasses import dataclass
from pydantic.networks import IPvAnyAddress

logger = logging.getLogger()
CHARM_CONFIG_DELIMITER = ","


class InvalidCharmConfigError(Exception):
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
    """

    http_proxy_domains: Annotated[list[str], Len(min_length=1)]
    http_proxy_auth: Annotated[list[ProxyAuthMethod], Len(min_length=1)]
    http_proxy_source_ips: list[IPvAnyAddress]

    @classmethod
    def from_charm(cls, charm: ops.CharmBase) -> "State":
        """Create an State class from a charm instance.

        Args:
            charm: the http-proxy-configurator charm.

        Raises:
            InvalidCharmConfigError: when the integrator mode config is invalid.

        Returns:
            State: instance of the state component.
        """
        configured_domains = cast(Optional[str], charm.config.get("http-proxy-domains"))
        configured_auth = cast(Optional[str], charm.config.get("http-proxy-auth"))
        configured_source_ips = cast(Optional[str], charm.config.get("http-proxy-source-ips"))
        try:
            return cls(
                http_proxy_domains=parse_charm_config_values(configured_domains),
                http_proxy_auth=[
                    ProxyAuthMethod(config)
                    for config in parse_charm_config_values(configured_auth)
                ],
                http_proxy_source_ips=[
                    cast(IPvAnyAddress, config)
                    for config in parse_charm_config_values(configured_source_ips)
                ],
            )
        except ValidationError as exc:
            logger.error(str(exc))
            error_field_str = ",".join(f"{field}" for field in get_invalid_config_fields(exc))
            raise InvalidCharmConfigError(
                f"Invalid charm configuration(s): {error_field_str}"
            ) from exc
        except ValueError as exc:
            # Error parsing str to ProxyAuthMethod
            invalid_proxy_auth_configs = ",".join(
                [
                    config
                    for config in parse_charm_config_values(configured_auth)
                    if config not in ProxyAuthMethod
                ]
            )
            raise InvalidCharmConfigError(
                (
                    f"Invalid auth configuration(s): {invalid_proxy_auth_configs}. "
                    f"Supported methods are: {ProxyAuthMethod.all()}"
                )
            ) from exc


def parse_charm_config_values(value: Optional[str]) -> list[str]:
    """Parse a charm config containing a list of values into a python list.

    Args:
        value: Raw charm config value.

    Returns:
        list[str]: The parsed list of config values, or an empty list
    """
    # We use `not value` here to also catch value = ""
    if not value:
        return []
    return value.split(CHARM_CONFIG_DELIMITER)


def get_invalid_config_fields(exc: ValidationError) -> list[str]:
    """Return a list on invalid config from pydantic validation error.

    Args:
        exc: The validation error exception.

    Returns:
        str: list of fields that failed validation.
    """
    logger.info(exc.errors())
    error_fields = ["-".join([str(i) for i in error["loc"]]) for error in exc.errors()]
    return error_fields
