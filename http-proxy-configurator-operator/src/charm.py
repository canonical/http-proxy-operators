#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""Charm the service."""

import logging
import typing
from typing import Optional, cast

import ops
from charms.squid_forward_proxy.v0.http_proxy import HttpProxyDynamicRequirer
from pydantic import ValidationError

logger = logging.getLogger(__name__)
HTTP_PROXY_RELATION = "http-proxy"
CHARM_CONFIG_DELIMITER = ","


class IngressConfiguratorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args: typing.Any):
        """Initialize the http-proxy-configurator charm.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self._http_proxy = HttpProxyDynamicRequirer(self, HTTP_PROXY_RELATION)
        self.framework.observe(self.on.config_changed, self._reconcile)
        self.framework.observe(self.on[HTTP_PROXY_RELATION].relation_changed, self._reconcile)
        self.framework.observe(self.on[HTTP_PROXY_RELATION].relation_broken, self._reconcile)
        self.framework.observe(self.on[HTTP_PROXY_RELATION].relation_departed, self._reconcile)

    def _reconcile(self, _: ops.EventBase) -> None:
        """Reconcile the charm."""
        # We don't do any validation in the charm itself since most of it are already handled by the library.
        # Furthermore, the library does pre-validation modifications to the parameters given to
        # `request_http_proxy` so we delegate this to the library to avoid having to reimplement this logic.
        try:
            self._http_proxy.request_http_proxy(
                parse_charm_config(cast(Optional[str], self.config.get("http-proxy-domains"))),
                parse_charm_config(cast(Optional[str], self.config.get("http-proxy-auth"))),
                parse_charm_config(cast(Optional[str], self.config.get("http-proxy-src-ips"))),
            )
            self.unit.status = ops.ActiveStatus()
        # Catching ValidationError first as those are the errors wrapped by pydantic for model validation.
        # ValueError is raised directly by `request_http_proxy` when the charm is not a leader or the
        # http-proxy relation is not ready.
        except ValidationError as exc:
            logger.exception("Error validating the charm configuration.")
            self.unit.status = ops.BlockedStatus(str(exc))
            return
        except ValueError as exc:
            logger.exception("Error validating the charm state.")
            self.unit.status = ops.BlockedStatus(str(exc))
            return


def parse_charm_config(value: Optional[str]) -> Optional[list[str]]:
    """Parse a http-proxy-configurator charm config to a list of str.

    Args:
        value: Config value to parse

    Returns:
        Optional[list[str]]: Parsed list of str.
    """
    if value is None:
        return None
    return value.split(CHARM_CONFIG_DELIMITER)


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(IngressConfiguratorCharm)
