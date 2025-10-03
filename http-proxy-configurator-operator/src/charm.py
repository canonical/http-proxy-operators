#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""Charm the service."""

import logging
import typing

import ops
from charms.squid_forward_proxy.v0.http_proxy import (
    HttpProxyDynamicRequirer,
    HTTPProxyUnavailableError,
)

from state import InvalidCharmConfigError, State

logger = logging.getLogger(__name__)
HTTP_PROXY_RELATION = "http-proxy"
CHARM_CONFIG_DELIMITER = ","


class HTTPProxyConfiguratorCharm(ops.CharmBase):
    """Charm the http-proxy configurator."""

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

        # Action handlers
        self.framework.observe(self.on.get_proxies_action, self._on_get_proxies)

    def _reconcile(self, _: ops.EventBase) -> None:
        """Reconcile the charm."""
        try:
            state = State.from_charm(self)
            self._http_proxy.request_http_proxy(
                state.http_proxy_domains,
                state.http_proxy_auth,
                [str(address) for address in state.http_proxy_source_ips],
            )
            self.unit.status = ops.ActiveStatus()
        except InvalidCharmConfigError as exc:
            logger.exception("Error validating the charm configuration.")
            self.unit.status = ops.BlockedStatus(str(exc))
            return
        except ValueError as exc:
            logger.exception("Error sending proxy request.")
            self.unit.status = ops.BlockedStatus(str(exc))
            return

    def _on_get_proxies(self, event: ops.ActionEvent) -> None:
        """Handle the get_proxied_endpoints action."""
        try:
            proxy_config = self._http_proxy.fetch_proxies()
            result = {
                "http-proxy": proxy_config.http_proxy,
                "https-proxy": proxy_config.https_proxy,
            }
            event.set_results(result)
        except (ValueError, HTTPProxyUnavailableError) as exc:
            logger.exception("Error response from http-proxy provider.")
            event.fail(str(exc))


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(HTTPProxyConfiguratorCharm)
