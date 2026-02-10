# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=import-error

"""Integration test charm."""

import secrets

import http_proxy
from any_charm_base import AnyCharmBase


class AnyCharm(AnyCharmBase):  # pylint: disable=too-few-public-methods
    """HTTP proxy backend charm."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialize the charm.

        Args:
            args: arguments passed to the charm.
            kwargs: keyword arguments passed to the charm.
        """
        super().__init__(*args, **kwargs)
        self._proxy_provider = http_proxy.HttpProxyPolyProvider(
            charm=self, integration_name="provide-http-proxy"
        )
        self.framework.observe(self.on["provide-http-proxy"].relation_changed, self.provide_proxy)

    def provide_proxy(self, _) -> None:
        """Provide http proxy to all requests."""
        if not self.unit.is_leader():
            return
        relation = self.model.get_relation("provide-http-proxy")
        proxy_requests = self._proxy_provider.open_request_list(relation.id)
        responses = self._proxy_provider.open_response_list(relation.id)
        for requirer in proxy_requests.get_requirer_ids():
            request = proxy_requests.get(requirer)
            auth = request.auth[0]
            if http_proxy.AUTH_METHOD_USERPASS in auth:
                user = {"username": "test", "password": secrets.token_hex()}
            else:
                user = None
            responses.add_or_replace(
                requirer_id=request.id,
                status=http_proxy.PROXY_STATUS_READY,
                auth=request.auth[0],
                http_proxy="http://proxy.test",
                https_proxy="https://proxy.test",
                user=user,
            )
