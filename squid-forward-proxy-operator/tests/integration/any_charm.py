# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test charm."""

import re

import requests
from any_charm_base import AnyCharmBase, logger  # pylint: disable=import-error

import http_proxy


class AnyCharm(AnyCharmBase):
    """HTTP proxy requirer charm."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialize the charm.

        Args:
            args: arguments passed to the charm.
            kwargs: keyword arguments passed to the charm.
        """
        super().__init__(*args, **kwargs)
        self._proxy_requirer = http_proxy.HttpProxyPolyRequirer(
            charm=self, integration_name="require-http-proxy"
        )
        self._requirer_id = "00000000-0000-0000-0000-000000000000"  # replace me

    def request_proxy(
        self, domains: list[str], auth: list[str], src_ips: list[str] | None = None
    ) -> None:
        """Request proxy from HTTP proxy provider.

        Args:
            domains: HTTP proxy domains.
            auth: HTTP proxy auth.
            src_ips: HTTP proxy src_ips.
        """
        integration = self.model.get_relation("require-http-proxy")
        proxy_requests = self._proxy_requirer.open_request_list(integration.id)
        proxy_requests.delete(self._requirer_id)
        proxy_requests.add(
            requirer_id=self._requirer_id, domains=domains, auth=auth, src_ips=src_ips
        )

    def test_proxy(
        self,
        url: str,
        override_user_pass: tuple[str, str] | None = None,
    ) -> int:
        """Test HTTP proxy returned from the HTTP proxy provider.

        Args:
            url: test target URL.
            override_user_pass: override user password in the proxy URL.

        Returns:
            HTTP status code.

        Raises:
            RuntimeError: if the HTTP proxy provider doesn't return a HTTP proxy.
        """
        proxies = self.get_proxies()
        if not proxies:
            raise RuntimeError("proxy not ready")
        if override_user_pass:
            proxies["http"] = self._set_user(proxies["http"], *override_user_pass)
            proxies["https"] = self._set_user(proxies["https"], *override_user_pass)
        try:
            logger.info("accessing %s via %s", url, proxies.get(self._requirer_id))
            return requests.get(url, proxies=proxies, timeout=5).status_code
        except requests.exceptions.ProxyError as e:
            return int(re.findall("Tunnel connection failed: (\\d+)", str(e))[0])

    def get_proxy_status(self) -> str | None:
        """Get HTTP proxy status returned from the HTTP proxy provider.

        Returns:
            HTTP proxy status returned from the HTTP proxy provider.
        """
        integration = self.model.get_relation("require-http-proxy")
        responses = self._proxy_requirer.open_response_list(integration.id)
        response = responses.get(self._requirer_id)
        if not response:
            return None
        return response.status

    def get_proxies(self) -> dict[str, str] | None:
        """Get HTTP proxies returned from the HTTP proxy provider.

        Returns:
            HTTP proxies returned from the HTTP proxy provider.
        """
        try:
            integration = self.model.get_relation("require-http-proxy")
            return self._proxy_requirer.get_proxies(integration.id, self._requirer_id)
        except http_proxy.HTTPProxyNotAvailableError:
            return None
