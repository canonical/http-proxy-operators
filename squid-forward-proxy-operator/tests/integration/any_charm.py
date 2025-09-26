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
        self._proxy_requirer = http_proxy.HttpProxyDynamicRequirer(
            charm=self,
            relation_name="require-http-proxy",
        )

    def request_proxy(
        self, domains: list[str], auth: list[str], src_ips: list[str] | None = None
    ) -> None:
        """Request proxy from HTTP proxy provider.

        Args:
            domains: HTTP proxy domains.
            auth: HTTP proxy auth.
            src_ips: HTTP proxy src_ips.
        """
        self._proxy_requirer.request_http_proxy(domains, auth, src_ips)

    def test_proxy(
        self,
        url: str,
    ) -> int:
        """Test HTTP proxy returned from the HTTP proxy provider.

        Args:
            url: test target URL.

        Returns:
            HTTP status code.

        Raises:
            RuntimeError: if the HTTP proxy provider doesn't return a HTTP proxy.
        """
        proxies = self.get_proxies()
        if not proxies:
            raise RuntimeError("proxy not ready")
        try:
            logger.info("accessing %s via %s", url, proxies)
            return requests.get(url, proxies=proxies, timeout=5).status_code
        except requests.exceptions.ProxyError as e:
            return int(re.findall("Tunnel connection failed: (\\d+)", str(e))[0])

    def get_proxy_status(self) -> str:
        """Get HTTP proxy status returned from the HTTP proxy provider.

        Returns:
            HTTP proxy status returned from the HTTP proxy provider.
        """
        try:
            self._proxy_requirer.fetch_proxies()
            return http_proxy.PROXY_STATUS_READY
        except http_proxy.HTTPProxyUnavailableError as e:
            return e.status

    def get_proxies(self) -> dict[str, str] | None:
        """Get HTTP proxies returned from the HTTP proxy provider.

        Returns:
            HTTP proxies returned from the HTTP proxy provider if ready else returns None.
        """
        try:
            proxies = self._proxy_requirer.fetch_proxies()
            return {
                "http": proxies.http_proxy,
                "https": proxies.https_proxy,
            }
        except http_proxy.HTTPProxyUnavailableError as e:
            logger.info(f"proxy not available: {e}")
            return None
