# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the charm in integrator mode."""

from typing import cast

import jubilant
import pytest
import requests


@pytest.mark.abort_on_fail
def test_config_hostnames_and_paths(
    juju: jubilant.Juju, application: str, squid_proxy: str, http_proxy_requirer: str
):
    """Test the charm configuration in integrator mode.

    Args:
        juju: Jubilant juju fixture
        application: Name of the ingress-configurator application.
        squid_proxy: Name of the squid_proxy application.
        http_proxy_requirer: Name of the requirer application.
    """
    juju.integrate(f"{squid_proxy}:http-proxy", f"{application}:http-proxy")
    juju.config(
        app=application,
        values={
            "http-proxy-domains": "canonical.com",
        },
    )
    juju.wait(
        lambda status: jubilant.all_active(status, squid_proxy, application),
        error=jubilant.any_error,
    )

    proxy_config = juju.run(f"{application}/0", "get-proxies")
    https_proxy = proxy_config.results.get("https-proxy")
    response = requests.get(
        "https://canonical.com",
        proxies={"https": cast(str, https_proxy)},
        timeout=60,
    )
    assert "Trusted open source" in response.text

    juju.integrate(f"{application}:delegate-http-proxy", f"{http_proxy_requirer}:http-proxy")
    juju.config(
        app=application,
        values={"http-proxy-domains": "canonical.com", "http-proxy-auth": "srcip"},
    )
    juju.wait(
        lambda status: jubilant.all_active(status, squid_proxy, application, http_proxy_requirer),
        error=jubilant.any_error,
    )
    output = juju.ssh(
        f"{http_proxy_requirer}/0",
        f"curl -x {https_proxy} https://canonical.com -I",
    )
    assert "HTTP/1.1 200 Connection established" in output
