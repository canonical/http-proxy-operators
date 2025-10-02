# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the charm in integrator mode."""

import jubilant
import pytest
import requests


@pytest.mark.abort_on_fail
def test_config_hostnames_and_paths(
    juju: jubilant.Juju,
    application: str,
    squid_proxy: str,
):
    """Test the charm configuration in integrator mode.

    Args:
        juju: Jubilant juju fixture
        application: Name of the ingress-configurator application.
        squid_proxy: Name of the squid_proxy application.
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
    response = requests.get(
        "https://canonical.com",
        proxies={"https": proxy_config.results.get("https_proxy")},
        timeout=60,
    )
    assert "Trusted open source" in response.text
