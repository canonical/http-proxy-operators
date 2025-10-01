# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the charm in integrator mode."""

import jubilant
import pytest
import requests

from .conftest import get_unit_addresses


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
        haproxy: Name of the haproxy application.
        any_charm_backend: Any charm running an apache webserver.
        http_session: Modified requests session fixture for making HTTP requests.
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

    squid_proxy_address = str(get_unit_addresses(juju, squid_proxy)[0])
    response = requests.get(
        "https://canonical.com", proxies={"https": f"https://{squid_proxy_address}:3128"}
    )
    assert "Trusted open source" in response.text
