# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests configuration."""

import pathlib
from typing import cast

import jubilant
import pytest
import yaml

JUJU_WAIT_TIMEOUT = 10 * 60  # 10 minutes
SQUID_PROXY_APP = "squid-forward-proxy"


@pytest.fixture(scope="session", name="charm")
def charm_fixture(pytestconfig: pytest.Config):
    """Pytest fixture that packs the charm and returns the filename, or --charm-file if set."""
    charm = pytestconfig.getoption("--charm-file")
    assert charm, "--charm-file must be set"
    yield charm


@pytest.fixture(scope="module", name="juju")
def juju_fixture(request: pytest.FixtureRequest):
    """Pytest fixture that wraps :meth:`jubilant.with_model`."""

    def show_debug_log(juju: jubilant.Juju):
        """Show the debug log if tests failed.

        Args:
            juju: Jubilant juju instance.
        """
        if request.session.testsfailed:
            log = juju.debug_log(limit=1000)
            print(log, end="")

    model = request.config.getoption("--model")
    if model:
        juju = jubilant.Juju(model=model)
        juju.wait_timeout = JUJU_WAIT_TIMEOUT
        yield juju
        show_debug_log(juju)
        return

    keep_models = cast(bool, request.config.getoption("--keep-models"))
    with jubilant.temp_model(keep=keep_models) as juju:
        juju.wait_timeout = JUJU_WAIT_TIMEOUT
        yield juju


@pytest.fixture(scope="module", name="application")
def application_fixture(pytestconfig: pytest.Config, juju: jubilant.Juju, charm: str):
    """Deploy the ingress-configurator application.

    Args:
        juju: Jubilant juju fixture.
        charm_file: Path to the packed charm file.

    Yields:
        The ingress-configurator app name.
    """
    metadata = yaml.safe_load(pathlib.Path("./charmcraft.yaml").read_text(encoding="UTF-8"))
    app_name = metadata["name"]
    if pytestconfig.getoption("--no-setup") and app_name in juju.status().apps:
        yield app_name
        return
    juju.deploy(
        charm=charm,
        app=app_name,
        base="ubuntu@24.04",
    )
    yield app_name


@pytest.fixture(scope="module", name="squid_proxy")
def squid_proxy_fixture(pytestconfig: pytest.Config, juju: jubilant.Juju):
    """Deploy the squid-forward-proxy charm.

    Args:
        juju: Jubilant juju fixture.

    Yields:
        The deployed application name.
    """
    if pytestconfig.getoption("--no-setup") and SQUID_PROXY_APP in juju.status().apps:
        yield SQUID_PROXY_APP
        return
    juju.deploy(
        charm=SQUID_PROXY_APP,
        app=SQUID_PROXY_APP,
        channel="latest/edge",
        revision=22,
        base="ubuntu@24.04",
    )
    juju.wait(
        lambda status: jubilant.all_active(status, SQUID_PROXY_APP),
    )
    yield SQUID_PROXY_APP
