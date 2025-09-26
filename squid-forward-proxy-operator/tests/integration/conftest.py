# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test charm fixtures."""
import asyncio
import json
import os.path
import pathlib
import typing

import juju.application
import pytest
import pytest_asyncio
from pytest_operator.plugin import OpsTest


@pytest_asyncio.fixture(scope="module", name="squid_proxy")
async def squid_proxy_fixture(
    ops_test: OpsTest, pytestconfig: pytest.Config
) -> juju.application.Application:
    """Build and deploy the charm in the testing model."""
    charm = pytestconfig.getoption("--charm-file")
    if not charm:
        charm = await ops_test.build_charm(".")
    assert ops_test.model
    charm = await ops_test.model.deploy(os.path.abspath(charm), num_units=3)
    await ops_test.model.wait_for_idle()
    return charm


class AnyCharm:
    """any-charm helper."""

    def __init__(self, ops_test: OpsTest, name: str) -> None:
        """Initialize the any-charm helper.

        Args:
            ops_test: OpsTest instance
            name: any-charm application name
        """
        assert ops_test.model
        self._model = ops_test.model
        self._app: juju.application.Application | None = None
        self.name = name

    async def deploy(self) -> None:
        """Deploy the any-charm in the testing model."""
        any_charm_py = pathlib.Path(__file__).parent / "any_charm.py"
        any_charm_py_content = any_charm_py.read_text(encoding="utf-8")
        http_proxy_py = (
            pathlib.Path(__file__).parent.parent.parent
            / "lib/charms/squid_forward_proxy/v0/http_proxy.py"
        )
        http_proxy_py_content = http_proxy_py.read_text(encoding="utf-8")
        self._app = await self._model.deploy(
            "any-charm",
            application_name=self.name,
            channel="latest/edge",
            config={
                "src-overwrite": json.dumps(
                    {"any_charm.py": any_charm_py_content, "http_proxy.py": http_proxy_py_content}
                ),
                "python-packages": "requests\npydantic~=2.0",
            },
        )

    async def integrate(self, other: str) -> None:
        """Integrate the any-charm with another charm.

        Args:
            other: charm to integrate
        """
        await self._model.integrate(self.name, other)
        await self._model.wait_for_idle(apps=[self.name])

    async def _run_action(self, action_name, **params) -> dict:
        """Run an action.

        Args:
            action_name: action name
            params: params to pass to the action

        Returns:
            action results.
        """
        action = (
            await typing.cast(juju.application.Application, self._app)
            .units[0]
            .run_action(action_name, **params)
        )
        await action.wait()
        return action.results

    async def _run_rpc(self, method: str, **params) -> dict | list | str | int | None:
        """Run any-charm rpc action.

        Args:
            method: rpc method
            params: params to pass to the rpc method

        Returns:
            rpc results.
        """
        result = await self._run_action("rpc", method=method, kwargs=json.dumps(params))
        return json.loads(result["return"])

    async def request_proxy(
        self, domains: list[str], auth: list[str], src_ips: list[str] | None = None
    ) -> None:
        """Request HTTP proxy from the HTTP proxy provider.

        Args:
            domains: HTTP proxy domains
            auth: HTTP proxy auth
            src_ips: HTTP proxy src_ips
        """
        await self._run_rpc("request_proxy", domains=domains, auth=auth, src_ips=src_ips)

    async def test_proxy(
        self,
        url: str,
    ) -> int:
        """Test the HTTP proxy returned from the HTTP proxy provider.

        Args:
            url: target url

        Returns:
            HTTP status code
        """
        return typing.cast(
            int,
            await self._run_rpc(
                "test_proxy",
                url=url,
            ),
        )

    async def get_proxies(self) -> dict | None:
        """Get the HTTP proxy returned from the HTTP proxy provider.

        Returns:
            HTTP proxy returned from the HTTP proxy provider.
        """
        return typing.cast(dict, await self._run_rpc("get_proxies"))


@pytest_asyncio.fixture(scope="module", name="any_charm_abcd")
async def any_charm_abcd_fixture(ops_test: OpsTest) -> list[AnyCharm]:
    """Deploy the any-charms in the testing model."""
    any_charms = [
        AnyCharm(
            ops_test=ops_test,
            name="any-charm-a",
        ),
        AnyCharm(
            ops_test=ops_test,
            name="any-charm-b",
        ),
        AnyCharm(
            ops_test=ops_test,
            name="any-charm-c",
        ),
        AnyCharm(
            ops_test=ops_test,
            name="any-charm-d",
        ),
    ]
    await asyncio.gather(*[any_charm.deploy() for any_charm in any_charms])

    assert ops_test.model
    await ops_test.model.wait_for_idle(apps=[any_charm.name for any_charm in any_charms])
    return any_charms


@pytest_asyncio.fixture(scope="module")
async def any_charm_a(any_charm_abcd, squid_proxy) -> AnyCharm:
    """Set up the any-charm-a in the testing model."""
    any_charm = any_charm_abcd[0]
    await any_charm.integrate(f"{squid_proxy.name}:http-proxy")
    return any_charm


@pytest_asyncio.fixture(scope="module")
async def any_charm_b(any_charm_abcd, squid_proxy) -> AnyCharm:
    """Set up the any-charm-b in the testing model."""
    any_charm = any_charm_abcd[1]
    await any_charm.integrate(f"{squid_proxy.name}:http-proxy")
    return any_charm


@pytest_asyncio.fixture(scope="module")
async def any_charm_c(any_charm_abcd, squid_proxy) -> AnyCharm:
    """Set up the any-charm-c in the testing model."""
    any_charm = any_charm_abcd[2]
    await any_charm.integrate(f"{squid_proxy.name}:http-proxy")
    return any_charm


@pytest_asyncio.fixture(scope="module")
async def any_charm_d(any_charm_abcd, squid_proxy) -> AnyCharm:
    """Set up the any-charm-d in the testing model."""
    any_charm = any_charm_abcd[3]
    await any_charm.integrate(f"{squid_proxy.name}:http-proxy")
    return any_charm
