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

import policy


@pytest_asyncio.fixture(scope="module", name="http_proxy_policy")
async def http_proxy_policy_fixture(
    ops_test: OpsTest, pytestconfig: pytest.Config
) -> juju.application.Application:
    """Build and deploy the charm in the testing model."""
    charms = pytestconfig.getoption("--charm-file")
    if not charms:
        charm = await ops_test.build_charm(".")
    else:
        charm = [c for c in charms if c.endswith("http-proxy-policy_ubuntu@22.04-amd64.charm")][0]
    assert ops_test.model
    charm = await ops_test.model.deploy(os.path.abspath(charm), num_units=0)
    base_charm = await ops_test.model.deploy(
        "any-charm",
        application_name="proxy-provider",
        channel="latest/edge",
        config={
            "src-overwrite": json.dumps(
                {
                    "any_charm.py": (pathlib.Path(__file__).parent / "any_charm.py").read_text(),
                    "http_proxy.py": (
                        pathlib.Path(__file__).parent.parent.parent / "src/http_proxy.py"
                    ).read_text(),
                }
            ),
            "python-packages": "pydantic~=2.0",
        },
        num_units=3,
    )
    postgresql_charm = await ops_test.model.deploy("postgresql", channel="14/stable")
    await ops_test.model.integrate(f"{charm.name}:juju-info", base_charm.name)
    await ops_test.model.integrate(f"{charm.name}:http-proxy-backend", base_charm.name)
    await ops_test.model.integrate(f"{charm.name}:postgresql", postgresql_charm.name)
    await ops_test.model.wait_for_idle()
    return charm


class RequirerCharm:
    """any-charm helper."""

    def __init__(self, ops_test: OpsTest, requirer_id: str, name: str) -> None:
        """Initialize the any-charm helper.

        Args:
            ops_test: OpsTest instance
            requirer_id: requirer id
            name: any-charm application name
        """
        assert ops_test.model
        self._model = ops_test.model
        self._app: juju.application.Application | None = None
        self.id = requirer_id
        self.name = name

    async def deploy(self) -> None:
        """Deploy the any-charm in the testing model."""
        any_charm_py = (
            pathlib.Path(__file__).parent.parent.parent.parent
            / "squid-forward-proxy-operator/tests/integration/any_charm.py"
        )
        any_charm_py_content = any_charm_py.read_text(encoding="utf-8").replace(
            "00000000-0000-0000-0000-000000000000", self.id
        )
        http_proxy_py = pathlib.Path(__file__).parent.parent.parent / "src/http_proxy.py"
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

    async def get_proxies(self) -> dict | None:
        """Get the HTTP proxy returned from the HTTP proxy provider.

        Returns:
            HTTP proxy returned from the HTTP proxy provider.
        """
        return typing.cast(dict, await self._run_rpc("get_proxies"))

    async def get_proxy_status(self) -> str | None:
        """Get the HTTP proxy status returned from the HTTP proxy provider.

        Returns:
            HTTP proxy status returned from the HTTP proxy provider.
        """
        return typing.cast(str, await self._run_rpc("get_proxy_status"))


@pytest_asyncio.fixture(scope="module", name="requirer_charm_abcd")
async def requirer_charm_abcd_fixture(ops_test: OpsTest) -> list[RequirerCharm]:
    """Deploy the any-charms in the testing model."""
    any_charms = [
        RequirerCharm(
            ops_test=ops_test,
            requirer_id="00000000-0000-4000-8000-000000000000",
            name="proxy-requirer-a",
        ),
        RequirerCharm(
            ops_test=ops_test,
            requirer_id="00000000-0000-4000-9000-000000000000",
            name="proxy-requirer-b",
        ),
        RequirerCharm(
            ops_test=ops_test,
            requirer_id="00000000-0000-4000-a000-000000000000",
            name="proxy-requirer-c",
        ),
    ]
    await asyncio.gather(*[any_charm.deploy() for any_charm in any_charms])
    assert ops_test.model
    await ops_test.model.wait_for_idle(apps=[any_charm.name for any_charm in any_charms])
    return any_charms


@pytest_asyncio.fixture(scope="module")
async def requirer_charm_a(requirer_charm_abcd, http_proxy_policy) -> RequirerCharm:
    """Set up the requirer-charm-a in the testing model."""
    requirer_charm = requirer_charm_abcd[0]
    await requirer_charm.integrate(f"{http_proxy_policy.name}:http-proxy")
    return requirer_charm


@pytest_asyncio.fixture(scope="module")
async def requirer_charm_b(requirer_charm_abcd, http_proxy_policy) -> RequirerCharm:
    """Set up the requirer-charm-b in the testing model."""
    requirer_charm = requirer_charm_abcd[1]
    await requirer_charm.integrate(f"{http_proxy_policy.name}:http-proxy")
    return requirer_charm


@pytest_asyncio.fixture(scope="module")
async def requirer_charm_c(requirer_charm_abcd, http_proxy_policy) -> RequirerCharm:
    """Set up the requirer-charm-c in the testing model."""
    requirer_charm = requirer_charm_abcd[2]
    await requirer_charm.integrate(f"{http_proxy_policy.name}:http-proxy")
    return requirer_charm


@pytest_asyncio.fixture(scope="module")
async def policy_client(ops_test, http_proxy_policy):
    """Create the policy service client"""
    _, status, _ = await ops_test.juju("status", "--format", "json")
    status = json.loads(status)
    units = status["applications"]["proxy-provider"]["units"]
    ip_list = []
    for key in sorted(units.keys(), key=lambda n: int(n.split("/")[-1])):
        ip_list.append(units[key]["public-address"])
    endpoint = f"http://{ip_list[0]}:8080"
    action = await http_proxy_policy.units[0].run_action(
        "create-superuser", username="test", email="test@test.test"
    )
    await action.wait()
    password = action.results["password"]
    return policy.HttpProxyPolicyClient(endpoint=endpoint, username="test", password=password)
