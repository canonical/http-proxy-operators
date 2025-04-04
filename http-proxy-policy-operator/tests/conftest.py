# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for charm tests."""

from unittest.mock import patch

import pytest

import policy


def pytest_addoption(parser):
    """Parse additional pytest options.

    Args:
        parser: Pytest parser.
    """
    parser.addoption("--charm-file", action="store")


@pytest.fixture(name="mock_policy")
def mock_policy_fixture():
    """Patch necessary methods in the policy module."""
    with (
        patch("policy.install_snap"),
        patch("policy.uninstall_snap"),
        patch("policy.config_snap"),
        patch("policy.install_refresh_timer"),
        patch("policy.create_or_update_user"),
        patch("policy.server_ready") as mock_server_ready,
        patch("policy.HttpProxyPolicyClient.refresh"),
    ):
        mock_server_ready.return_value = True
        yield policy
