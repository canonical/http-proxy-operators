# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for charm tests."""

from unittest.mock import patch

import pytest

import squid


def pytest_addoption(parser):
    """Parse additional pytest options.

    Args:
        parser: Pytest parser.
    """
    parser.addoption("--charm-file", action="store")


@pytest.fixture(name="mock_squid")
def mock_squid_fixture():
    """Create a Squid object with necessary methods patched."""
    mock_config = ""
    mock_exporter_config = ""
    # this is not a real password
    mock_passwd = ""  # nosec

    def read_config() -> str:
        """Read the Squid configuration file.

        Returns:
            Squid configuration file.
        """
        return mock_config

    def write_config(content: str) -> None:
        """Write the Squid configuration file.

        Args:
            content: content to write.
        """
        nonlocal mock_config
        mock_config = content

    def read_exporter_config() -> str:
        """Read the exporter configuration file.

        Returns:
            exporter configuration file.
        """
        return mock_exporter_config

    def write_exporter_config(content: str) -> None:
        """Write the exporter configuration file.

        Args:
            content: content to write.
        """
        nonlocal mock_exporter_config
        mock_exporter_config = content

    def read_passwd():
        """Read the Squid passwd file.

        Returns:
            Squid passwd file.
        """
        return mock_passwd

    def write_passwd(content: str):
        """Write the Squid passwd file.

        Args:
            content: content to write.
        """
        nonlocal mock_passwd
        mock_passwd = content

    with (
        patch("squid.install"),
        patch("squid.reload"),
        patch("squid.write_config") as mock_write_config,
        patch("squid.read_config") as mock_read_config,
        patch("squid.write_passwd") as mock_write_passwd,
        patch("squid.read_passwd") as mock_read_passwd,
        patch("squid.restart_exporter"),
        patch("squid.write_exporter_config") as mock_write_exporter_config,
        patch("squid.read_exporter_config") as mock_read_exporter_config,
    ):
        mock_write_config.side_effect = write_config
        mock_read_config.side_effect = read_config
        mock_write_passwd.side_effect = write_passwd
        mock_read_passwd.side_effect = read_passwd
        mock_write_exporter_config.side_effect = write_exporter_config
        mock_read_exporter_config.side_effect = read_exporter_config
        yield squid
