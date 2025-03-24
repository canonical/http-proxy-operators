# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Squid helper."""

import ctypes.util
import pathlib
import secrets
import shutil
import string
import textwrap
from collections import defaultdict

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from http_proxy import (
    AUTH_METHOD_SRCIP,
    AUTH_METHOD_USERPASS,
    HttpProxySpec,
)

libcrypt = None  # pylint: disable=invalid-name


def _base36(number: int) -> str:
    """Convert integer to base 36.

    Args:
        number: Integer to convert.

    Returns:
        Integer in base 36.
    """
    base36 = ""
    alphabet = string.digits + string.ascii_lowercase
    if 0 <= number < len(alphabet):
        return alphabet[number]
    while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36
    return base36


def _crypt_hash(password: str, setting: str | None = None) -> str:
    """Create a hash of password using crypt.

    Args:
        password: password to hash.
        setting: crypt settings.

    Returns:
        hashed password

    Raises:
        RuntimeError: crypt errors.
    """
    global libcrypt  # pylint: disable=global-statement

    if libcrypt is None:
        libcrypt_path = ctypes.util.find_library("crypt")
        if not libcrypt_path:
            raise RuntimeError("libcrypt not found")
        libcrypt = ctypes.CDLL(libcrypt_path)
        libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        libcrypt.crypt.restype = ctypes.c_char_p

    if setting is None:
        salt = secrets.token_urlsafe(6)
        setting = f"$1${salt}"
    hashed = libcrypt.crypt(password.encode("utf-8"), setting.encode("utf-8")).decode("utf-8")
    if not hashed.startswith("$"):
        raise RuntimeError("crypt failed")
    return hashed


def _crypt_verify(hashed: str, password: str) -> bool:
    """Verify hashed password using crypt.

    Args:
        hashed: hashed password.
        password: password.

    Returns:
        true if hashed password matches.
    """
    expected = _crypt_hash(password, hashed)
    return expected == hashed


class Squid:
    """Squid service."""

    _CONFIG_PATH = pathlib.Path("/etc/squid/squid.conf")
    _HTPASSWD_PATH = pathlib.Path("/etc/squid/passwd")

    @staticmethod
    def derive_proxy_username(spec: HttpProxySpec) -> str:
        """Create a username for HTTP proxy authentication.

        Args:
            spec: HTTP proxy specification

        Returns:
            HTTP proxy authentication username.
        """
        # case-insensitive, less or equal to 32 characters for maximum compatibility
        return f"u{_base36(spec.group)}-{_base36(spec.id.int)}"

    def generate_config(self, specs: list[HttpProxySpec], http_port: int = 3128) -> str:
        """Generate Squid configuration.

        Args:
            specs: HTTP proxy specifications.
            http_port: HTTP proxy port.

        Returns:
            Squid configuration.
        """
        buffer = [
            textwrap.dedent(
                f"""\
                http_port {http_port}

                auth_param basic program /usr/lib/squid/basic_ncsa_auth {self._HTPASSWD_PATH}
                auth_param basic credentialsttl 60 seconds

                cache deny all
                """
            ),
            *sorted(
                [
                    self._generate_http_access_snippet(
                        spec=spec, comment=f"group: {spec.group}, id: {spec.id}"
                    )
                    for spec in specs
                ]
            ),
            textwrap.dedent(
                """\
                http_access deny all
                """
            ),
        ]
        return "\n".join(buffer)

    def _generate_http_access_snippet(
        self, spec: HttpProxySpec, comment: str | None = None
    ) -> str:
        """Generate HTTP access snippet in the Squid configuration.

        Args:
            spec: HTTP proxy specification.
            comment: comment for HTTP access snippet.

        Returns:
            HTTP access snippet.
        """
        buffer = [f"# {line}" for line in comment.splitlines()] if comment else []
        host_ports = defaultdict(list)
        for domain in spec.domains:
            host, port = spec.parse_domain(domain)
            if port:
                host_ports[host].append(port)
            else:
                host_ports[host].extend([80, 443])
        for idx, host in enumerate(sorted(host_ports)):
            acl_name_prefix = f"rel{spec.group}_{spec.id}_{idx}"
            acl_name_prefix = acl_name_prefix.replace("[", "")
            acl_name_prefix = acl_name_prefix.replace("]", "")

            host_buffer = []
            acl_names = []

            acl_name = f"{acl_name_prefix}_domain"
            acl_names.append(acl_name)
            host_buffer.append(f"acl {acl_name} dstdomain -n {host}")

            acl_name = f"{acl_name_prefix}_port"
            acl_names.append(acl_name)
            host_buffer.append(
                f"acl {acl_name} port {' '.join(map(str, sorted(host_ports[host])))}"
            )

            auth = spec.auth[0]

            if AUTH_METHOD_SRCIP in auth:
                acl_name = f"{acl_name_prefix}_src"
                acl_names.append(acl_name)
                host_buffer.append(f"acl {acl_name} src {' '.join(spec.src_ips)}")

            if AUTH_METHOD_USERPASS in auth:
                acl_name = f"{acl_name_prefix}_user"
                acl_names.append(acl_name)
                host_buffer.append(f"acl {acl_name} proxy_auth {self.derive_proxy_username(spec)}")

            acl_names.sort()
            host_buffer.append(f"http_access allow {' '.join(acl_names)}")
            buffer.extend(sorted(host_buffer))

        return "\n".join(buffer).strip() + "\n"

    def generate_passwd(self, user_pass: dict[str, str]) -> str:
        """Generate passwd file for Squid proxy authentication.

        Args:
            user_pass: Username password mapping.

        Returns:
            passwd file for Squid proxy authentication.
        """
        old_passwd = dict(
            line.split(":", maxsplit=1) for line in self.read_passwd().strip().splitlines()
        )
        new_passwd = {}
        for username, password in user_pass.items():
            if username in old_passwd and _crypt_verify(
                hashed=old_passwd[username], password=password
            ):
                new_passwd[username] = old_passwd[username]
            else:
                new_passwd[username] = _crypt_hash(password=password)
        return "\n".join(f"{user}:{new_passwd[user]}" for user in sorted(new_passwd))

    def install(self) -> None:  # pragma: nocover
        """Install Squid and charm dependencies."""
        apt.add_package(["squid", "libcrypt1"], update_cache=True)

    def reload(self) -> None:  # pragma: nocover
        """Reload or restart the Squid service."""
        service = "squid"
        if systemd.service_running(service):
            systemd.service_reload(service)
        else:
            systemd.service_start(service)

    def read_passwd(self) -> str:  # pragma: nocover
        """Read the passwd file.

        Returns:
            content of the passwd file.
        """
        self._HTPASSWD_PATH.touch(exist_ok=True, mode=0o600)
        shutil.chown(self._HTPASSWD_PATH, user="proxy", group="proxy")
        return self._HTPASSWD_PATH.read_text(encoding="utf-8")

    def write_passwd(self, content: str) -> None:  # pragma: nocover
        """Write the passwd file.

        Args:
            content: content to write.
        """
        self._HTPASSWD_PATH.write_text(content, encoding="utf-8")
        self._HTPASSWD_PATH.chmod(0o600)
        shutil.chown(self._HTPASSWD_PATH, user="proxy", group="proxy")

    def read_config(self) -> str:  # pragma: nocover
        """Read the Squid configuration file.

        Returns:
            Squid configuration file content.
        """
        return self._CONFIG_PATH.read_text(encoding="utf-8")

    def write_config(self, content: str) -> None:  # pragma: nocover
        """Write the Squid configuration file.

        Args:
            content: content to write.
        """
        self._CONFIG_PATH.write_text(content, encoding="utf-8")
