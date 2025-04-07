# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""HTTP proxy policy library."""

import pathlib
import subprocess  # nosec
import textwrap
import uuid
from typing import Optional

import requests
from charms.operator_libs_linux.v2 import snap

import http_proxy
import timer


def install_snap() -> None:
    """Install the charmed-http-proxy-policy charm."""
    snap.install_local(
        filename=str(
            pathlib.Path(__file__).resolve().parent / "charmed-http-proxy-policy_0.1_amd64.snap"
        ),
        dangerous=True,
    )


def uninstall_snap() -> None:
    """Uninstall the charmed-http-proxy-policy charm."""
    snap.remove("charmed-http-proxy-policy")


def config_snap(config: dict) -> None:
    """Configure the charmed-http-proxy-policy snap.

    Args:
        config: Snap configuration.
    """
    policy_snap = snap.SnapCache()["charmed-http-proxy-policy"]
    existing_config = policy_snap.get(None, typed=True)
    if any(existing_config.get(k) != v for k, v in config.items()):
        policy_snap.set(config, typed=True)
    policy_snap.start()


def install_refresh_timer(unit_name: str, interval: int = 60, timeout: int = 30) -> None:
    """Install a systemd timer for refreshing the HTTP proxy requests.

    Args:
        unit_name: The name of the juju unit.
        interval: The interval in seconds between each refresh.
        timeout: The maximum number of seconds to wait for a response.
    """
    timer.start_timer(
        unit_name=unit_name,
        event_name="reconcile",
        interval=interval,
        timeout=timeout,
    )


def server_ready(endpoint: str) -> bool:
    """Check if the HTTP proxy policy server is ready.

    Args:
        endpoint: The endpoint to check.

    Returns:
        True if the HTTP proxy policy server is ready.
    """
    try:
        requests.get(endpoint, timeout=5).raise_for_status()
    except (requests.exceptions.RequestException, TimeoutError):
        return False
    return True


def create_or_update_user(username: str, password: str) -> None:
    """Create or update the HTTP proxy policy superuser.

    Args:
        username: The username.
        password: The password.

    Raises:
        RuntimeError: If the action failed.
    """
    script = textwrap.dedent(
        f"""\
        from django.contrib.auth import get_user_model
        User = get_user_model()
        username, password = {repr(username)}, {repr(password)}
        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_password(password)
            user.save()
        elif not user.check_password(password):
            user.set_password(password)
            user.save()
        user.is_staff = True
        user.is_superuser = True
        user.save()
        """
    )
    try:
        subprocess.run(  # nosec
            ["charmed-http-proxy-policy.manage", "shell"],
            check=True,
            input=script,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"failed to update Django user: {e.stdout}") from e


class EvaluatedHttpProxyRequest(http_proxy.HttpProxyRequest):
    """Response returned from the HTTP proxy policy refresh API.

    Attributes:
        status: HTTP proxy request status.
        accepted_auth: accepted HTTP proxy authentication method.
    """

    status: str
    accepted_auth: Optional[str]


class HttpProxyPolicyClient:
    """HTTP proxy policy client."""

    def __init__(
        self, username: str, password: str, endpoint: str = "http://localhost:8080"
    ) -> None:
        """Initialize the http proxy policy client.

        Args:
            endpoint: http proxy policy endpoint.
            username: http proxy policy username.
            password: http proxy policy password.
        """
        self._endpoint = endpoint
        self._auth = (username, password)

    def refresh(
        self, proxy_requests: list[http_proxy.HttpProxyRequest]
    ) -> list[EvaluatedHttpProxyRequest]:
        """Refresh HTTP proxy requests.

        This updates all requests stored in the HTTP proxy policy and re-evaluates the rules
        against the updated requests. The evaluated requests are returned.

        Args:
            proxy_requests: list of http proxy requests.

        Returns:
            list of evaluated http proxy requests.
        """
        input_requests = {str(r.id): r for r in proxy_requests}
        payload = []
        for request in proxy_requests:
            request_dict = request.model_dump(mode="json")
            del request_dict["group"]
            request_dict["requirer"] = request_dict["id"]
            del request_dict["id"]
            payload.append(request_dict)
        response = requests.post(
            self._endpoint + "/api/v1/requests/refresh",
            json=payload,
            auth=self._auth,
            timeout=10,
        )
        response.raise_for_status()
        result = []
        for request in response.json():
            request["group"] = input_requests[request["requirer"]].group
            request["id"] = request["requirer"]
            del request["requirer"]
            result.append(EvaluatedHttpProxyRequest(**request))
        return result

    # pylint: disable=too-many-arguments
    def create_rule(
        self,
        *,
        requirer: uuid.UUID | None = None,
        domains: list[str] | None = None,
        auth: list[str] | None = None,
        src_ips: list[str] | None = None,
        verdict: str = "accept",
        comment: str | None = None,
    ) -> None:
        """Create a HTTP proxy policy rule.

        Args:
            requirer: match requirer
            domains: match domains
            auth: match auth
            src_ips: match src_ips
            verdict: rule verdict
            comment: rule comment
        """
        rule: dict[str, str | list[str]] = {}
        if requirer is not None:
            rule["requirer"] = str(requirer)
        if domains is not None:
            rule["domains"] = domains
        if auth is not None:
            rule["auth"] = auth
        if src_ips is not None:
            rule["src_ips"] = src_ips
        if verdict is not None:
            rule["verdict"] = verdict
        if comment is not None:
            rule["comment"] = comment
        response = requests.put(
            self._endpoint + "/api/v1/rules",
            auth=self._auth,
            json=rule,
            timeout=10,
        )
        response.raise_for_status()

    def get_rule(self, rule_id: int) -> dict | None:
        """Get a HTTP proxy policy rule.

        Args:
            rule_id: rule id

        Returns:
            HTTP proxy policy rule.
        """
        response = requests.get(
            self._endpoint + f"/api/v1/rules/{rule_id}",
            auth=self._auth,
            timeout=10,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def list_rules(self) -> list[dict]:
        """List all HTTP proxy policy rules.

        Returns:
            A list of HTTP proxy policy rule.
        """
        response = requests.get(
            self._endpoint + "/api/v1/rules",
            auth=self._auth,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    def delete_rule(self, rule_id: int) -> None:
        """Delete a HTTP proxy policy rule.

        Args:
            rule_id: rule id
        """
        response = requests.delete(
            self._endpoint + f"/api/v1/rules/{rule_id}",
            auth=self._auth,
            timeout=10,
        )
        response.raise_for_status()
