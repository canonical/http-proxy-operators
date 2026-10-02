#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the service."""

import logging
import os
import secrets
import subprocess  # nosec
import time
from typing import Any, cast

import ops
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.squid_forward_proxy.v0 import http_proxy
from charms.squid_forward_proxy.v0.http_proxy import DEFAULT_HTTP_PROXY_INTEGRATION_NAME

import policy
import relay

logger = logging.getLogger(__name__)

HTTP_PROXY_BACKEND_INTEGRATION_NAME = "http-proxy-backend"
PEER_INTEGRATION_NAME = "http-proxy-policy-peer"
POLICY_SERVER_ENDPOINT = "http://localhost:8080"


# this is not an error
class NotReady(Exception):  # noqa: N818
    """The Charm is not ready."""


class ReconcileEvent(ops.charm.EventBase):
    """Event representing a periodic reload of the charmed-bind service."""


class HttpProxyPolicyCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args: Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.on.define_event("reconcile", ReconcileEvent)
        self._relay = relay.HttpProxyRequestRelay(
            proxy_provider=http_proxy.HttpProxyPolyProvider(
                charm=self, integration_name=DEFAULT_HTTP_PROXY_INTEGRATION_NAME
            ),
            provider_relations=self.model.relations[DEFAULT_HTTP_PROXY_INTEGRATION_NAME],
            proxy_backend=http_proxy.HttpProxyPolyRequirer(
                charm=self, integration_name=HTTP_PROXY_BACKEND_INTEGRATION_NAME
            ),
            backend_relation=self.model.get_relation(HTTP_PROXY_BACKEND_INTEGRATION_NAME),
        )
        self._postgresql = DatabaseRequires(
            self, relation_name="postgresql", database_name=self.app.name
        )
        self._peer_relation = self.model.get_relation(relation_name=PEER_INTEGRATION_NAME)
        self.framework.observe(self.on.install, self._install)
        self.framework.observe(self.on.upgrade_charm, self._install)
        self.framework.observe(self.on.config_changed, self._reconcile)
        self.framework.observe(self._postgresql.on.database_created, self._reconcile)
        self.framework.observe(self._postgresql.on.endpoints_changed, self._reconcile)
        self.framework.observe(self.on.postgresql_relation_broken, self._reconcile)
        self.framework.observe(
            self.on[DEFAULT_HTTP_PROXY_INTEGRATION_NAME].relation_changed, self._reconcile
        )
        self.framework.observe(
            self.on[DEFAULT_HTTP_PROXY_INTEGRATION_NAME].relation_joined, self._reconcile
        )
        self.framework.observe(
            self.on[DEFAULT_HTTP_PROXY_INTEGRATION_NAME].relation_departed, self._reconcile
        )
        self.framework.observe(
            self.on[DEFAULT_HTTP_PROXY_INTEGRATION_NAME].relation_broken, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_BACKEND_INTEGRATION_NAME].relation_changed, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_BACKEND_INTEGRATION_NAME].relation_joined, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_BACKEND_INTEGRATION_NAME].relation_departed, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_BACKEND_INTEGRATION_NAME].relation_broken, self._reconcile
        )
        self.framework.observe(self.on[PEER_INTEGRATION_NAME].relation_changed, self._reconcile)
        self.framework.observe(self.on[PEER_INTEGRATION_NAME].relation_joined, self._reconcile)
        self.framework.observe(self.on.secret_changed, self._reconcile)
        self.framework.observe(self.on.create_superuser_action, self._create_superuser)
        self.framework.observe(self.on.reconcile, self._reconcile)
        self.unit.open_port("tcp", 8080)

    def _install(self, _: ops.EventBase) -> None:
        """Install charmed-http-proxy-policy snap and refresh timer."""
        self.unit.status = ops.MaintenanceStatus("installing charmed-http-proxy-policy")
        policy.install_snap()
        policy.install_refresh_timer(self.unit.name)
        self.unit.status = ops.ActiveStatus()

    def _reconcile(self, _: ops.EventBase) -> None:
        """Run the main reconciliation loop."""
        if self._peer_relation is None:
            self.unit.status = ops.WaitingStatus("waiting for peer relation")
            return
        try:
            self._setup_policy_server()
            if not self.unit.is_leader():
                return
            user = cast(dict[str, str], self._get_peer_secrets("django-superuser"))
            client = policy.HttpProxyPolicyClient(
                username=user["username"], password=user["password"]
            )
            statistic = self._relay.relay(client=client)
            self._update_status(statistic=statistic)
        except NotReady as e:
            if self.unit.is_leader():
                self.app.status = ops.WaitingStatus(str(e))

    def _setup_policy_server(self) -> None:
        """Set up the charmed-http-proxy-policy server."""
        secret_key = self._get_peer_secrets("django-secret-key")
        if not secret_key:
            if self.unit.is_leader():
                secret_key = {"secret-key": secrets.token_urlsafe(32)}
                self._create_peer_secrets("django-secret-key", secret_key)
            else:
                raise NotReady("waiting for leader to create django secret key")
        postgresql_config = self._get_postgresql_credentials()
        if not postgresql_config:
            raise NotReady("waiting for postgresql")
        snap_config = {
            "allowed-hosts": '["*"]',
            "secret-key": secret_key["secret-key"],
            "log-level": "info",
            **postgresql_config,
        }
        policy.config_snap(snap_config)
        deadline = time.time() + 5 * 60
        ready = policy.server_ready(POLICY_SERVER_ENDPOINT)
        while time.time() < deadline and not ready:
            ready = policy.server_ready(POLICY_SERVER_ENDPOINT)
            time.sleep(5)
        if not ready:
            raise RuntimeError("failed to start policy server")
        policy_user = self._get_peer_secrets("django-superuser")
        if not policy_user:
            if self.unit.is_leader():
                policy_user = {"username": "charm", "password": secrets.token_urlsafe(16)}
                self._create_peer_secrets("django-superuser", policy_user)
            else:
                raise NotReady("waiting for leader to create django superuser")
        policy.create_or_update_user(policy_user["username"], policy_user["password"])

    def _update_status(self, statistic: relay.HttpProxyPolicyStatistic) -> None:
        """Update unit and app status."""
        if not self.unit.is_leader():
            self.unit.status = ops.ActiveStatus()
            return
        if statistic.invalid_backend_responses:
            self.app.status = ops.BlockedStatus(
                "Invalid responses from http proxy backend. Check debug logs."
            )
            return
        if statistic.invalid_backend_relations:
            self.app.status = ops.BlockedStatus(
                "Invalid http proxy backend integrations. Check debug logs."
            )
            return
        if statistic.missing_backend_relations:
            self.app.status = ops.WaitingStatus("Waiting for http-proxy-backend relation.")
            return

        fields = {
            "accepted": statistic.accepted_requests,
            "rejected": statistic.rejected_requests,
            "pending": statistic.pending_requests,
            "invalid requests": statistic.invalid_requests,
            "duplicated": statistic.duplicated_requests,
            "unsupported": statistic.unsupported_requests,
            "invalid integrations": statistic.invalid_relations,
            "invalid backend responses": statistic.invalid_backend_responses,
        }
        summary = ", ".join(f"{k}: {v}" for k, v in fields.items() if v)

        self.app.status = ops.ActiveStatus(summary)

    def _get_peer_secrets(self, field: str) -> dict[str, str] | None:
        """Get a juju secret from peer relation.

        Args:
            field: peer relation field.

        Returns:
            The content of the juju secret, or None if secret not exists.
        """
        secret_id = cast(ops.Relation, self._peer_relation).data[self.app].get(field)
        if not secret_id:
            return None
        try:
            secret = self.model.get_secret(id=secret_id)
        except (ops.SecretNotFoundError, ops.ModelError):
            return None
        return secret.get_content(refresh=True)

    def _create_peer_secrets(self, field: str, content: dict[str, str]) -> None:
        """Create a juju secret in the peer relation.

        Args:
            field: peer relation field.
            content: secret content.
        """
        secret = self.app.add_secret(content=content)
        cast(ops.Relation, self._peer_relation).data[self.app][field] = cast(str, secret.id)

    def _get_postgresql_credentials(self) -> dict[str, str] | None:
        """Get postgresql credentials from the postgresql integration.

        Returns:
            postgresql credentials.
        """
        relation = self.model.get_relation("postgresql")
        if not relation or not relation.app:
            return None
        endpoint = self._postgresql.fetch_relation_field(relation.id, "endpoints")
        database = self._postgresql.fetch_relation_field(relation.id, "database")
        username = self._postgresql.fetch_relation_field(relation.id, "username")
        password = self._postgresql.fetch_relation_field(relation.id, "password")
        if not all((endpoint, database, username, password)):
            return None
        host, _, port = endpoint.partition(":")
        if not port:
            port = "5432"
        return {
            "database-host": host,
            "database-port": port,
            "database-user": username,
            "database-password": password,
            "database-name": database,
        }

    def _create_superuser(self, event: ops.ActionEvent) -> None:
        """Handle create-superuser action.

        Args:
            event: ops framework action event.
        """
        password = secrets.token_urlsafe(16)
        try:
            subprocess.run(  # nosec
                ["charmed-http-proxy-policy.manage", "createsuperuser", "--noinput"],
                check=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={
                    **os.environ,
                    "DJANGO_SUPERUSER_PASSWORD": password,
                    "DJANGO_SUPERUSER_USERNAME": event.params["username"],
                    "DJANGO_SUPERUSER_EMAIL": event.params["email"],
                },
            )
            event.set_results(
                {
                    "username": event.params["username"],
                    "password": password,
                    "email": event.params["email"],
                }
            )
        except subprocess.CalledProcessError as e:
            event.fail(f"failed to create superuser: {e.stdout}")


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(HttpProxyPolicyCharm)
