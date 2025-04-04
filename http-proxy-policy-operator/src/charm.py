#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the service."""

import dataclasses
import logging
import os
import secrets
import subprocess
import time
from typing import Any, cast

import ops
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires

import http_proxy
import policy

logger = logging.getLogger(__name__)

HTTP_PROXY_INTEGRATION_NAME = "http-proxy"
HTTP_PROXY_BACKEND_INTEGRATION_NAME = "http-proxy-backend"
PEER_INTEGRATION_NAME = "http-proxy-policy-peer"
POLICY_SERVER_ENDPOINT = "http://localhost:8080"


@dataclasses.dataclass
class HttpProxyPolicyStatistic:  # pylint: disable=too-many-instance-attributes
    """HTTP Proxy Policy charm statistic.

    Attributes:
        invalid_relations: invalid proxy request integrations
        invalid_requests: invalid proxy requests
        duplicated_requests: duplicated proxy requests
        accepted_requests: accepted proxy requests
        rejected_requests: rejected proxy requests
        invalid_backend_responses: invalid backend responses
        invalid_backend_relations: invalid backend relation
        missing_backend_relations: missing backend relation
    """

    invalid_relations: int = 0
    invalid_requests: int = 0
    duplicated_requests: int = 0
    accepted_requests: int = 0
    rejected_requests: int = 0
    invalid_backend_responses: int = 0
    invalid_backend_relations: int = 0
    missing_backend_relations: int = 0


# this is not an error
class NotReady(Exception):  # noqa: N818
    """The Charm is not ready."""


class HttpProxyPolicyCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args: Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self._proxy_provider = http_proxy.HttpProxyPolyProvider(
            charm=self, integration_name=HTTP_PROXY_INTEGRATION_NAME
        )
        self._backend_requirer = http_proxy.HttpProxyPolyRequirer(
            charm=self, integration_name=HTTP_PROXY_BACKEND_INTEGRATION_NAME
        )
        self._postgresql = DatabaseRequires(
            self, relation_name="postgresql", database_name=self.app.name
        )
        self._statistic = HttpProxyPolicyStatistic()
        self._peer_relation = self.model.get_relation(relation_name=PEER_INTEGRATION_NAME)
        self.framework.observe(self.on.install, self._install)
        self.framework.observe(self.on.upgrade_charm, self._install)
        self.framework.observe(self.on.config_changed, self._reconcile)
        self.framework.observe(self._postgresql.on.database_created, self._reconcile)
        self.framework.observe(self._postgresql.on.endpoints_changed, self._reconcile)
        self.framework.observe(self.on.postgresql_relation_broken, self._reconcile)
        self.framework.observe(
            self.on[HTTP_PROXY_INTEGRATION_NAME].relation_changed, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_INTEGRATION_NAME].relation_joined, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_INTEGRATION_NAME].relation_departed, self._reconcile
        )
        self.framework.observe(
            self.on[HTTP_PROXY_INTEGRATION_NAME].relation_broken, self._reconcile
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
            self._statistic = HttpProxyPolicyStatistic()
            self._setup_policy_server()
            if not self.unit.is_leader():
                return
            collected_requests = self._collect_proxy_requests()
            evaluated_requests = self._evaluate_proxy_requests(collected_requests)
            self._relay_requests(evaluated_requests)
            self._update_status()
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

    def _collect_proxy_requests(self) -> dict[str, http_proxy.HttpProxyRequest]:
        """Collect proxy requests from http_proxy relations.

        Returns:
            proxy requests from http_proxy relations.
        """
        collected: dict[str, http_proxy.HttpProxyRequest] = {}
        duplicated_requirers = set()
        for relation in self.model.relations[HTTP_PROXY_INTEGRATION_NAME]:
            try:
                proxy_requests = self._proxy_provider.open_request_list(relation.id)
            except http_proxy.IntegrationDataError:
                self._statistic.invalid_relations += 1
                continue
            for requirer in proxy_requests.get_requirer_ids():
                if requirer in collected or requirer in duplicated_requirers:
                    self._statistic.duplicated_requests += 1
                    collected.pop(requirer, None)
                    duplicated_requirers.add(requirer)
                    continue
                try:
                    collected[requirer] = proxy_requests.get(requirer)
                except ValueError:
                    self._statistic.invalid_requests += 1
                    continue
        return collected

    def _evaluate_proxy_requests(
        self, proxy_requests: dict[str, http_proxy.HttpProxyRequest]
    ) -> dict[str, policy.EvaluatedHttpProxyRequest]:
        """Submit the proxy requests to the HTTP proxy policy server.

        Args:
            proxy_requests: proxy requests from http_proxy relations.

        Returns:
            evaluated proxy requests returned by the HTTP proxy policy server.
        """
        user = cast(dict[str, str], self._get_peer_secrets("django-superuser"))
        client = policy.HttpProxyPolicyClient(username=user["username"], password=user["password"])
        return {str(item.id): item for item in client.refresh(list(proxy_requests.values()))}

    def _relay_requests(self, proxy_requests: dict[str, policy.EvaluatedHttpProxyRequest]) -> None:
        """Relay all proxy requests and responses between the http proxy relation and the backend.

        Args:
            proxy_requests: proxy requests from http_proxy relations.
        """
        backend_requests = self._get_backend_requests()
        backend_responses = self._get_backend_responses()
        accepted_requests = set()
        for relation_request in proxy_requests.values():
            self._relay_request(
                relation_request=relation_request,
                backend_responses=backend_responses,
                backend_requests=backend_requests,
            )
            if relation_request.status == http_proxy.PROXY_STATUS_ACCEPTED:
                accepted_requests.add(str(relation_request.id))
        # if the http_proxy backend is not available (e.g., relation removed),
        # skip updating the http_proxy backend request list
        if backend_requests is not None:
            for requirer_id in backend_requests.get_requirer_ids():
                if requirer_id not in accepted_requests:
                    backend_requests.delete(requirer_id=requirer_id)

    def _relay_request(
        self,
        relation_request: policy.EvaluatedHttpProxyRequest,
        backend_responses: http_proxy._HttpProxyResponseListReader | None,
        backend_requests: http_proxy._HttpProxyRequestListReadWriter | None,
    ) -> None:
        """Relay proxy requests and responses between the http proxy relation and the backend.

        Args:
            relation_request: proxy request from http_proxy relations.
            backend_responses: proxy responses from http_proxy backend.
            backend_requests: proxy requests to http_proxy relations.
        """
        proxy_responses = self._proxy_provider.open_response_list(relation_request.group)
        if relation_request.status == http_proxy.PROXY_STATUS_ACCEPTED:
            # if the http_proxy backend is not available (e.g., relation removed),
            # skip updating the http_proxy backend request list
            if backend_requests is not None:
                backend_requests.add_or_replace(
                    requirer_id=relation_request.id,
                    domains=list(relation_request.domains),
                    auth=[relation_request.accepted_auth],
                    src_ips=list(relation_request.src_ips),
                )
            backend_response = None
            # if the http_proxy backend is not available (e.g., relation removed),
            # pretend that the backend doesn't have a response
            if backend_responses is not None:
                try:
                    backend_response = backend_responses.get(relation_request.id)
                except ValueError:
                    self._statistic.invalid_backend_responses += 1
            if backend_response is not None:
                proxy_responses.add_or_replace(
                    requirer_id=relation_request.id,
                    status=backend_response.status,
                    auth=backend_response.auth,
                    http_proxy=backend_response.http_proxy,
                    https_proxy=backend_response.https_proxy,
                    user=backend_response.user.model_dump(mode="json"),
                )
                return
        proxy_responses.add_or_replace(
            requirer_id=relation_request.id,
            status=relation_request.status,
            auth=None,
            http_proxy=None,
            https_proxy=None,
            user=None,
        )

    def _update_status(self) -> None:
        """Update unit and app status."""
        if not self.unit.is_leader():
            self.unit.status = ops.ActiveStatus()
            return
        if self._statistic.invalid_relations:
            self.app.status = ops.BlockedStatus("invalid relation data from http proxy backend")
            return
        if self._statistic.missing_backend_relations:
            self.app.status = ops.WaitingStatus("waiting for http proxy backend")
        status = f"accepted: {self._statistic.accepted_requests}"
        status += f", rejected: {self._statistic.rejected_requests}"
        if self._statistic.invalid_backend_responses:
            status += f", invalid requests: {self._statistic.invalid_backend_responses}"
        if self._statistic.duplicated_requests:
            status += f", duplicated requests: {self._statistic.duplicated_requests}"
        if self._statistic.invalid_relations:
            status += f", invalid integrations: {self._statistic.invalid_relations}"
        if self._statistic.invalid_backend_responses:
            status += f", invalid backend responses: {self._statistic.invalid_backend_responses}"

    def _get_backend_requests(self) -> http_proxy._HttpProxyRequestListReadWriter | None:
        """Open http proxy backend request list.

        Returns:
            http proxy backend request list, or None if backend not available.
        """
        relation = self.model.get_relation(HTTP_PROXY_BACKEND_INTEGRATION_NAME)
        if not relation:
            self._statistic.missing_backend_relations = 1
            return None
        return self._backend_requirer.open_request_list(relation.id)

    def _get_backend_responses(self) -> http_proxy._HttpProxyResponseListReader | None:
        """Open http proxy backend response list.

        Returns:
            http proxy backend response list, or None if backend not available.
        """
        relation = self.model.get_relation(HTTP_PROXY_BACKEND_INTEGRATION_NAME)
        if not relation:
            self._statistic.missing_backend_relations = 1
            return None
        try:
            return self._backend_requirer.open_response_list(relation.id)
        except http_proxy.IntegrationDataError:
            logger.exception("backend relation data error")
            self._statistic.invalid_backend_relations = 1
            return None

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
        secret = self.model.get_secret(id=secret_id)
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
            subprocess.run(
                ["charmed-http-proxy-policy.manage", "shell"],
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
