#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the service."""

import json
import logging
import secrets
import typing

import ops

import http_proxy
import squid

logger = logging.getLogger(__name__)

HTTP_PROXY_INTEGRATION_NAME = "http-proxy"
PEER_INTEGRATION_NAME = "squid-peer"


class SquidProxyCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args: typing.Any):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self._proxy_provider = http_proxy.HttpProxyPolyProvider(
            charm=self, integration_name=HTTP_PROXY_INTEGRATION_NAME
        )
        self.framework.observe(self.on.install, self._install)
        self.framework.observe(self.on.upgrade_charm, self._install)
        self.framework.observe(self.on.config_changed, self._reconcile)
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
        self.framework.observe(self.on[PEER_INTEGRATION_NAME].relation_changed, self._reconcile)
        self.framework.observe(self.on[PEER_INTEGRATION_NAME].relation_joined, self._reconcile)
        self.framework.observe(self.on.secret_changed, self._reconcile)
        self.framework.observe(self.on.update_status, self._reconcile)
        self.unit.open_port("tcp", 3128)

    def _install(self, _: ops.EventBase) -> None:
        """Install Squid."""
        self.unit.status = ops.MaintenanceStatus("installing squid")
        squid.install()
        self.unit.status = ops.ActiveStatus()

    def _reconcile(self, _: ops.EventBase) -> None:
        """Run the main reconciliation loop."""
        peer_integration = self.model.get_relation(relation_name=PEER_INTEGRATION_NAME)
        if not peer_integration:
            self.unit.status = ops.WaitingStatus("waiting for peer integration")
            return
        if self.unit.is_leader():
            self._reconcile_leader()
        else:
            self._reconcile_non_leader()

    def _reconcile_leader(self) -> None:
        """Run the main reconciliation loop for leader unit."""
        temporary_integration_errors = 0
        integration_errors = 0
        invalid_requests = 0
        proxy_requests: list[http_proxy.HttpProxyRequest] = []
        proxy_users: dict[str, str] = {}
        secret_ids = []
        for integration in self.model.relations["http-proxy"]:
            if integration.app is None:
                continue
            proxy_url = self._get_proxy_url(integration)
            if not proxy_url:
                temporary_integration_errors += 1
                continue
            try:
                reconciler = IntegrationReconciler(
                    charm=self,
                    proxy_url=proxy_url,
                    proxy_provider=self._proxy_provider,
                    integration=integration,
                )
            except http_proxy.IntegrationDataError:
                logger.warning(
                    "integration (id: %s, remote: %s) contains bad data",
                    integration.id,
                    integration.app.name,
                )
                integration_errors += 1
                continue
            reconciler.reconcile()
            proxy_requests.extend(reconciler.proxy_requests)
            proxy_users.update(reconciler.proxy_users)
            secret_ids.extend(reconciler.responses.get_juju_secrets())
            invalid_requests += reconciler.invalid_request_count
        squid.update_config_and_passwd(
            proxy_requests=proxy_requests, proxy_users=proxy_users, http_port=self._get_http_port()
        )
        status: type[ops.ActiveStatus] | type[ops.BlockedStatus] = ops.ActiveStatus
        status_message = f"ready: {len(proxy_requests)}"
        if invalid_requests:
            status_message += f", invalid: {invalid_requests}"
        if temporary_integration_errors:
            status_message += f", temporary integration errors: {temporary_integration_errors}"
        if integration_errors:
            status = ops.BlockedStatus
            status_message += f", integration errors: {integration_errors}"
        self.unit.status = status(status_message)
        self._set_peer_data(
            proxy_requests=proxy_requests,
            secret_ids=secret_ids,
            status=status.name,
            status_message=status_message,
        )

    def _set_peer_data(
        self,
        proxy_requests: list[http_proxy.HttpProxyRequest],
        secret_ids: list[str],
        status: str,
        status_message: str,
    ) -> None:
        """Set replica consensus data in the peer integrations.

        Args:
            proxy_requests: http proxy requests.
            secret_ids: juju secret ids
            status: unit status
            status_message: unit status message
        """
        integration = typing.cast(
            ops.Relation, self.model.get_relation(relation_name=PEER_INTEGRATION_NAME)
        )
        integration_data = integration.data[self.app]
        integration_data["proxy-requests"] = json.dumps(
            [r.model_dump(mode="json") for r in proxy_requests]
        )
        integration_data["secret-ids"] = json.dumps(secret_ids)
        integration_data["status"] = status
        integration_data["status-message"] = status_message

    def _reconcile_non_leader(self) -> None:
        """Run the main reconciliation loop for non-leader units."""
        integration = typing.cast(
            ops.Relation, self.model.get_relation(relation_name=PEER_INTEGRATION_NAME)
        )
        integration_data = integration.data[self.app]
        proxy_requests_data = integration_data.get("proxy-requests")
        if not proxy_requests_data:
            self.unit.status = ops.WaitingStatus("waiting for leader")
            return
        proxy_requests = [
            http_proxy.HttpProxyRequest(**data) for data in json.loads(proxy_requests_data)
        ]
        secret_ids = json.loads(integration_data["secret-ids"])
        proxy_users = {}
        for secret_id in secret_ids:
            try:
                proxy_user = self.model.get_secret(id=secret_id).get_content(refresh=True)
                proxy_users[proxy_user["username"]] = proxy_user["password"]
            except ops.SecretNotFoundError:
                pass
        status_name = integration_data["status"]
        status_message = integration_data["status-message"]
        squid.update_config_and_passwd(
            proxy_requests=proxy_requests, proxy_users=proxy_users, http_port=self._get_http_port()
        )
        status_mapping = {
            ops.BlockedStatus.name: ops.BlockedStatus,
            ops.ActiveStatus.name: ops.ActiveStatus,
            ops.MaintenanceStatus.name: ops.MaintenanceStatus,
            ops.WaitingStatus.name: ops.WaitingStatus,
        }
        self.unit.status = status_mapping[status_name](status_message)

    def _get_proxy_url(self, integration: ops.Relation) -> str | None:
        """Get the proxy url for the proxy requirer.

        Args:
            integration: the integration instance.

        Returns:
            The proxy url or None if the charm can't get the bind address for the integration at
            the moment.
        """
        hostname = self.config.get("hostname")
        if not hostname:
            network_binding = self.model.get_binding(integration)
            if (
                network_binding is not None
                and (bind_address := network_binding.network.bind_address) is not None
            ):
                hostname = str(bind_address)
            else:
                logger.error(
                    "failed to retrieve ip information from juju for integration"
                    " (id: %s, remote: %s)",
                    integration.id,
                    integration.app.name,
                )
                return None
        return f"http://{hostname}:{self._get_http_port()}"

    def _get_http_port(self) -> int:
        """Get http-port configuration.

        Returns:
            http-port configuration.
        """
        return typing.cast(int, self.config["http-port"])


class IntegrationReconciler:  # pylint: disable=too-few-public-methods
    """Integration reconciliation helper.

    Attributes:
        proxy_users: proxy authentication users needed
        proxy_requests: proxy requests collected
        invalid_request_count: number of invalid requests
        responses: integration response list
    """

    def __init__(
        self,
        charm: SquidProxyCharm,
        proxy_url: str,
        proxy_provider: http_proxy.HttpProxyPolyProvider,
        integration: ops.Relation,
    ) -> None:
        """Initialize the charm.

        Args:
            charm: the charm instance
            proxy_url: the proxy url
            proxy_provider: the proxy provider instance
            integration: the charm integration instance
        """
        self._charm = charm
        self._proxy_url = proxy_url
        self._requests = proxy_provider.open_request_list(integration.id)
        self.responses = proxy_provider.open_response_list(integration.id)
        self.proxy_users: dict[str, str] = {}
        self.proxy_requests: list[http_proxy.HttpProxyRequest] = []
        self.invalid_request_count = 0

    def reconcile(self) -> None:
        """Run the reconciliation loop on this integration."""
        self.proxy_users.clear()
        self.proxy_requests.clear()
        self.invalid_request_count = 0
        for requirer_id in self._requests.get_requirer_ids():
            self._reconcile_request_as_leader(requirer_id)

    def _reconcile_request_as_leader(self, requirer_id: str) -> None:
        """Reconcile one single http proxy request on the leader unit.

        Args:
            requirer_id: http proxy request requirer id
        """
        response = self.responses.get(requirer_id)
        try:
            request = self._requests.get(requirer_id)
        except ValueError:
            if response:
                self.responses.update(
                    requirer_id,
                    status=http_proxy.PROXY_STATUS_INVALID,
                    http_proxy=None,
                    https_proxy=None,
                    auth=None,
                    user=None,
                )
            else:
                self.responses.add(requirer_id, status=http_proxy.PROXY_STATUS_INVALID)
            self.invalid_request_count += 1
            return
        auth = request.auth[0]
        username = None
        password = None
        if http_proxy.AUTH_METHOD_USERPASS in auth:
            if response and response.user:
                username = response.user.username
                password = response.user.password.get_secret_value()
            else:
                username = squid.derive_proxy_username(request)
                password = self._generate_proxy_password()
            self.proxy_users[username] = password
        if response:
            self.responses.update(
                requirer_id,
                status=http_proxy.PROXY_STATUS_READY,
                auth=auth,
                http_proxy=self._proxy_url,
                https_proxy=self._proxy_url,
                user={"username": username, "password": password} if username else None,
            )
        else:
            self.responses.add(
                requirer_id,
                status=http_proxy.PROXY_STATUS_READY,
                auth=auth,
                http_proxy=self._proxy_url,
                https_proxy=self._proxy_url,
                user={"username": username, "password": password} if username else None,
            )
        self.proxy_requests.append(request)

    @staticmethod
    def _generate_proxy_password() -> str:
        """Generate a password that can be used for proxy authentication.

        Returns:
            A password string.
        """
        return secrets.token_urlsafe(128 // 8)  # 128 bits of entropy


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(SquidProxyCharm)
