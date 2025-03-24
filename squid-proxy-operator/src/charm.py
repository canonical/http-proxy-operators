#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the service."""

import logging
import secrets
import typing
import uuid

import ops

import http_proxy
from squid import Squid

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
        self._squid = Squid()
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
            self.on[HTTP_PROXY_INTEGRATION_NAME].relation_broken, self._reconcile
        )
        self.framework.observe(self.on[PEER_INTEGRATION_NAME].relation_changed, self._reconcile)
        self.framework.observe(self.on[PEER_INTEGRATION_NAME].relation_joined, self._reconcile)
        self.framework.observe(self.on.update_status, self._reconcile)

    def _install(self, _: ops.EventBase) -> None:
        """Install Squid."""
        self.unit.status = ops.ActiveStatus("installing squid")
        self._squid.install()
        self.unit.status = ops.ActiveStatus()

    def _reconcile(self, _: ops.EventBase) -> None:
        """Run the main reconciliation loop."""
        temporary_integration_errors = 0
        integration_errors = 0
        invalid_requests = 0
        proxy_requests: list[http_proxy.HttpProxyRequest] = []
        proxy_users: dict[str, str] = {}
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
            except http_proxy.BadIntegrationError:
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
            invalid_requests += reconciler.invalid_request_count
        self._update_config_passwd(proxy_requests, proxy_users)
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

    def _update_config_passwd(
        self, proxy_requests: list[http_proxy.HttpProxyRequest], proxy_users: dict[str, str]
    ) -> None:
        """Update Squid configuration and passwd file.

        Args:
            proxy_requests: list of http proxy requests
            proxy_users: required http proxy users
        """
        old_config = self._squid.read_config()
        old_passwd = self._squid.read_passwd()
        new_config = self._squid.generate_config(
            specs=proxy_requests,
            http_port=self.config["http-port"],
        )
        new_passwd = self._squid.generate_passwd(proxy_users)
        if old_config != new_config or old_passwd != new_passwd:
            logger.info("squid configuration changed, reloading")
            if old_config != new_config:
                self._squid.write_config(new_config)
            if old_passwd != new_passwd:
                self._squid.write_passwd(new_passwd)
            self._squid.reload()
            if self.unit.is_leader():
                peer_integration = self.model.get_relation("squid-peer")
                if peer_integration:
                    # notify other non-leader units
                    peer_integration.data[self.app]["refresh"] = str(uuid.uuid4())

    def _get_proxy_url(self, integration: ops.Relation) -> str | None:
        """Get the proxy url for the proxy requirer.

        Args:
            integration: the integration instance.

        Returns:
            The proxy url or None if the charm can't get the bind address for the integration at
            the moment.
        """
        network_binding = self.model.get_binding(integration)

        hostname = self.config.get("hostname")
        if not hostname:
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
        return f"http://{hostname}:{self.config['http-port']}"


class IntegrationReconciler:  # pylint: disable=too-few-public-methods
    """Integration reconciliation helper.

    Attributes:
        proxy_users: proxy authentication users needed
        proxy_requests: proxy requests collected
        invalid_request_count: number of invalid requests
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
        self._responses = proxy_provider.open_response_list(integration.id)
        self.proxy_users: dict[str, str] = {}
        self.proxy_requests: list[http_proxy.HttpProxyRequest] = []
        self.invalid_request_count = 0

    def reconcile(self) -> None:
        """Run the reconciliation loop on this integration."""
        self.proxy_users.clear()
        self.proxy_requests.clear()
        self.invalid_request_count = 0
        if self._charm.unit.is_leader():
            self._reconcile_as_leader()
        else:
            self._reconcile_as_non_leader()

    def _reconcile_request_as_leader(self, requirer_id: str) -> None:
        """Reconcile one single http proxy request on the leader unit.

        Args:
            requirer_id: http proxy request requirer id
        """
        response = self._responses.get(requirer_id)
        try:
            request = self._requests.get(requirer_id)
        except ValueError:
            if response:
                self._responses.update(
                    requirer_id,
                    status=http_proxy.PROXY_STATUS_INVALID,
                    http_proxy=None,
                    https_proxy=None,
                    auth=None,
                    user=None,
                )
            else:
                self._responses.add(requirer_id, status=http_proxy.PROXY_STATUS_INVALID)
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
                username = Squid.derive_proxy_username(request)
                password = self._generate_proxy_password()
            self.proxy_users[username] = password
        if response:
            self._responses.update(
                requirer_id,
                status=http_proxy.PROXY_STATUS_READY,
                auth=auth,
                http_proxy=self._proxy_url,
                https_proxy=self._proxy_url,
                user={"username": username, "password": password} if username else None,
            )
        else:
            self._responses.add(
                requirer_id,
                status=http_proxy.PROXY_STATUS_READY,
                auth=auth,
                http_proxy=self._proxy_url,
                https_proxy=self._proxy_url,
                user={"username": username, "password": password} if username else None,
            )
        self.proxy_requests.append(request)

    def _reconcile_as_leader(self) -> None:
        """Reconcile the integration on the leader unit."""
        for requirer_id in self._requests.get_requirer_ids():
            self._reconcile_request_as_leader(requirer_id)

    def _reconcile_as_non_leader(self) -> None:
        """Reconcile the integration on the non-leader unit."""
        for requirer_id in self._responses.get_requirer_ids():
            response = self._responses.get(requirer_id)
            if not response.status == http_proxy.PROXY_STATUS_READY:
                if response.status == http_proxy.PROXY_STATUS_INVALID:
                    self.invalid_request_count += 1
                continue
            try:
                request = self._requests.get(requirer_id)
            except ValueError:
                self.invalid_request_count += 1
                continue
            self.proxy_requests.append(request)
            if response.user:
                self.proxy_users[response.user.username] = (
                    response.user.password.get_secret_value()
                )

    @staticmethod
    def _generate_proxy_password() -> str:
        """Generate a password that can be used for proxy authentication.

        Returns:
            A password string.
        """
        return secrets.token_urlsafe(128 // 8)


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(SquidProxyCharm)
