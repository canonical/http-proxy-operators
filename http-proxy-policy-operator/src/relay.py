# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""HTTP proxy request relay."""

import dataclasses
import logging

import ops
from charms.squid_forward_proxy.v0 import http_proxy

import policy

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class HttpProxyPolicyStatistic:  # pylint: disable=too-many-instance-attributes
    """HTTP Proxy Policy charm statistic.

    Attributes:
        invalid_relations: invalid proxy request integrations
        invalid_requests: invalid proxy requests
        duplicated_requests: duplicated proxy requests
        accepted_requests: accepted proxy requests
        rejected_requests: rejected proxy requests
        pending_requests: pending proxy requests
        unsupported_requests: unsupported proxy requests
        invalid_backend_responses: invalid backend responses
        invalid_backend_relations: invalid backend relation
        missing_backend_relations: missing backend relation
    """

    invalid_relations: int = 0
    invalid_requests: int = 0
    duplicated_requests: int = 0
    accepted_requests: int = 0
    rejected_requests: int = 0
    pending_requests: int = 0
    unsupported_requests: int = 0
    invalid_backend_responses: int = 0
    invalid_backend_relations: int = 0
    missing_backend_relations: int = 0


class HttpProxyRequestRelay:  # pylint: disable=too-few-public-methods
    """HTTP proxy request relay."""

    def __init__(
        self,
        proxy_provider: http_proxy.HttpProxyPolyProvider,
        provider_relations: list[ops.Relation],
        proxy_backend: http_proxy.HttpProxyPolyRequirer,
        backend_relation: ops.Relation | None,
    ) -> None:
        """Initialize the HTTP proxy request relay.

        Args:
            proxy_provider: HTTP proxy provider.
            provider_relations: HTTP proxy provider relations.
            proxy_backend: HTTP proxy backend requirer.
            backend_relation: HTTP proxy backend relation.
        """
        self._proxy_provider = proxy_provider
        self._provider_relations = provider_relations
        self._backend_requirer = proxy_backend
        self._backend_relation = backend_relation
        self._statistic = HttpProxyPolicyStatistic()

    def relay(self, client: policy.HttpProxyPolicyClient) -> HttpProxyPolicyStatistic:
        """Relay HTTP proxy requests.

        Args:
            client: HTTP proxy policy client.

        Return:
            HTTP proxy policy statistic.
        """
        # this ensures that each new run of relay starts with fresh stats. This might
        # be required later, if relay is called multiple times during a charm invocation,
        # such as with deferred events, custom events etc.
        self._statistic = HttpProxyPolicyStatistic()
        collected_requests = self._collect_proxy_requests()
        evaluated_requests = self._evaluate_proxy_requests(
            proxy_requests=collected_requests, client=client
        )
        self._relay_requests(evaluated_requests)
        return self._statistic

    def _collect_proxy_requests(self) -> dict[str, http_proxy.HttpProxyRequest]:
        """Collect proxy requests from http_proxy relations.

        Returns:
            proxy requests from http_proxy relations.
        """
        collected: dict[str, http_proxy.HttpProxyRequest] = {}
        duplicated_requirers: set = set()

        for relation in self._provider_relations:
            proxy_responses = self._proxy_provider.open_response_list(relation.id)
            try:
                proxy_requests = self._proxy_provider.open_request_list(relation.id)
            except http_proxy.IntegrationDataError as e:
                logger.debug("invalid proxy relation, id: %s, reason: %s", relation.id, e)
                self._statistic.invalid_relations += 1
                continue
            for requirer in proxy_requests.get_requirer_ids():
                if requirer in collected or requirer in duplicated_requirers:
                    self._handle_duplicate_request(
                        relation.id, requirer, collected, duplicated_requirers
                    )
                    continue

                request = self._get_request(proxy_requests, relation.id, requirer, proxy_responses)
                if request is None:
                    continue

                if not self._is_supported_request(request, relation.id, requirer, proxy_responses):
                    continue

                collected[requirer] = request

        return collected

    def _handle_duplicate_request(
        self,
        relation_id: int,
        requirer: str,
        collected: dict[str, http_proxy.HttpProxyRequest],
        duplicated_requirers: set,
    ) -> None:
        """Handle duplicated proxy request.

        Args:
            relation_id: relation id.
            requirer: requirer id.
            collected: collected proxy requests.
            duplicated_requirers: set of already identified duplicated requirer ids.
        """
        logger.debug(
            "duplicated proxy request, relation id: %s, requirer id: %s", relation_id, requirer
        )
        self._statistic.duplicated_requests += 1

        proxy_responses = self._proxy_provider.open_response_list(relation_id)
        proxy_responses.add_or_replace(
            requirer,
            status=http_proxy.PROXY_STATUS_INVALID,
            http_proxy=None,
            https_proxy=None,
            auth=None,
            user=None,
        )

        if duplicated_request := collected.pop(requirer, None):
            logger.debug(
                "removed duplicated proxy request from collected list, "
                "relation id: %s, requirer id: %s",
                duplicated_request.group,
                duplicated_request.id,
            )

            self._statistic.duplicated_requests += 1
            dup_responses = self._proxy_provider.open_response_list(duplicated_request.group)
            # Note: If a requirer_id already exists in another relation and was
            # previously marked as ACCEPTED, it will now be reclassified as DUPLICATED
            # and set to INVALID. This ensures that no two relations can
            # simultaneously manage the same requirer_id.
            dup_responses.add_or_replace(
                requirer,
                status=http_proxy.PROXY_STATUS_INVALID,
                http_proxy=None,
                https_proxy=None,
                auth=None,
                user=None,
            )

        duplicated_requirers.add(requirer)

    def _get_request(
        self,
        proxy_requests: http_proxy._HttpProxyRequestListReader,
        relation_id: int,
        requirer: str,
        proxy_responses: http_proxy._HttpProxyResponseListReadWriter,
    ) -> http_proxy.HttpProxyRequest | None:
        """Get proxy request from the proxy requests list.

        Args:
            proxy_requests: proxy requests list.
            relation_id: relation id.
            requirer: requirer id.
            proxy_responses: proxy responses list.

        Returns:
            proxy request, or None if the request is invalid.
        """
        try:
            return proxy_requests.get(requirer)
        except ValueError:
            logger.debug(
                "invalid proxy request, relation id: %s, requirer id: %s", relation_id, requirer
            )
            self._statistic.invalid_requests += 1
            proxy_responses.add_or_replace(
                requirer,
                status=http_proxy.PROXY_STATUS_INVALID,
                http_proxy=None,
                https_proxy=None,
                auth=None,
                user=None,
            )
            return None

    def _is_supported_request(
        self,
        request: http_proxy.HttpProxyRequest,
        relation_id: int,
        requirer: str,
        proxy_responses: http_proxy._HttpProxyResponseListReadWriter,
    ) -> bool:
        """Check if the proxy request is supported.

        Args:
            request: proxy request.
            relation_id: relation id.
            requirer: requirer id.
            proxy_responses: proxy responses list.

        Returns:
            True if the request is supported.
        """
        if not request.domains or not request.auth:
            logger.debug(
                "unsupported proxy request, relation id: %s, requirer id: %s",
                relation_id,
                requirer,
            )
            self._statistic.unsupported_requests += 1
            proxy_responses.add_or_replace(
                requirer,
                status=http_proxy.PROXY_STATUS_UNSUPPORTED,
                http_proxy=None,
                https_proxy=None,
                auth=None,
                user=None,
            )
            return False

        unsupported_auth = [auth for auth in request.auth if auth not in http_proxy.AUTH_METHODS]
        if unsupported_auth:
            logger.debug(
                "unsupported authentication modes in proxy request, "
                "relation id: %s, requirer id: %s, unsupported auth methods: %s",
                relation_id,
                requirer,
                unsupported_auth,
            )
            self._statistic.unsupported_requests += 1
            proxy_responses.add_or_replace(
                requirer,
                status=http_proxy.PROXY_STATUS_UNSUPPORTED,
                http_proxy=None,
                https_proxy=None,
                auth=None,
                user=None,
            )
            return False

        return True

    def _evaluate_proxy_requests(
        self,
        proxy_requests: dict[str, tuple[int, http_proxy.HttpProxyRequest]],
        client: policy.HttpProxyPolicyClient,
    ) -> dict[str, policy.EvaluatedHttpProxyRequest]:
        """Submit the proxy requests to the HTTP proxy policy server.

        Args:
            proxy_requests: proxy requests from http_proxy relations.
            client: HTTP proxy policy client.

        Returns:
            evaluated proxy requests returned by the HTTP proxy policy server.
        """
        evaluated = client.refresh(list(proxy_requests.values()))
        result = {}
        for evaluated_request in evaluated:
            if evaluated_request.status == http_proxy.PROXY_STATUS_ACCEPTED:
                self._statistic.accepted_requests += 1
            if evaluated_request.status == http_proxy.PROXY_STATUS_REJECTED:
                self._statistic.rejected_requests += 1
            if evaluated_request.status == http_proxy.PROXY_STATUS_PENDING:
                self._statistic.pending_requests += 1
            result[str(evaluated_request.id)] = evaluated_request
        return result

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
                    logger.debug("invalid backend response, requirer id: %s", relation_request.id)
                    self._statistic.invalid_backend_responses += 1
            if backend_response is not None:
                proxy_responses.add_or_replace(
                    requirer_id=relation_request.id,
                    status=backend_response.status,
                    auth=backend_response.auth,
                    http_proxy=backend_response.http_proxy,
                    https_proxy=backend_response.https_proxy,
                    user=backend_response.user.dump(),
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

    def _get_backend_requests(self) -> http_proxy._HttpProxyRequestListReadWriter | None:
        """Open http proxy backend request list.

        Returns:
            http proxy backend request list, or None if backend not available.
        """
        relation = self._backend_relation
        if not relation:
            self._statistic.missing_backend_relations = 1
            return None
        return self._backend_requirer.open_request_list(relation.id)

    def _get_backend_responses(self) -> http_proxy._HttpProxyResponseListReader | None:
        """Open http proxy backend response list.

        Returns:
            http proxy backend response list, or None if backend not available.
        """
        relation = self._backend_relation
        if not relation:
            self._statistic.missing_backend_relations = 1
            return None
        try:
            return self._backend_requirer.open_response_list(relation.id)
        except http_proxy.IntegrationDataError:
            logger.exception("backend relation data error")
            self._statistic.invalid_backend_relations = 1
            return None
