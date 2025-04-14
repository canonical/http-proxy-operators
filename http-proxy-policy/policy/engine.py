# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import typing

import policy.models as models

__all__ = ["apply_rules"]


class _EvaluationResult(typing.NamedTuple):
    verdict: models.Verdict
    auth: str | None = None


def make_rule(request: models.Request, verdict: models.Verdict) -> models.Rule:
    """Create a rule based on a request and the verdict."""
    if verdict == models.Verdict.REJECT:
        return models.Rule(
            requirer=request.requirer,
            domains=[],
            auth=[],
            src_ips=[],
            verdict=verdict,
        )
    else:
        return models.Rule(
            requirer=request.requirer,
            domains=request.domains,
            auth=[] if request.implicit_src_ips else [request.auth[0]],
            src_ips=request.src_ips,
            verdict=verdict,
        )


def apply_rules(rules: list[models.Rule], request: models.Request) -> models.Request:
    """Apply rules to the request.

    The general rules:
        For a proxy request to be accepted:
            For any authentication method the requester supports, if every possible combination of
            the domain and source IP declared by the request is accepted by at least one of the
            accept rules, and none of the combinations is rejected by any rule, the request is
            accepted and this authentication method is selected.

        For a proxy request to be rejected:
            If, for an authentication method, any combination of the domain and source IP declared
            by the request is rejected by at least any of the reject rules, the authentication
            method is rejected. If every authentication method the requester supports is rejected,
            the request is rejected.

        If the request is neither accepted nor rejected, the request is in a pending state.
    """
    result = _evaluate_rules(rules, request)
    if not result:
        request.status = models.PROXY_STATUS_PENDING
        request.accepted_auth = None
    elif result.verdict == models.Verdict.ACCEPT:
        request.status = models.PROXY_STATUS_ACCEPTED
        request.accepted_auth = result.auth
    else:
        request.status = models.PROXY_STATUS_REJECTED
        request.accepted_auth = None
    return request


def _evaluate_rules(rules: list[models.Rule], request: models.Request) -> _EvaluationResult | None:
    rules = [r for r in rules if r.requirer is None or r.requirer == request.requirer]
    if not rules:
        return None
    deny_rules = [r for r in rules if r.verdict == models.Verdict.REJECT]
    accept_rules = [r for r in rules if r.verdict == models.Verdict.ACCEPT]
    denied_count = 0
    for auth in request.auth:
        if deny_rules and any(
            _match_deny_rules(
                deny_rules,
                domain=domain,
                auth=auth,
                src_ips=request.src_ips,
            )
            for domain in request.domains
        ):
            denied_count += 1
            continue
        if accept_rules and all(
            _match_accept_rules(
                accept_rules,
                domain=domain,
                auth=auth,
                src_ips=request.src_ips,
            )
            for domain in request.domains
        ):
            return _EvaluationResult(verdict=models.Verdict.ACCEPT, auth=auth)
    if denied_count == len(request.auth):
        return _EvaluationResult(verdict=models.Verdict.REJECT, auth=None)
    return None


def _match_deny_rules(
    rules: list[models.Rule], domain: str, auth: str, src_ips: models.IpSet
) -> bool:
    if not rules:
        return False
    for rule in rules:
        if rule.auth and auth not in rule.auth:
            continue
        if rule.domains and not any(
            _domain_match(domain, rule_domain) for rule_domain in rule.domains
        ):
            continue
        if rule.src_ips.is_empty() or rule.src_ips.overlap(src_ips):
            return True
    return False


def _match_accept_rules(
    rules: list[models.Rule], domain: str, auth: str, src_ips: models.IpSet
) -> bool:
    if not rules:
        return False
    rule_src_ips = models.IpSet([])
    for rule in rules:
        if rule.auth and auth not in rule.auth:
            continue
        if rule.domains and not any(
            _domain_match(domain, rule_domain) for rule_domain in rule.domains
        ):
            continue
        if rule.src_ips.is_empty():
            return True
        rule_src_ips += rule.src_ips
    return rule_src_ips.is_superset_of(src_ips)


def _domain_match(domain: str, rule_domain: str) -> bool:
    return domain == rule_domain or domain.endswith("." + rule_domain)
