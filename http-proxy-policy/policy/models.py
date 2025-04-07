# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import collections
import enum
import ipaddress
import itertools
import re
import uuid
from typing import Optional, Sequence, Annotated

from django.db import models
from pydantic import BaseModel, BeforeValidator, model_validator

AUTH_METHOD_SRCIP_USERPASS = "srcip+userpass"
AUTH_METHOD_USERPASS = "userpass"
AUTH_METHOD_SRCIP = "srcip"
AUTH_METHOD_NONE = "none"
AUTH_METHODS = [
    AUTH_METHOD_SRCIP_USERPASS,
    AUTH_METHOD_USERPASS,
    AUTH_METHOD_SRCIP,
    AUTH_METHOD_NONE,
]
PROXY_STATUS_PENDING = "pending"
PROXY_STATUS_ACCEPTED = "accepted"
PROXY_STATUS_REJECTED = "rejected"
PROXY_STATUS_INVALID = "invalid"
PROXY_STATUS_ERROR = "error"
PROXY_STATUS_READY = "ready"
PROXY_STATUSES = [
    PROXY_STATUS_PENDING,
    PROXY_STATUS_ACCEPTED,
    PROXY_STATUS_REJECTED,
    PROXY_STATUS_INVALID,
    PROXY_STATUS_ERROR,
    PROXY_STATUS_READY,
]


class Verdict(enum.StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


class RangeSet:
    """A set of integers represented by integer ranges.

    Integer ranges are represented by tuples (a, b), which denote integers i such that a <= i < b.
    """
    def __init__(self, ranges: list[tuple[int, int]]):
        self._ranges = self._merge(ranges)

    def _merge(self, ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
        ranges = sorted(r for r in ranges if r[0] < r[1])
        merged = []
        for segment in ranges:
            if not merged or merged[-1][1] < segment[0]:
                merged.append(segment)
            else:
                last = merged[-1]
                merged[-1] = (last[0], max(merged[-1][1], segment[1]))
        return merged

    def overlap(self, other: "RangeSet") -> bool:
        """Check if this range set overlaps with another range set."""
        if not self._ranges and not other._ranges:
            return False
        return any(
            self._range_overlap(left, right)
            for left, right in itertools.product(self._ranges, other._ranges)
        )

    def is_superset_of(self, other: "RangeSet") -> bool:
        """Check if this range set is a superset of or equal to the other range set."""
        if not self._ranges:
            return not other._ranges
        for right in other._ranges:
            if not any(self._range_superset(left, right) for left in self._ranges):
                return False
        return True

    def _range_overlap(self, left: tuple[int, int], right: tuple[int, int]) -> bool:
        """Check if left overlaps with right."""
        return left[1] > right[0] and left[0] < right[1]

    def _range_superset(self, left: tuple[int, int], right: tuple[int, int]) -> bool:
        """Check if left is a superset of right."""
        return left[0] <= right[0] < left[1] and right[1] <= left[1]

    def __add__(self, other: "RangeSet") -> "RangeSet":
        return RangeSet(self._ranges + other._ranges)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self._ranges)})"


class IpSet:
    def __init__(self, ips: list[str]):
        self.source = ips
        self._ipv6 = None
        self._ipv4 = None

    @property
    def ipv6(self) -> RangeSet:
        if self._ipv6 is None:
            self._ipv6 = self._build_ip_range_set([ip for ip in self.source if ":" in ip], 6)
        return self._ipv6

    @property
    def ipv4(self) -> RangeSet:
        if self._ipv4 is None:
            self._ipv4 = self._build_ip_range_set([ip for ip in self.source if "." in ip], 4)
        return self._ipv4

    def _build_ip_range_set(self, ips: list[str], version: int) -> RangeSet:
        ranges = []
        for ip in ips:
            ipnet = ipaddress.ip_network(ip, strict=False)
            begin = int(ipnet.network_address)
            end = begin + (1 << ((32 if version == 4 else 128) - ipnet.prefixlen))
            ranges.append((begin, end))
        return RangeSet(ranges)

    def is_superset_of(self, other: "IpSet") -> bool:
        """Check if this IP set is a superset of the other IP set."""
        return self.ipv4.is_superset_of(other.ipv4) and self.ipv6.is_superset_of(other.ipv6)

    def overlap(self, other: "IpSet") -> bool:
        """Check if this IP set overlaps with another IP set."""
        return self.ipv4.overlap(other.ipv4) or self.ipv6.overlap(other.ipv6)

    def __add__(self, other: "IpSet") -> "IpSet":
        """Add combine two IP sets to a new IP set."""
        ipset = IpSet([])
        ipset.source = self.source + other.source
        ipset._ipv4 = self.ipv4 + other.ipv4
        ipset._ipv6 = self.ipv6 + other.ipv6
        return ipset

    def is_empty(self) -> bool:
        return not self.source

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.source)})"


class IpSetField(models.JSONField):
    def from_db_value(self, value, expression, connection):
        db_val = super().from_db_value(value, expression, connection)

        if db_val is None:
            return db_val

        return IpSet(db_val)

    def get_prep_value(self, value):
        if isinstance(value, IpSet):
            prep_value = super().get_prep_value(value.source)
        else:
            prep_value = value
        return prep_value


def dedup(input_list: list[str]) -> list[str]:
    """Deduplicate a list without changing the order.

    Args:
        input_list: The input list.

    Returns:
        The deduplicated list.
    """
    seen = set()
    result = []
    for i in input_list:
        if i in seen:
            continue
        seen.add(i)
        result.append(i)
    return result


def parse_domain(domain: str) -> tuple[str, int]:
    """Parse a domain string in the form of host[:port].

    Args:
        domain: The domain string.

    Returns:
        A (host, port) tuple. Port is 0 if not specified.

    Raises:
        ValueError: If the domain string is invalid.
    """
    host: str
    port: int | str
    # ipv6 (the correct way), i.e. "[::1]:8080" or "[::1]"
    if domain.startswith("["):
        if "]:" in domain:
            host, port = domain.rsplit("]:", maxsplit=1)
            host = host.removeprefix("[")
        else:
            host = domain.removeprefix("[").removesuffix("]")
            port = 0
        ipaddress.ip_network(host, strict=False)
        host = f"[{host}]"
    # ipv6 (the "incorrect" way), i.e. "fe80::1", "::1"
    elif domain.count(":") >= 2:
        ipaddress.ip_network(domain, strict=False)
        host, port = f"[{domain}]", 0
    # ipv4
    elif re.match("^[0-9.:]+$", domain):
        if ":" in domain:
            host, port = domain.rsplit(":", 1)
        else:
            host, port = domain, 0
        ipaddress.ip_address(host)
    # DNS domain
    else:
        match = re.match(
            r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
            r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])"
            r"(:[0-9]+)?$",
            domain,
        )
        if not match:
            raise ValueError(f"invalid domain: {domain}")
        if ":" in domain:
            host, port = domain.rsplit(":", 1)
        else:
            host, port = domain, 0
    return host, int(port)


def _validate_and_transform_domains(domains: Sequence[str]) -> tuple[str, ...]:
    """Validate and transform the domains input.

    Args:
        domains: The input domains.

    Returns:
        The canonical representation of the domains.
    """
    if not domains:
        raise ValueError("no domains specified")
    valid_domains = []
    invalid_domains = []
    for domain in domains:
        try:
            host, port = parse_domain(domain)
            if not 0 <= port <= 65535:
                raise ValueError(f"invalid port: {port}")
            if port != 0:
                valid_domains.append(f"{host}:{port}")
            else:
                valid_domains.append(f"{host}:80")
                valid_domains.append(f"{host}:443")
        except ValueError:
            invalid_domains.append(domain)
    if invalid_domains:
        raise ValueError(f"invalid domains: {invalid_domains}")
    return tuple(dedup(sorted(valid_domains, key=parse_domain)))


def _validate_and_transform_auth(auth: Sequence[str]) -> tuple[str, ...]:
    """Validate and transform the auth input.

    Args:
        auth: The input auth.

    Returns:
        The canonical representation of the auth.
    """
    if not auth:
        raise ValueError("no auth method specified")
    invalid_auth = [a for a in auth if a not in AUTH_METHODS]
    if invalid_auth:
        raise ValueError(f"invalid auth type: {invalid_auth}")
    sorted_auth = dedup(sorted(auth, key=AUTH_METHODS.index))
    return tuple(sorted_auth)


def _validate_and_sort_src_ip(src_ips: Sequence[str]) -> tuple[str, ...]:
    """Validate and transform the src_ips input.

    Args:
        src_ips: The input auth.

    Returns:
        The canonical representation of the src_ips.
    """
    if src_ips is None:
        return tuple()
    validated_ips = []
    invalid_ips = []
    for ip in src_ips:
        try:
            ipaddress.ip_network(ip, strict=False)
            validated_ips.append(ip)
        except ValueError:
            invalid_ips.append(ip)
    if invalid_ips:
        raise ValueError(f"invalid src_ips: {invalid_ips}")
    return tuple(dedup(sorted(validated_ips)))


def compact_domains(domains: Sequence[str]) -> list[str]:
    host_port = collections.defaultdict(list)
    for domains in domains:
        host, port = parse_domain(domains)
        host_port[host].append(port)
    result = []
    for host, ports in host_port.items():
        if 80 in ports and 443 in ports:
            result.append(host)
            ports.remove(80)
            ports.remove(443)
        for port in ports:
            result.append(f"{host}:{port}")
    return result


class RuleInput(BaseModel):
    requirer: Optional[uuid.UUID] = None
    domains: Annotated[
        tuple[str, ...],
        BeforeValidator(
            lambda domains: (_validate_and_transform_domains(domains=domains) if domains else ())
        ),
    ] = ()
    auth: Annotated[
        tuple[str, ...],
        BeforeValidator(lambda auth: _validate_and_transform_auth(auth=auth) if auth else ()),
    ] = ()
    src_ips: Annotated[
        tuple[str, ...],
        BeforeValidator(_validate_and_sort_src_ip),
    ] = ()
    verdict: Verdict
    comment: str = ""


class Rule(models.Model):
    id = models.BigAutoField(primary_key=True)
    requirer = models.UUIDField(db_index=True, null=True)
    domains = models.JSONField(default=list)
    auth = models.JSONField(default=list)
    src_ips = IpSetField(default=list)
    verdict = models.TextField(
        choices={
            Verdict.ACCEPT: Verdict.ACCEPT,
            Verdict.REJECT: Verdict.REJECT,
        }
    )
    comment = models.TextField(default="")

    def to_jsonable(self) -> dict:
        return {
            "id": self.id,
            "requirer": str(self.requirer),
            "domains": self.domains,
            "auth": self.auth,
            "src_ips": self.src_ips.source,
            "verdict": str(self.verdict),
            "comment": self.comment,
        }


class RequestInput(BaseModel):
    requirer: uuid.UUID
    domains: Annotated[tuple[str, ...], BeforeValidator(_validate_and_transform_domains)]
    auth: Annotated[tuple[str, ...], BeforeValidator(_validate_and_transform_auth)]
    src_ips: Annotated[tuple[str, ...], BeforeValidator(_validate_and_sort_src_ip)]
    implicit_src_ips: bool

    @model_validator(mode="after")
    def _validate(self) -> "RequestInput":
        """Validate the object as a whole.

        Returns:
            The validated object.
        """
        if (
            any(auth in (AUTH_METHOD_SRCIP, AUTH_METHOD_SRCIP_USERPASS) for auth in self.auth)
            and not self.src_ips
        ):
            raise ValueError("no src_ips specified for srcip authentication")
        return self


class Request(models.Model):
    requirer = models.UUIDField(primary_key=True)
    domains = models.JSONField()
    auth = models.JSONField()
    src_ips = IpSetField()
    implicit_src_ips = models.BooleanField()
    status = models.TextField(
        choices={
            PROXY_STATUS_ACCEPTED: PROXY_STATUS_ACCEPTED,
            PROXY_STATUS_REJECTED: PROXY_STATUS_REJECTED,
            PROXY_STATUS_PENDING: PROXY_STATUS_PENDING,
        },
        db_index=True,
    )
    accepted_auth = models.TextField(null=True)

    def to_jsonable(self) -> dict:
        return {
            "requirer": str(self.requirer),
            "domains": self.domains,
            "auth": self.auth,
            "src_ips": self.src_ips.source,
            "implicit_src_ips": self.implicit_src_ips,
            "status": self.status,
            "accepted_auth": self.accepted_auth,
        }
