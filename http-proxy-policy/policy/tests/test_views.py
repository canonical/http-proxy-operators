# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from django.urls import reverse

import policy.models as models


class ModelsTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("admin", "admin@example.com", "admin")
        self.client = APIClient()

    def login(self):
        self.client.login(username="admin", password="admin")

    def generate_example_proxy_requests(self):
        return [
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com"],
                "auth": ["none"],
                "src_ips": ["10.0.0.1"],
                "implicit_src_ips": False,
            },
            {
                "requirer": "00000000-0000-4000-9000-000000000000",
                "domains": ["ubuntu.com"],
                "auth": ["srcip+userpass", "srcip", "userpass", "none"],
                "src_ips": ["192.168.0.1", "192.168.0.2"],
                "implicit_src_ips": True,
            },
            {
                "requirer": "00000000-0000-4000-a000-000000000000",
                "domains": ["github.com"],
                "auth": ["userpass", "none"],
                "src_ips": ["172.16.0.1", "172.16.0.2"],
                "implicit_src_ips": True,
            },
        ]

    def test_requests_refresh_empty(self):
        self.login()
        response = self.client.post(
            reverse("api-refresh-requests"), data=[], format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertSequenceEqual(response.json(), [])

    def create_rule(
        self,
        verdict: models.Verdict,
        domains: list[str] | None = None,
        auth: list[str] | None = None,
        src_ips: list[str] | None = None,
    ):
        payload = {"verdict": verdict}
        if domains is not None:
            payload["domains"] = domains
        if auth is not None:
            payload["auth"] = auth
        if src_ips is not None:
            payload["src_ips"] = src_ips
        response = self.client.put(
            reverse("api-rules"),
            data=payload,
            format="json",
        )
        self.assertEqual(response.status_code, 200)

    def refresh_requests(self, requests):
        response = self.client.post(
            reverse("api-refresh-requests"),
            data=requests,
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_request_refresh(self):
        self.login()
        response = self.client.post(
            reverse("api-refresh-requests"),
            data=self.generate_example_proxy_requests(),
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertSequenceEqual(
            response.json(),
            [
                {
                    "requirer": "00000000-0000-4000-8000-000000000000",
                    "domains": ["example.com:80", "example.com:443"],
                    "auth": [models.AUTH_METHOD_NONE],
                    "src_ips": ["10.0.0.1"],
                    "implicit_src_ips": False,
                    "status": "pending",
                    "accepted_auth": None,
                },
                {
                    "requirer": "00000000-0000-4000-9000-000000000000",
                    "domains": ["ubuntu.com:80", "ubuntu.com:443"],
                    "auth": [
                        models.AUTH_METHOD_SRCIP_USERPASS,
                        models.AUTH_METHOD_USERPASS,
                        models.AUTH_METHOD_SRCIP,
                        models.AUTH_METHOD_NONE,
                    ],
                    "src_ips": ["192.168.0.1", "192.168.0.2"],
                    "implicit_src_ips": True,
                    "status": "pending",
                    "accepted_auth": None,
                },
                {
                    "requirer": "00000000-0000-4000-a000-000000000000",
                    "domains": ["github.com:80", "github.com:443"],
                    "auth": [
                        models.AUTH_METHOD_USERPASS,
                        models.AUTH_METHOD_NONE,
                    ],
                    "src_ips": ["172.16.0.1", "172.16.0.2"],
                    "implicit_src_ips": True,
                    "status": "pending",
                    "accepted_auth": None,
                },
            ],
        )

    def test_request_refresh_with_rule(self):
        self.login()

        self.create_rule(verdict=models.Verdict.ACCEPT, domains=["ubuntu.com"])

        response = self.client.post(
            reverse("api-refresh-requests"),
            data=self.generate_example_proxy_requests(),
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        response_map = {i["requirer"]: i for i in response.json()}
        self.assertDictEqual(
            {k: v["status"] for k, v in response_map.items()},
            {
                "00000000-0000-4000-8000-000000000000": models.PROXY_STATUS_PENDING,
                "00000000-0000-4000-9000-000000000000": models.PROXY_STATUS_ACCEPTED,
                "00000000-0000-4000-a000-000000000000": models.PROXY_STATUS_PENDING,
            },
        )
        self.assertDictEqual(
            {k: v["accepted_auth"] for k, v in response_map.items()},
            {
                "00000000-0000-4000-8000-000000000000": None,
                "00000000-0000-4000-9000-000000000000": models.AUTH_METHOD_SRCIP_USERPASS,
                "00000000-0000-4000-a000-000000000000": None,
            },
        )

    def test_accept_reject_request(self):
        self.login()
        response = self.client.post(
            reverse("api-refresh-requests"),
            data=self.generate_example_proxy_requests(),
            format="json",
        )
        self.assertEqual(response.status_code, 200)

        uuid = "00000000-0000-4000-8000-000000000000"

        response = self.client.post(reverse("api-request-action", args=(uuid, "accept")))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse("api-get-request", args=(uuid,)))
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(
            response.json(),
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["example.com:80", "example.com:443"],
                "auth": [models.AUTH_METHOD_NONE],
                "src_ips": ["10.0.0.1"],
                "implicit_src_ips": False,
                "status": models.PROXY_STATUS_ACCEPTED,
                "accepted_auth": models.AUTH_METHOD_NONE,
            },
        )

        response = self.client.post(reverse("api-request-action", args=(uuid, models.Verdict.REJECT)))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse("api-get-request", args=(uuid,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], models.PROXY_STATUS_REJECTED)

    def test_create_list_rules(self):
        self.login()
        self.create_rule(verdict=models.Verdict.ACCEPT, domains=["github.com"])
        self.create_rule(
            verdict=models.Verdict.ACCEPT,
            domains=["ubuntu.com", "ubuntu.com:22"],
            auth=[models.AUTH_METHOD_USERPASS],
        )
        self.create_rule(
            verdict=models.Verdict.ACCEPT,
            domains=["example.com"],
            auth=[models.AUTH_METHOD_USERPASS],
            src_ips=["172.16.0.1", "172.16.0.2"],
        )

        response = self.client.get(reverse("api-rules"))
        self.assertSequenceEqual(
            response.json(),
            [
                {
                    "auth": [],
                    "comment": "",
                    "domains": ["github.com:80", "github.com:443"],
                    "id": 1,
                    "requirer": None,
                    "src_ips": [],
                    "verdict": "accept",
                },
                {
                    "auth": ["userpass"],
                    "comment": "",
                    "domains": ["ubuntu.com:22", "ubuntu.com:80", "ubuntu.com:443"],
                    "id": 2,
                    "requirer": None,
                    "src_ips": [],
                    "verdict": "accept",
                },
                {
                    "auth": ["userpass"],
                    "comment": "",
                    "domains": ["example.com:80", "example.com:443"],
                    "id": 3,
                    "requirer": None,
                    "src_ips": ["172.16.0.1", "172.16.0.2"],
                    "verdict": "accept",
                },
            ],
        )

    def test_rule_match_subdomain(self):
        self.login()
        self.create_rule(verdict=models.Verdict.ACCEPT, domains=["api.github.com"])

        result = self.refresh_requests(
            [
                {
                    "requirer": "00000000-0000-4000-8000-000000000000",
                    "domains": ["test.api.github.com"],
                    "auth": [models.AUTH_METHOD_NONE],
                    "src_ips": ["10.0.0.1"],
                    "implicit_src_ips": False,
                },
            ]
        )
        self.assertSequenceEqual(
            result,
            [
                {
                    "requirer": "00000000-0000-4000-8000-000000000000",
                    "domains": ["test.api.github.com:80", "test.api.github.com:443"],
                    "auth": [models.AUTH_METHOD_NONE],
                    "src_ips": ["10.0.0.1"],
                    "implicit_src_ips": False,
                    "status": models.PROXY_STATUS_ACCEPTED,
                    "accepted_auth": models.AUTH_METHOD_NONE,
                }
            ],
        )

        result = self.refresh_requests(
            [
                {
                    "requirer": "00000000-0000-4000-8000-000000000000",
                    "domains": ["github.com"],
                    "auth": [models.AUTH_METHOD_NONE],
                    "src_ips": ["10.0.0.1"],
                    "implicit_src_ips": False,
                },
            ]
        )
        self.assertSequenceEqual(
            result,
            [
                {
                    "requirer": "00000000-0000-4000-8000-000000000000",
                    "domains": ["github.com:80", "github.com:443"],
                    "auth": [models.AUTH_METHOD_NONE],
                    "src_ips": ["10.0.0.1"],
                    "implicit_src_ips": False,
                    "status": models.PROXY_STATUS_PENDING,
                    "accepted_auth": None,
                }
            ],
        )

    def test_multiple_rules_accept_request(self):
        self.login()
        self.create_rule(
            verdict=models.Verdict.ACCEPT,
            domains=["github.com"],
            src_ips=["10.0.0.0/8"],
        )
        requests = [
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["github.com", "example.com"],
                "auth": [models.AUTH_METHOD_NONE],
                "src_ips": ["10.0.0.1", "192.168.1.1"],
                "implicit_src_ips": False,
            },
        ]
        result = self.refresh_requests(requests=requests)
        self.assertEqual(result[0]["status"], models.PROXY_STATUS_PENDING)

        self.create_rule(
            verdict=models.Verdict.ACCEPT,
            domains=["github.com"],
            src_ips=["192.168.0.0/16"],
        )

        result = self.refresh_requests(requests=requests)
        self.assertEqual(result[0]["status"], models.PROXY_STATUS_PENDING)

        self.create_rule(
            verdict=models.Verdict.ACCEPT,
            domains=["example.com"],
            src_ips=["10.0.0.0/8", "192.168.0.0/16"],
        )

        result = self.refresh_requests(requests=requests)
        self.assertEqual(result[0]["status"], models.PROXY_STATUS_ACCEPTED)

    def test_partial_match_reject(self):
        self.login()
        self.create_rule(
            verdict=models.Verdict.REJECT,
            domains=["github.com"],
            src_ips=["10.0.0.0/8"],
        )
        result = self.refresh_requests([
            {
                "requirer": "00000000-0000-4000-8000-000000000000",
                "domains": ["github.com", "example.com"],
                "auth": [models.AUTH_METHOD_NONE],
                "src_ips": ["10.0.0.1", "192.168.1.1"],
                "implicit_src_ips": False,
            },
        ])
        self.assertEqual(result[0]["status"], models.PROXY_STATUS_REJECTED)
