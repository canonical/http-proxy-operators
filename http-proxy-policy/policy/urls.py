# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from django.urls import path

import policy.views as views

urlpatterns = [
    path(
        "api/v1/requests/refresh",
        views.RefreshRequestsView.as_view(),
        name="api-refresh-requests",
    ),
    path(
        "api/v1/requests/<uuid:pk>/accept",
        views.AcceptRequestsView.as_view(),
        name="api-accept-request",
    ),
    path(
        "api/v1/requests/<uuid:pk>/reject",
        views.RejectRequestsView.as_view(),
        name="api-reject-request",
    ),
    path(
        "api/v1/requests/<uuid:pk>",
        views.GetRequestsView.as_view(),
        name="api-get-request",
    ),
    path(
        "api/v1/requests",
        views.ListRequestsView.as_view(),
        name="api-get-requests",
    ),
    path(
        "api/v1/rules",
        views.ListCreateRulesView.as_view(),
        name="api-rules",
    ),
    path(
        "api/v1/rules/<int:pk>",
        views.RuleApiView.as_view(),
        name="api-rule"
    ),
]
