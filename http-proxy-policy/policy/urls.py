# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from django.urls import path, register_converter

import policy.views as views
import policy.models as models


class RequestActionConverter:
    regex = "|".join(models.Verdict)

    def to_python(self, value):
        return models.Verdict[value.upper()]

    def to_url(self, value):
        return str(value)


register_converter(RequestActionConverter, "action")

urlpatterns = [
    path(
        "api/v1/requests/refresh",
        views.RefreshRequestsView.as_view(),
        name="api-refresh-requests",
    ),
    path(
        "api/v1/requests/<uuid:pk>/<action:action>",
        views.RequestActionView.as_view(),
        name="api-request-action",
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
    path("api/v1/rules/<int:pk>", views.RuleApiView.as_view(), name="api-rule"),
]
