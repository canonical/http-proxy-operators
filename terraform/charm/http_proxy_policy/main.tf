# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "http_proxy_policy" {
  name       = var.app_name
  model_uuid = var.model_uuid

  charm {
    name     = "http-proxy-policy"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  config      = var.config
  constraints = var.constraints
}
