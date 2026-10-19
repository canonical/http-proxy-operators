# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed application object."
  value       = juju_application.http_proxy_configurator
}

output "provides" {
  description = "Map of the provided integration endpoints."
  value = {
    delegate_http_proxy = {
      kind     = "endpoint"
      name     = juju_application.http_proxy_configurator.name
      endpoint = "delegate-http-proxy"
    }
  }
}

output "requires" {
  description = "Map of the required integration endpoints."
  value = {
    http_proxy = {
      kind     = "endpoint"
      name     = juju_application.http_proxy_configurator.name
      endpoint = "http-proxy"
    }
  }
}
