# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed application object."
  value       = juju_application.squid_forward_proxy
}

output "provides" {
  description = "Map of the provided integration endpoints."
  value = {
    cos_agent = {
      kind     = "endpoint"
      name     = juju_application.squid_forward_proxy.name
      endpoint = "cos-agent"
    }
    http_proxy = {
      kind     = "endpoint"
      name     = juju_application.squid_forward_proxy.name
      endpoint = "http-proxy"
    }
  }
}

output "requires" {
  description = "Map of the required integration endpoints."
  value       = {}
}
