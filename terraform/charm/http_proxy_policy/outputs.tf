# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed application object."
  value       = juju_application.http_proxy_policy
}

output "provides" {
  description = "Map of the provided integration endpoints."
  value = {
    http_proxy = {
      kind     = "endpoint"
      name     = juju_application.http_proxy_policy.name
      endpoint = "http-proxy"
    }
  }
}

output "requires" {
  description = "Map of the required integration endpoints."
  value = {
    http_proxy_backend = {
      kind     = "endpoint"
      name     = juju_application.http_proxy_policy.name
      endpoint = "http-proxy-backend"
    }
    juju_info = {
      kind     = "endpoint"
      name     = juju_application.http_proxy_policy.name
      endpoint = "juju-info"
    }
    postgresql = {
      kind     = "endpoint"
      name     = juju_application.http_proxy_policy.name
      endpoint = "postgresql"
    }
  }
}
