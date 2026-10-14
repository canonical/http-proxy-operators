# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variables {
  app_name    = "http-proxy-policy"
  base        = "ubuntu@24.04"
  channel     = "latest/edge"
  config      = {}
  constraints = "arch=amd64"
  model_uuid  = "00000000-0000-0000-0000-000000000001"
  revision    = 51
}

mock_provider "juju" {
  mock_resource "juju_application" {
    override_during = plan
    defaults = {
      id         = "http-proxy-policy"
      model_type = "iaas"
    }
  }
}

run "deploys_application" {
  command = plan

  assert {
    condition     = output.application.name == "http-proxy-policy" && output.application.model_uuid == "00000000-0000-0000-0000-000000000001" && output.application.charm[0].name == "http-proxy-policy" && output.application.charm[0].channel == "latest/edge" && output.application.charm[0].base == "ubuntu@24.04" && output.application.charm[0].revision == 51
    error_message = "application identity did not match the expected deployment"
  }

  assert {
    condition = output.provides == {
      http_proxy = {
        kind     = "endpoint"
        name     = "http-proxy-policy"
        endpoint = "http-proxy"
      }
    }
    error_message = "provides outputs did not match expected structure"
  }

  assert {
    condition = output.requires == {
      http_proxy_backend = {
        kind     = "endpoint"
        name     = "http-proxy-policy"
        endpoint = "http-proxy-backend"
      }
      juju_info = {
        kind     = "endpoint"
        name     = "http-proxy-policy"
        endpoint = "juju-info"
      }
      postgresql = {
        kind     = "endpoint"
        name     = "http-proxy-policy"
        endpoint = "postgresql"
      }
    }
    error_message = "requires outputs did not match expected structure"
  }
}
