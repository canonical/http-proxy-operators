# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variables {
  app_name    = "squid-forward-proxy"
  base        = "ubuntu@24.04"
  channel     = "latest/edge"
  config      = {}
  constraints = "arch=amd64"
  model_uuid  = "00000000-0000-0000-0000-000000000001"
  revision    = 40
  units       = 1
}

mock_provider "juju" {
  mock_resource "juju_application" {
    override_during = plan
    defaults = {
      id         = "squid-forward-proxy"
      model_type = "iaas"
    }
  }
}

run "deploys_application" {
  command = plan

  assert {
    condition     = output.application.name == "squid-forward-proxy" && output.application.model_uuid == "00000000-0000-0000-0000-000000000001" && output.application.charm[0].name == "squid-forward-proxy" && output.application.charm[0].channel == "latest/edge" && output.application.charm[0].base == "ubuntu@24.04" && output.application.charm[0].revision == 40
    error_message = "application identity did not match the expected deployment"
  }

  assert {
    condition     = output.application.units == 1
    error_message = "application units did not match expected"
  }

  assert {
    condition = output.provides == {
      cos_agent = {
        kind     = "endpoint"
        name     = "squid-forward-proxy"
        endpoint = "cos-agent"
      }
      http_proxy = {
        kind     = "endpoint"
        name     = "squid-forward-proxy"
        endpoint = "http-proxy"
      }
    }
    error_message = "provides outputs did not match expected structure"
  }
}
