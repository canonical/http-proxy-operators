# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variables {
  app_name    = "http-proxy-configurator"
  base        = "ubuntu@24.04"
  channel     = "latest/edge"
  config      = {}
  constraints = "arch=amd64"
  model_uuid  = "00000000-0000-0000-0000-000000000001"
  revision    = 17
  units       = 1
}

mock_provider "juju" {
  mock_resource "juju_application" {
    override_during = plan
    defaults = {
      id         = "http-proxy-configurator"
      model_type = "iaas"
    }
  }
}

run "deploys_application" {
  command = plan

  assert {
    condition     = output.application.name == "http-proxy-configurator" && output.application.model_uuid == "00000000-0000-0000-0000-000000000001" && output.application.charm[0].name == "http-proxy-configurator" && output.application.charm[0].channel == "latest/edge" && output.application.charm[0].base == "ubuntu@24.04" && output.application.charm[0].revision == 17
    error_message = "application identity did not match the expected deployment"
  }

  assert {
    condition     = output.application.units == 1
    error_message = "application units did not match expected"
  }

  assert {
    condition = output.provides == {
      delegate_http_proxy = {
        kind     = "endpoint"
        name     = "http-proxy-configurator"
        endpoint = "delegate-http-proxy"
      }
    }
    error_message = "provides outputs did not match expected structure"
  }

  assert {
    condition = output.requires == {
      http_proxy = {
        kind     = "endpoint"
        name     = "http-proxy-configurator"
        endpoint = "http-proxy"
      }
    }
    error_message = "requires outputs did not match expected structure"
  }
}
