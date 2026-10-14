# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

run "setup_tests" {
  module {
    source = "./tests/setup"
  }
}

run "basic_deploy" {
  variables {
    model_uuid = run.setup_tests.model_uuid
    base       = "ubuntu@24.04"
    channel    = "latest/edge"
    # renovate: depName="squid-forward-proxy"
    revision = 40
  }

  assert {
    condition     = output.application.name == "squid-forward-proxy"
    error_message = "squid-forward-proxy application name did not match expected"
  }

  assert {
    condition     = output.provides.value.endpoint == "cos-agent"
    error_message = "squid-forward-proxy module should provide 'provides.value' output"
  }

  assert {
    condition     = output.provides.http_proxy.endpoint == "http-proxy"
    error_message = "squid-forward-proxy module should provide 'provides.http_proxy' output"
  }
}
