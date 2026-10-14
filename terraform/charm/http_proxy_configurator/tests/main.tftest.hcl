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
    # renovate: depName="http-proxy-configurator"
    revision = 17
  }

  assert {
    condition     = output.application.name == "http-proxy-configurator"
    error_message = "http-proxy-configurator application name did not match expected"
  }

  assert {
    condition     = output.provides.value.endpoint == "delegate-http-proxy"
    error_message = "http-proxy-configurator module should provide 'provides.value' output"
  }

  assert {
    condition     = output.requires.value.endpoint == "http-proxy"
    error_message = "http-proxy-configurator module should provide 'requires.value' output"
  }
}
