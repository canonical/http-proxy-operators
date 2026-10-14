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
    # renovate: depName="http-proxy-policy"
    revision = 51
  }

  assert {
    condition     = output.application.name == "http-proxy-policy"
    error_message = "http-proxy-policy application name did not match expected"
  }

  assert {
    condition     = output.provides.value.endpoint == "http-proxy"
    error_message = "http-proxy-policy module should provide 'provides.value' output"
  }

  assert {
    condition     = output.requires.value.endpoint == "http-proxy-backend"
    error_message = "http-proxy-policy module should provide 'requires.value' output"
  }

  assert {
    condition     = output.requires.juju_info.endpoint == "juju-info"
    error_message = "http-proxy-policy module should provide 'requires.juju_info' output"
  }

  assert {
    condition     = output.requires.postgresql.endpoint == "postgresql"
    error_message = "http-proxy-policy module should provide 'requires.postgresql' output"
  }
}
