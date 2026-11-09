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
    condition     = output.provides.http_proxy.endpoint == "http-proxy"
    error_message = "http-proxy-policy module should provide 'provides.http_proxy' output"
  }

  assert {
    condition     = output.requires.http_proxy_backend.endpoint == "http-proxy-backend"
    error_message = "http-proxy-policy module should provide 'requires.http_proxy_backend' output"
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
