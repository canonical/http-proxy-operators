# HTTP proxy operators

This repository provides a collection of operators related to HTTP proxies,
including offering HTTP proxy services and managing HTTP proxy integration with
our charms.

For detailed information about how to deploy, integrate, and manage the HTTP proxy configurator charm, see the official [HTTP proxy configurator operator documentation](https://charmhub.io/http-proxy-configurator).

## Repository layout

```
.github/                          # GitHub issue, pull request, and workflow configuration
http-proxy-configurator-operator/ # Juju charm: configurator for the http-proxy interface
  docs/                           # In-repository documentation for configurator modes, integrations, actions, and tutorial
  src/                            # Configurator charm source code
  tests/                          # Configurator charm tests
http-proxy-policy-operator/       # Juju subordinate charm: policy layer in front of the HTTP proxy charms
  docs/                           # In-repository changelog and upgrade guide
  src/                            # Policy charm source code
  tests/                          # Policy charm tests
http-proxy-policy/                # Snap workload: Django application made for the http-proxy-policy charm
  docs/                           # Snap changelog
  http_proxy_policy/              # Django project package
  policy/                         # Policy application code
  snap/                           # Snapcraft packaging
squid-forward-proxy-operator/     # Juju charm: Squid proxy instance as a forward proxy server
  docs/                           # In-repository changelog and upgrade guide
  src/                            # Squid forward proxy charm source code
  tests/                          # Squid forward proxy charm tests
Makefile                          # Top-level make targets, delegated to Makefile.docs
Makefile.docs                     # Documentation quality and local documentation targets
```

## Components

This repository contains three Juju charms and one snapped workload:

| Published name | Component path | Role |
| --- | --- | --- |
| `http-proxy-configurator` | `./http-proxy-configurator-operator/` | A charm that serves as a configurator for the http-proxy interface. It can be used to provide http-proxy for both charmed and non-charmed workloads. |
| `squid-forward-proxy` | `./squid-forward-proxy-operator/` | A machine charm managing a Squid proxy instance as a forward proxy server. |
| `http-proxy-policy` | `./http-proxy-policy-operator/` | A subordinate charm that adds a policy layer in front of the HTTP proxy charms. |
| `charmed-http-proxy-policy` | `./http-proxy-policy/` | A snapped Django application specifically made for the `http-proxy-policy` charm. |

### Charmhub and Snapcraft

| Name | Listing |
| --- | --- |
| `http-proxy-configurator` | https://charmhub.io/http-proxy-configurator |
| `http-proxy-policy` | https://charmhub.io/http-proxy-policy |
| `squid-forward-proxy` | https://charmhub.io/squid-forward-proxy |
| `charmed-http-proxy-policy` | https://snapcraft.io/charmed-http-proxy-policy |

## Get started

Start with the component that matches the architecture you are working on:

* To deploy the Squid forward proxy charm and use it as an HTTP proxy server, see [`squid-forward-proxy-operator/README.md`](./squid-forward-proxy-operator/README.md).
* To deploy the HTTP proxy policy charm and explore its web interface, see [`http-proxy-policy-operator/README.md`](./http-proxy-policy-operator/README.md).
* To provide http-proxy for both charmed and non-charmed workloads, see [`http-proxy-configurator-operator/README.md`](./http-proxy-configurator-operator/README.md) and the in-repository tutorial at [`http-proxy-configurator-operator/docs/tutorial/getting-started.md`](./http-proxy-configurator-operator/docs/tutorial/getting-started.md).
* To build or run the workload of the `http-proxy-policy` charm, see [`http-proxy-policy/README.md`](./http-proxy-policy/README.md).


## Integrations

For endpoint details, see the in-repository files [`http-proxy-policy-operator/README.md`](./http-proxy-policy-operator/README.md), [`squid-forward-proxy-operator/README.md`](./squid-forward-proxy-operator/README.md), and [`http-proxy-configurator-operator/docs/reference/integrations.md`](./http-proxy-configurator-operator/docs/reference/integrations.md).

## Documentation

Our documentation is stored in the `docs` directory.
In structuring, the
documentation employs the [Diátaxis](https://diataxis.fr/) approach.

You may open a pull request with your documentation changes, or you can
[file a bug](https://github.com/canonical/http-proxy-operators/issues) to
provide constructive feedback or suggestions.

GitHub runs automatic checks on the documentation to validate links and
style guide compliance.

You can (and should) run the same checks locally:

```bash
make lychee
make vale
```

## Project and community

The HTTP proxy operators project is a member of the Ubuntu family. It is an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.

* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Issues](https://github.com/canonical/http-proxy-operators/issues)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

## Licensing and trademark

See [`LICENSE`](./LICENSE) for licensing details.
