# HTTP proxy configurator operator

[![CharmHub Badge](https://charmhub.io/http-proxy-configurator/badge.svg)](https://charmhub.io/http-proxy-configurator)
[![Juju](https://img.shields.io/badge/Juju%20-3.0+-%23E95420)](https://juju.is/)

A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators) that serves as a configurator for the http-proxy interface. It can be used to provide http-proxy for both charmed and non-charmed workloads. Like any Juju charm, this charm supports one-line deployment, configuration, integration, and more.

The HTTP proxy configurator charm acts as a bridge between applications that need HTTP proxy configuration and proxy providers. It can operate in two modes:

- **Integrator mode**: For non-charmed applications that configure the charm via config options and retrieve proxy values via the `get-proxies` action.
- **Pass-through mode**: For charmed applications that integrate via relations and can dynamically configure domains and authentication modes.

For detailed information about how to deploy, integrate, and manage this charm, see the official [HTTP proxy configurator operator documentation](https://charmhub.io/http-proxy-configurator).

## Get started

To begin, refer to the [tutorial](https://charmhub.io/http-proxy-configurator/docs/tutorial-getting-started) for step-by-step instructions.

### Basic operations

The HTTP proxy configurator charm can work in two main modes:

#### Integrator mode (for non-charmed applications)

In integrator mode, non-charmed applications configure the charm via config options and retrieve proxy configuration via the `get-proxies` action. This mode is ideal for applications that cannot implement the `http-proxy` interface directly.

Example setup:
```bash
juju config http-proxy-configurator http-proxy-domains="example.com,api.service.com"
juju config http-proxy-configurator http-proxy-auth="none"
juju config http-proxy-configurator http-proxy-source-ips="192.168.1.100,192.168.1.101"
juju run http-proxy-configurator/0 get-proxies
```

#### Pass-through mode (for charmed applications)

In pass-through mode, charmed applications integrate with the configurator via the `delegate-http-proxy` relation. The applications will receive the proxy configuration via relation data from the `http-proxy-configurator` charm, based on the domains and authentication methods configured on the charm.

Example setup:
```bash
juju deploy my-charmed-app
juju integrate my-charmed-app:http-proxy http-proxy-configurator:delegate-http-proxy
juju config http-proxy-configurator http-proxy-domains="example.com,api.service.com"
juju config http-proxy-configurator http-proxy-auth="userpass"
```

## Learn more

* [Read more](https://charmhub.io/http-proxy-configurator)
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) 

## Project and community

The HTTP proxy configurator is a member of the Ubuntu family. It's an open source project that warmly welcomes community projects, contributions, suggestions, fixes and constructive feedback.


* [Issues](https://github.com/canonical/http-proxy-operators/issues) 
* [Contributing](https://github.com/canonical/http-proxy-operators/blob/main/http-proxy-configurator-operator/CONTRIBUTING.md) 
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) 
