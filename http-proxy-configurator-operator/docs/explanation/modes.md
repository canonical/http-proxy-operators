# Modes of the the HTTP proxy configurator charm

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
