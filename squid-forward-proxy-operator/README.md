# Squid forward proxy charm

[![CharmHub Badge](https://charmhub.io/squid-forward-policy/badge.svg)](https://charmhub.io/squid-forward-policy)
[![Publish to edge](https://github.com/canonical/http-proxy-operators/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/http-proxy-operators/actions/workflows/publish.yaml/badge.svg)
[![Promote charm](https://github.com/canonical/http-proxy-operators/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/http-proxy-operators/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

Squid forward proxy charm is a charm running Squid proxy for its forward HTTP 
proxy functionality.

Like any Juju charm, this charm supports one-line deployment, configuration, 
integration, scaling, and more. For Charmed Squid forward proxy, this includes:

* Automatically installing and setting up Squid as a forward HTTP proxy
* HTTP proxy access control via Juju relations

For information about how to deploy, integrate, and manage this charm, see the
official [Squid forward proxy charm documentation](https://charmhub.io/squid-forward-proxy).

## Get started

In this section, we will deploy the Squid forward proxy charm and use it as an
HTTP proxy server.

You’ll need a workstation, such as a laptop, with sufficient resources to launch
a virtual machine with 4 CPUs, 8 GB RAM, and 50 GB of disk space.

### Set up

You can follow the how-to guide [here](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-deployment/manage-your-deployment-environment/#set-things-up) to set up a test environment for Juju with LXD.

### Deploy

From inside the virtual machine, deploy the Squid forward proxy charm using the
`juju deploy` command.

```
juju deploy squid-forward-proxy --channel latest/edge
```

### Basic operations

When the Squid forward proxy charm has finished deploying and installing, it 
should show the message `ready: 0` in the output of `juju status`.

Now we can use the Squid forward proxy charm as an HTTP proxy server. As we 
haven't obtained access to the HTTP proxy via a Juju relation, the proxy request
will fail. This is expected.

```
curl -x http://<squid-forward-proxy-unit-ip>:3128 https://example.com
```

## Integrations

The Squid forward proxy charm provides the `http-proxy` interface, which 
HTTP proxy-requiring applications can use to obtain access to the HTTP proxy 
service provided by the Squid proxy policy charm.

If you want to protect and manage who can use the `http-proxy` relation, 
consider using it in conjunction with the [HTTP proxy policy charm](https://charmhub.io/http-proxy-policy).

## Learn more
* [Read more](https://charmhub.io/http-proxy-policy)
* [Official webpage](https://www.squid-cache.org/)
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

## Project and community
* [Issues](https://github.com/canonical/http-proxy-operators/issues)
* [Contributing](./CONTRIBUTING.md)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
