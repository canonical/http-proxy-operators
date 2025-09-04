# HTTP proxy policy charm 

[![CharmHub Badge](https://charmhub.io/http-proxy-policy/badge.svg)](https://charmhub.io/http-proxy-policy)
[![Publish to edge](https://github.com/canonical/http-proxy-operators/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/http-proxy-operators/actions/workflows/publish.yaml/badge.svg)
[![Promote charm](https://github.com/canonical/http-proxy-operators/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/http-proxy-operators/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

The HTTP proxy policy is a charm in the family of policy charms used to filter
relations that request resources. In the case of the HTTP proxy policy charm, 
it receives `http-proxy` relations, filters them based on rules set by the 
administrator, combines the requests, and forwards them to the backend. The 
charm provides a web interface built using the Django framework, which system
administrators can use to approve or reject HTTP proxy requests and modify the
filtering rules as mentioned before.

Like any Juju charm, this charm supports one-line deployment, configuration, 
integration, scaling, and more. For the Charmed HTTP proxy policy, this 
includes:

* Automatically deploying and setting up the HTTP proxy policy server
* Initial user management for the HTTP proxy policy web portal

For information on how to deploy, integrate, and manage this charm, see 
the official [HTTP proxy policy charm documentation](https://charmhub.io/http-proxy-policy).

## Get started

In this section, we will deploy the HTTP proxy policy charm and explore its web
interface.

You’ll need a workstation, such as a laptop, with sufficient resources to launch
a virtual machine with 4 CPUs, 8 GB RAM, and 50 GB of disk space.

### Set up

You can follow the how-to guide [here](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-juju-deployment/set-up-your-juju-deployment-local-testing-and-development/)
to set up a test environment for Juju with LXD.

### Deploy

As the HTTP proxy policy charm is a subordinate charm, we will start by 
deploying the Squid forward proxy charm inside the virtual machine using the
`juju deploy` command. This serves as the base for the HTTP proxy policy charm.

```
juju deploy squid-forward-proxy --channel latest/edge
```

Then deploy the HTTP proxy policy charm on top of the Squid forward proxy charm.
This is a two-step process: first, deploy the HTTP proxy policy charm using the
`juju deploy` command, then use the `juju integrate` command to create a 
subordinate-to-primary relation.

```
juju deploy http-proxy-policy --channel latest/edge
juju integrate http-proxy-policy:juju-info squid-forward-proxy
juju integrate http-proxy-policy:http-proxy-backend squid-forward-proxy
```

Next, deploy the PostgreSQL charm and integrate it with the HTTP proxy policy
charm.

```
juju deploy postgresql
juju integrate http-proxy-policy postgresql
```

### Basic operations

Run the `create-superuser` action on the leader unit of the HTTP proxy policy
charm to create a superuser in the system.

```
juju run http-proxy-policy/leader create-superuser username=testing email=testing@example.com
```

Then you can log in to the HTTP proxy policy web interface using the credentials
created in the previous step at `http://<http-proxy-policy-unit-ip>:8080`.

## Integrations

The main functional relations of the HTTP proxy policy charm are the 
`http-proxy` relation and the `http-proxy-backend` relation.

The `http-proxy` relation is used to collect HTTP proxy requests from all proxy
requirer applications. You can safely expose this relation via a public Juju 
offer, as the HTTP proxy requests received by the HTTP proxy policy charm will
not be fulfilled until they are approved, either manually or automatically.

The `http-proxy-backend` relation is used by the HTTP proxy policy charm to 
send approved HTTP proxy requests to a charm that actually runs the HTTP 
proxy server, for example, the Squid forward proxy charm, to actually fulfill
the requests.

## Learn more
* [Read more](https://charmhub.io/http-proxy-policy)
* [Developer documentation]()
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

## Project and community
* [Issues](https://github.com/canonical/http-proxy-operators/issues)
* [Contributing](./CONTRIBUTING.md)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
