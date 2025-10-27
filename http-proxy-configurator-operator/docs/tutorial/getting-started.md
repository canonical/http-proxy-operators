# Deploy the HTTP proxy configurator charm

This tutorial will walk you through deploying and configuring the HTTP proxy configurator operator, a Juju charm that provides HTTP proxy configuration to your application. For the purpose of the tutorial, we will demonstrate how to use the charm in `pass-through` mode.

## What you'll need

Before you start, you'll need:

- A machine with amd64 architecture.
- A Juju controller (version 3.0 or higher)
- MicroK8s / Canonical Kubernetes and LXD installed and bootstrapped to Juju.

[note]
All the requirements can be met using the [Multipass charm-dev blueprint](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-deployment/manage-your-deployment-environment/#set-things-up). Use the Multipass VM shell to run all commands in this tutorial.
[/note]

For more information about how to install Juju, see [Get started with Juju](https://documentation.ubuntu.com/juju/3.6/tutorial/).

## Set up tutorial models

To easily clean up the resources and to separate your workload from the contents of this tutorial,
set up a new Juju model in the `lxd` controller to deploy a HTTP proxy provider.

```bash
juju add-model proxy-tutorial-lxd
```

Set up a new Juju model in the `microk8s` controller to deploy a HTTP proxy requirer.

```bash
juju switch <k8s-controller-name>
juju add-model proxy-tutorial-k8s
```
## Deploy the charms

<!-- vale Canonical.007-Headings-sentence-case = NO -->
### Deploy a proxy requirer
<!-- vale Canonical.007-Headings-sentence-case = YES -->

```bash
juju deploy hockeypuck-k8s --channel=2.2/edge --config metrics-port=9626 --config app-port=11371
juju deploy postgresql-k8s --channel 14/stable --trust
juju integrate hockeypuck-k8s postgresql-k8s
```

Wait for the charm to be active:
```bash
juju wait-for application hockeypuck-k8s
```
### Deploy the HTTP proxy configurator

Deploy the HTTP proxy configurator charm:

```bash
juju deploy http-proxy-configurator
```

Establish the relation between the configurator and the proxy requirer:

```bash
juju integrate http-proxy-configurator:delegate-http-proxy hockeypuck-k8s:http-proxy
```

[note]
The configurator charm assumes that it is deployed on the same cloud as the application it integrates with.
For the authentication modes to work as expected, ensure that the configurator charm is deployed on the same cloud.
[/note]

Configure the domains that applications will access through the proxy:

```bash
juju config http-proxy-configurator http-proxy-domains="api.github.com,example.com"
```

### Deploy a proxy provider

We'll use the squid-forward-proxy operator:

```bash
juju switch <lxd-controller-name>:proxy-tutorial-lxd
juju deploy squid-forward-proxy --channel edge
juju config squid-forward-proxy hostname="proxy.example.com"
```

Wait for the deployment to complete:

```bash
juju status --watch 1s
```

You should see the squid-forward-proxy in an active state.

Create an offer for the `http-proxy` interface:

```bash
juju offer squid-forward-proxy:http-proxy
```

Establish the relation between the configurator and the proxy provider:

```bash
juju switch <k8s-controller-name>:proxy-tutorial-k8s
juju integrate http-proxy-configurator:http-proxy <lxd-controller-name>:admin/proxy-tutorial-lxd.squid-forward-proxy:http-proxy
```

### Test proxy

You can now test if the proxy values have been received by the proxy requirer charm:

```bash
juju ssh hockeypuck-k8s/0 "pebble plan" | grep "PROXY"
```
This must be the same as the values obtained from the Squid proxy charm:

```bash
juju run http-proxy-configurator/0 get-proxies
```

### Clean up the environment

Congratulations! You have successfully finished the tutorial. You can now remove the
model environment that you’ve created using the following command.


```bash
juju destroy-model proxy-tutorial-k8s --destroy-storage
juju switch <lxd-controller-name>
juju destroy-model proxy-tutorial-lxd --destroy-storage
```
