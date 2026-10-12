# How to upgrade

The `squid-forward-proxy` charm is stateless. Upgrade the charm by
refreshing it to a new revision. The charm's configuration and
relations are preserved by Juju.

The charm may reload the Squid proxy service configuration during an
upgrade to apply new changes, but it typically should not cause service
interruptions.

For example:

```bash
juju refresh squid-forward-proxy
```
