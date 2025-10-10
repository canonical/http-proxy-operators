# Upgrade guide

The `squid-forward-proxy` charm is stateless. Upgrading the charm is
simply refreshes the charm to a new revision. Charm configuration and
relations are preserved by Juju.

The charm may reload the Squid proxy service configuration during an
upgrade to apply new changes, but it typically should not cause service
interruptions.

## Example of upgrading the squid-forward-proxy charm

```bash
juju refresh squid-forward-proxy
```
