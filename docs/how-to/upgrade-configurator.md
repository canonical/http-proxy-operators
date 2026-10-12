# How to upgrade

The `http-proxy-configurator` charm is stateless, making the upgrade process straightforward and 
safe. Upgrade the charm by refreshing it to a new revision. The charm's configuration and relations
are preserved by Juju during the upgrade process.

```bash
juju refresh http-proxy-configurator
```

## Verify the upgrade

After upgrading, verify that the charm is functioning correctly by checking the charm status.
The charm must be in `active` and `idle` state.

```bash
juju status http-proxy-configurator
```
