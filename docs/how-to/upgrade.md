# How to upgrade

This guide describes how to upgrade the HTTP proxy charms.

## Upgrade the HTTP proxy configurator charm

The `http-proxy-configurator` charm is stateless, making the upgrade process
straightforward and safe. Upgrade the charm by refreshing it to a new revision.
Juju preserves the charm's configuration and relations during the upgrade.

```bash
juju refresh http-proxy-configurator
```

### Verify the upgrade

After upgrading, verify that the charm is functioning correctly by checking its
status. The charm must be in the `active` and `idle` state.

```bash
juju status http-proxy-configurator
```

## Upgrade the HTTP proxy policy charm

The `http-proxy-policy` charm is stateless. Upgrading the charm involves
refreshing it to a new revision. However, back up the PostgreSQL database
related to `http-proxy-policy` before upgrading due to a small chance of data
loss.

To back up the PostgreSQL database, refer to [the PostgreSQL charm backup
guide](https://canonical-charmed-postgresql.readthedocs-hosted.com/14/how-to/back-up-and-restore/create-a-backup/).

During the upgrade, the charm may need to restart the `http-proxy-policy`
service. This may briefly interrupt `http-proxy-policy` and cause errors in its
web portal. The errors disappear when the upgrade finishes.

### Back up the PostgreSQL database

```bash
juju run postgresql/leader create-backup --wait=1h
```

### Upgrade the charm

```bash
juju refresh http-proxy-policy
```

## Upgrade the Squid forward proxy charm

The `squid-forward-proxy` charm is stateless. Upgrade the charm by refreshing
it to a new revision. Juju preserves the charm's configuration and relations
during the upgrade.

The charm may reload the Squid proxy service configuration during an upgrade to
apply new changes, but this typically does not interrupt service.

```bash
juju refresh squid-forward-proxy
```
