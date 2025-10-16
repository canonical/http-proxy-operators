# How to upgrade

The `http-proxy-policy` charm is stateless. Upgrading the charm
involves refreshing it to a new revision. However, it is recommended to
back up the PostgreSQL database related to `http-proxy-policy` before
performing the upgrade due to a small chance of data loss.

To back up the PostgreSQL database, please refer to [the guide in the PostgreSQL charm](https://canonical-charmed-postgresql.readthedocs-hosted.com/14/how-to/back-up-and-restore/create-a-backup/).

During the upgrade, the charm may need to restart the
`http-proxy-policy` service. This may cause a brief interruption in
`http-proxy-policy`, which might appear as errors in the
`http-proxy-policy` web portal. These errors will disappear once the
upgrade has finished.

## Example

### Back up the PostgreSQL database

```bash
juju run postgresql/leader create-backup --wait=1h
```

### Upgrade the `http-proxy-policy` charm

```bash
juju refresh http-proxy-policy
```
