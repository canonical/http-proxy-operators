# HTTP proxy policy snap

This snap is meant to be the workload of the [http-proxy-policy-operator](https://github.com/canonical/http-proxy-policy/http-proxy-policy-operator) 
charm.  

## Get started

### Install the snap
The snap can be installed directly from the Snap Store.  
[![Get it from the snap store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/charmed-http-proxy-policy)


### Build the snap
The steps outlined below are based on the assumption that you are building 
the snap with the latest LTS of Ubuntu. If you are using another version of
Ubuntu or another operating system, the process may be different.

#### Clone repository
```bash
git clone git@github.com:canonical/http-proxy-policy.git
cd http-proxy-operators/charmed-http-proxy-policy
```

#### Install and configure prerequisites
```bash
sudo snap install snapcraft
sudo snap install lxd
sudo lxd init --auto
```

#### Pack and install the snap
```bash
snapcraft pack
sudo snap install ./charmed-http-proxy-policy_*.snap --devmode
```

#### Basic setup

Start a PostgreSQL database:

```
docker run -d --name postgres -p 127.0.0.1:5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_USERNAME=postgres postgres:latest
```

Basic snap configurations:

```
sudo snap set charmed-http-proxy-policy allowed-hosts='["*"]'
sudo snap set charmed-http-proxy-policy log-level=info
sudo snap set charmed-http-proxy-policy database-password=postgres
sudo snap set charmed-http-proxy-policy database-host=localhost
sudo snap set charmed-http-proxy-policy database-port=5432
sudo snap set charmed-http-proxy-policy database-user=postgres
sudo snap set charmed-http-proxy-policy database-name=postgres
sudo snap set charmed-http-proxy-policy secret-key=test
```

## Learn more
* [Read more](https://charmhub.io/http-proxy-policy/docs)

## Project and community
* [Issues](https://github.com/canonical/http-proxy-operators/issues)
* [Contribute](https://github.com/canonical/http-proxy-operators/blob/main/CONTRIBUTING.md)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
