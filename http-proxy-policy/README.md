# HTTP proxy policy snap

This snap is meant to be the workload of the [http-proxy-policy-operator](https://github.com/canonical/http-proxy-policy/http-proxy-policy-operator) charm.  

## Get started

### Install the snap
The snap can be installed directly from the snap store.  
[![Get it from the snap store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/charmed-http-proxy-policy)


### Build the snap
The steps outlined below are based on the assumption that you are building the snap with the latest LTS of Ubuntu. If you are using another version of Ubuntu or another operating system, the process may be different.

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

## Learn more
* [Read more](https://charmhub.io/bind/docs)

## Project and community
* [Issues](https://github.com/canonical/http-proxy-operators/issues)
* [Contribute](https://github.com/canonical/http-proxy-operators/blob/main/CONTRIBUTING.md)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
