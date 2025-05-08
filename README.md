# HTTP proxy operators

This repository provides a collection of operators related to HTTP proxies,
including offering HTTP proxy services and managing HTTP proxy integration with
our charms.

This repository contains the code for the following charms:

1. [`squid-forward-proxy`](./squid-forward-proxy-operator): A machine charm
   managing a Squid proxy instance as a forward proxy server.
2. [`http-proxy-policy`](./http-proxy-policy-operator): A subordinate charm that
   adds a policy layer in front of the HTTP proxy charms.

The repository also contains the snapped workload of some charms:

1. [`charmed-http-proxy-policy`](./http-proxy-policy): A snapped Django
   application specifically made for the `http-proxy-policy` charm.

## Project and community

The HTTP proxy operators project is a member of the Ubuntu family. It is an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.

* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Issues](https://github.com/canonical/http-proxy-operators/issues)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
