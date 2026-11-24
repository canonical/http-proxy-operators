# HTTP proxy operators

The HTTP proxy operators are a collection of [Juju](https://canonical.com/juju)
charms for deploying an HTTP forward proxy, controlling access to it, and
providing proxy configuration to applications.

The collection includes three operators:

- **Squid forward proxy** runs the proxy server and manages access through Juju relations.
- **HTTP proxy policy** filters proxy access requests using administrator-defined rules
  and provides a web interface for approving or rejecting access requests.
- **HTTP proxy configurator** connects applications to proxy providers. It
  supports both charmed applications and non-charmed applications that retrieve
  proxy configuration through a Juju action.

These operators help system administrators and SRE teams manage HTTP proxy
services and application access through Juju.

## In this documentation

| | |
| --- | --- |
| **Get started** | [Deploy the HTTP proxy configurator with a Squid proxy](tutorial/getting-started.md) |
| **Maintenance** | [Upgrade the configurator, policy, and Squid charms](how-to/upgrade.md) |
| **Configuration and relations** | HTTP proxy configurator: [Configuration options](reference/configurations.md) · [Actions](reference/actions.md) · [Relation endpoints](reference/integrations.md) |
| **Design** | HTTP proxy configurator: [Integrator and pass-through modes](explanation/modes.md) · [Charm architecture](reference/charm-architecture.md) |
| **Security** | HTTP proxy configurator: [Best practices](explanation/security.md) · [External access requirements](reference/external_access.md) |

## How this documentation is organized

This documentation follows the [Diátaxis framework](https://diataxis.fr/).
Most pages cover the HTTP proxy configurator; the upgrade guide covers all three
charms.

- The [tutorial](tutorial/getting-started.md) takes you through deploying the
  HTTP proxy configurator and connecting an application to a Squid forward proxy.
- The [how-to guide](how-to/upgrade.md) provides upgrade instructions for the
  configurator, policy, and Squid charms.
- Reference pages provide technical details about the configurator's
  [configuration options](reference/configurations.md),
  [actions](reference/actions.md), and [integrations](reference/integrations.md).
- Explanation pages describe the configurator's
  [operating modes](explanation/modes.md) and
  [security considerations](explanation/security.md).

## Contributing to this documentation

We welcome contributions, suggestions, and constructive feedback on the
documentation. You can propose changes through a pull request in the
[HTTP proxy operators repository](https://github.com/canonical/http-proxy-operators)
or [file an issue](https://github.com/canonical/http-proxy-operators/issues)
to report a problem or suggest missing documentation.

## Project and community

The HTTP proxy operators project is a member of the Ubuntu family. It's an
open-source project that welcomes contributions, suggestions, fixes, and
constructive feedback.

- [Code of conduct](https://ubuntu.com/community/docs/ethos/code-of-conduct)
- [Get support](https://discourse.charmhub.io/)
- [Join our online chat](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

Thinking about using the HTTP proxy operators for your next project?
[Get in touch](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)!

## Contents

1. Explanation
   1. [Modes](explanation/modes.md)
   2. [Security](explanation/security.md)
2. How-to guides
   1. [Upgrade](how-to/upgrade.md)
3. Reference
   1. [Actions](reference/actions.md)
   2. [Charm architecture](reference/charm-architecture.md)
   3. [Configurations](reference/configurations.md)
   4. [External access](reference/external_access.md)
   5. [Integrations](reference/integrations.md)
4. Tutorial
   1. [Getting started](tutorial/getting-started.md)
