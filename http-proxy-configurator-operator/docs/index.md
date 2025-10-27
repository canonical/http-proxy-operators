# HTTP proxy configurator operator

A [Juju](https://juju.is/) [charm](https://documentation.ubuntu.com/juju/3.6/reference/charm/) that serves as a configurator for the http-proxy interface. It can be used to provide http-proxy for both charmed and non-charmed workloads. Like any Juju charm, this charm supports one-line deployment, configuration, integration, and more. 

The HTTP proxy configurator acts as a bridge between applications that need HTTP proxy configuration and proxy providers.
It can operate in two distinct modes:
- **Integrator mode**: For non-charmed applications that configure the charm via config options and retrieve proxy values via the `get-proxies` action.
- **Pass-through mode**: For charmed applications that integrate via relations and can dynamically configure domains and authentication modes.

For DevOps and SRE teams, this charm will make operating HTTP proxy configuration simple and straightforward through Juju's clean interface.

## In this documentation

| | |
|--|--|
|  [Tutorials](https://charmhub.io/http-proxy-configurator/docs/tutorial-getting-started)</br>  Get started - a hands-on introduction to using the charm for new users </br> |  [How-to guides](https://charmhub.io/http-proxy-configurator/docs/how-to-contribute) </br> Step-by-step guides covering key operations and common tasks |
| [Reference](https://charmhub.io/http-proxy-configurator/docs/reference-actions) </br> Technical information - specifications, APIs, architecture | [Explanation](https://charmhub.io/http-proxy-configurator/docs/explanation-charm-architecture) </br> Concepts - discussion and clarification of key topics  |

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as 
the code. As such, we welcome community contributions, suggestions and constructive feedback on our documentation. 
Our documentation is hosted on the [Charmhub forum](https://discourse.charmhub.io/) 
to enable easy collaboration. Please use the "Help us improve this documentation" links on each documentation page to 
either directly change something you see that's wrong, ask a question or make a suggestion about a potential change via 
the comments section.

If there's a particular area of documentation that you'd like to see that's missing, please 
[file a bug](https://github.com/canonical/http-proxy-operators/issues).

## Project and community

The HTTP proxy configurator operator is a member of the Ubuntu family. It's an open-source project that warmly welcomes community 
projects, contributions, suggestions, fixes, and constructive feedback.

- [Code of conduct](https://ubuntu.com/community/code-of-conduct)
- [Get support](https://discourse.charmhub.io/)
- [Join our online chat](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
- [Contribute](https://github.com/canonical/http-proxy-operators/blob/main/http-proxy-configurator-operator/CONTRIBUTING.md)

Thinking about using the HTTP proxy configurator operator for your next project? 
[Get in touch](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)!

# Contents

1. [Changelog](changelog.md)
2. [Explanation](explanation)
  1. [Charm architecture](explanation/charm-architecture.md)
3. [How To](how-to)
  1. [Upgrade](how-to/upgrade.md)
4. [Reference](reference)
  1. [Actions](reference/actions.md)
  2. [Configurations](reference/configurations.md)
  3. [Integrations](reference/integrations.md)
5. [Tutorial](tutorial)
  1. [Getting started](tutorial/getting-started.md)

