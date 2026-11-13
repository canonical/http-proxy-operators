# Security

This document outlines common risks and possible best practices for the HTTP proxy configurator charm.

#### Best practices

- Ensure to provide all the authentication modes supported by the application requiring proxy in the configuration. This allows the proxy provider to select the most appropriate and secure authentication method for the application.
- Restrict the domains configured via `http-proxy-domains` to trusted endpoints only. Follow the [principles of least privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege) while configuring the domains.
- Keep the Juju and the charm updated. See more about Juju updates in the [documentation](https://documentation.ubuntu.com/juju/latest/explanation/juju-security/index.html#regular-updates-and-patches).
