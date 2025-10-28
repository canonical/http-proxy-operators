# Integrations

See [Integrations](https://charmhub.io/http-proxy-configurator/integrations).

### `http-proxy`

_Interface_: `http_proxy`
_Supported charms_: [Squid Forward Proxy](https://charmhub.io/squid-forward-proxy), [HTTP proxy policy](https://charmhub.io/http-proxy-policy)

The `http-proxy` endpoint integrates with charms that **provide** HTTP proxy configuration. This relation allows the charm to receive and apply proxy settings from compatible proxy provider charms.

Example integration command: 
```
juju integrate http-proxy-configurator:http-proxy squid-forward-proxy
```

### `delegate-http-proxy`

_Interface_: `http_proxy`
_Supported charms_: All 12 factor charms. For example, the [Hockeypuck charm](https://charmhub.io/hockeypuck-k8s).

The `delegate-http-proxy` endpoint integrates with charms that **require** HTTP proxy configuration. This relation allows the charm to relay proxy settings back to the proxy requiring charms.

Example integration command: 
```
juju integrate http-proxy-configurator:http-proxy hockeypuck-k8s
```
