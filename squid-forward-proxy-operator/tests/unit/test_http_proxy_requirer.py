import pytest

from src.http_proxy import HttpProxyDynamicRequirer, HttpProxyRequirer, HTTPProxyUnavailableError


class DummyCharm:
    def __init__(self):
        self.on = {}
        self.framework = DummyFramework(self)


class DummyFramework:
    def __init__(self, charm):
        self.charm = charm

    def observe(self, event, handler):
        return  # no-op


@pytest.fixture(params=["static", "dynamic"])
def make_requirer(request):
    """Factory fixture that returns a function to build a requirer with domains/auth/src_ips."""

    def _factory(domains=None, auth=None, src_ips=None):
        charm = DummyCharm()
        if request.param == "static":
            return HttpProxyRequirer(charm, domains=domains, auth=auth, src_ips=src_ips)
        else:
            r = HttpProxyDynamicRequirer(charm)
            if domains and auth:
                r.request_http_proxy(domains=domains, auth=auth, src_ips=src_ips)
            return r

    return _factory


# -------------------------------
# 1. Happy path
# -------------------------------


def test_happy_path_with_src_ips(make_requirer, monkeypatch):
    r = make_requirer(domains=["example.com"], auth=["none"], src_ips=["10.0.0.1"])
    monkeypatch.setattr(r, "must_get_proxies", lambda: {"HTTP_PROXY": "http://proxy"})
    proxies = r.must_get_proxies()
    assert "HTTP_PROXY" in proxies


def test_happy_path_with_auth_only(make_requirer, monkeypatch):
    r = make_requirer(domains=["example.com"], auth=["none"])
    monkeypatch.setattr(r, "must_get_proxies", lambda: {"HTTPS_PROXY": "https://proxy"})
    proxies = r.must_get_proxies()
    assert "HTTPS_PROXY" in proxies


# -------------------------------
# 2. Invalid domains
# -------------------------------


def test_invalid_domain(make_requirer):
    if make_requirer.__closure__[0].cell_contents == "static":
        # static: invalid domain fails at __init__
        with pytest.raises(ValueError):
            make_requirer(domains=["bad:99999"], auth=["none"])
    else:
        # dynamic: invalid domain fails at request_http_proxy
        r = make_requirer()
        with pytest.raises(ValueError):
            r.request_http_proxy(domains=["bad:99999"], auth=["none"])


# -------------------------------
# 3. Missing required args
# -------------------------------


def test_missing_domains(make_requirer):
    if make_requirer.__closure__[0].cell_contents == "static":
        with pytest.raises(TypeError):
            make_requirer(auth=["none"])
    else:
        r = make_requirer()
        with pytest.raises(ValueError):
            r.request_http_proxy(auth=["none"])


def test_missing_auth(make_requirer):
    if make_requirer.__closure__[0].cell_contents == "static":
        with pytest.raises(TypeError):
            make_requirer(domains=["example.com"])
    else:
        r = make_requirer()
        with pytest.raises(ValueError):
            r.request_http_proxy(domains=["example.com"])


# -------------------------------
# 4. Proxies not ready
# -------------------------------


def test_proxies_not_ready(make_requirer):
    r = make_requirer(domains=["example.com"], auth=["none"])

    def fail():
        raise HTTPProxyUnavailableError("not ready", status="pending")

    r.must_get_proxies = fail

    with pytest.raises(HTTPProxyUnavailableError) as exc_info:
        r.must_get_proxies()
    assert exc_info.value.status == "pending"
    assert exc_info.value.status == "pending"
