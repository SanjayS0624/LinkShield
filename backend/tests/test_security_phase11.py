from app.core.rate_limit import scan_rate_limit
from app.detection import domain_intelligence, redirect_analyzer
from app.detection.url_analyzer import URLValidationError, analyze_url


def test_registration_cannot_assign_privileged_role(client):
    response = client.post("/api/auth/register", json={
        "email": "role-test@example.com",
        "password": "correct horse battery",
        "role": "admin",
    })
    assert response.status_code == 201
    assert response.json()["user"]["role"] == "viewer"


def test_viewer_cannot_manage_brands(client):
    registration = client.post("/api/auth/register", json={
        "email": "viewer@example.com", "password": "correct horse battery"
    }).json()
    response = client.post("/api/brands", headers={
        "Authorization": f"Bearer {registration['access_token']}"
    }, json={"name": "Test Brand", "official_domains": ["test-brand.example"]})
    assert response.status_code == 403


def test_invalid_bearer_token_is_rejected(client):
    response = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


def test_security_headers_and_no_store_on_api(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_special_use_domains_never_trigger_dns(monkeypatch):
    def fail_if_resolved(*args, **kwargs):
        raise AssertionError("special-use hostname must not be resolved")

    monkeypatch.setattr(domain_intelligence.dns.resolver, "resolve_name", fail_if_resolved)
    monkeypatch.setattr(redirect_analyzer.dns.resolver, "resolve_name", fail_if_resolved)
    assert domain_intelligence.inspect_domain("service.internal")["dns"]["status"] == "blocked"
    assert domain_intelligence.inspect_domain("example.invalid")["dns"]["status"] == "blocked"
    assert redirect_analyzer._resolve_public("printer.local") == []
    assert redirect_analyzer._resolve_public("example.invalid") == []


def test_redirect_checker_blocks_private_ips_before_connect(monkeypatch):
    monkeypatch.setattr(redirect_analyzer.socket, "socket", lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("private address must not open a socket")))
    result = redirect_analyzer.inspect_redirects("http://127.0.0.1/admin")
    assert result["status"] == "blocked"
    assert result["redirect_count"] == 0


def test_url_input_boundary_and_scheme_fuzz_cases():
    for candidate in ("javascript:alert(1)", "file:///etc/passwd", "ftp://example.com/file",
                      "https://example.com/\r\nInjected: value", "https://bad..example"):
        try:
            analyze_url(candidate)
        except URLValidationError:
            continue
        raise AssertionError(f"unsafe or malformed input was accepted: {candidate!r}")

    try:
        analyze_url("https://example.com/" + "a" * 4100)
    except URLValidationError:
        pass
    else:
        raise AssertionError("overlong URL was accepted")


class FakeRedis:
    def __init__(self):
        self.counts = {}

    def eval(self, script, key_count, key, window):
        self.counts[key] = self.counts.get(key, 0) + 1
        return [self.counts[key], window]


def test_anonymous_scan_rate_limit_returns_retry_after(client, monkeypatch):
    from app.core import rate_limit
    from app.api import scans

    monkeypatch.setattr(rate_limit, "_client", FakeRedis())
    # Keep this limit test isolated from external network services.
    monkeypatch.setattr(scans, "inspect_domain", lambda *args, **kwargs: {
        "dns": {"status": "unavailable", "addresses": []},
        "certificate": {"status": "not_checked"},
        "registration": {"status": "unavailable"},
    })
    monkeypatch.setattr(scans, "lookup_url", lambda url: {"providers": []})
    monkeypatch.setattr(scans, "inspect_redirects", lambda url: {"redirect_count": 0})
    monkeypatch.setattr(scans, "explain_assessment", lambda **kwargs: {})

    # Existing fixture disables the dependency for other scan tests; enable it here.
    client.app.dependency_overrides.pop(scan_rate_limit, None)
    for _ in range(5):
        assert client.post("/api/scans", json={"url": "https://example.com"}).status_code == 201
    limited = client.post("/api/scans", json={"url": "https://example.com"})
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0
    assert limited.json()["detail"].startswith("Scan limit reached")
