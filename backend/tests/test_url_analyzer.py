import pytest

from app.detection.url_analyzer import URLValidationError, analyze_url


def test_normalizes_host_scheme_case_and_default_path():
    result = analyze_url(" Example.COM ")
    assert result.normalized_url == "https://example.com/"
    assert result.domain == "example.com"


def test_flags_ip_port_sensitive_action_and_does_not_fetch():
    result = analyze_url("http://127.0.0.1:8080/login")
    titles = {finding["title"] for finding in result.findings}
    assert "IP address used as hostname" in titles
    assert "Non-standard port" in titles
    assert "Sensitive-action wording in URL" in titles
    assert result.domain == "127.0.0.1"


def test_flags_punycode_and_unicode_domains():
    punycode = analyze_url("https://xn--pple-43d.com")
    unicode = analyze_url("https://аррӏе.com")
    assert any(f["title"] == "Internationalized hostname" for f in punycode.findings)
    assert any(f["title"] == "Internationalized hostname" for f in unicode.findings)


def test_redacts_secrets_and_fragment_from_persistable_url():
    result = analyze_url("https://example.xyz/login?token=supersecret#session-secret")
    assert "supersecret" not in result.storage_url
    assert "session-secret" not in result.storage_url
    assert "REDACTED" in result.storage_url
    assert any(f["title"] == "URL fragment present" for f in result.findings)


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,hello", "ftp://example.com/file", "https:///missing-host"])
def test_rejects_non_http_schemes_and_malformed_urls(url):
    with pytest.raises(URLValidationError):
        analyze_url(url)
