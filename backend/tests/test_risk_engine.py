from app.detection.risk_engine import assess_risk, risk_level


def test_score_is_explainable_and_https_is_only_a_modest_offset():
    result = assess_risk([
        {"category": "DOMAIN", "severity": "MEDIUM", "title": "IP address used as hostname", "evidence": "Host: 192.0.2.1"},
        {"category": "URL_STRUCTURE", "severity": "LOW", "title": "Sensitive-action wording in URL", "evidence": "Matched terms: login"},
    ], scheme="https")
    assert result["risk_score"] == 25
    assert result["risk_level"] == "LOW"
    assert result["risk_calculation"]["raw_total"] == 25
    assert [item["impact"] for item in result["risk_calculation"]["components"]] == [20, 10, -5]
    assert result["findings"][-1]["title"] == "HTTPS transport observed"


def test_risk_bands_match_configured_thresholds():
    assert [risk_level(score) for score in (0, 29, 30, 59, 60, 79, 80, 100)] == [
        "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"
    ]


def test_one_weak_signal_cannot_create_high_or_critical_risk():
    result = assess_risk([
        {"category": "URL_STRUCTURE", "severity": "LOW", "title": "Non-standard port", "evidence": "Port: 8080"}
    ], scheme="http")
    assert result["risk_score"] == 5
    assert result["risk_level"] == "LOW"
