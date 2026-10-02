"""Deterministic, evidence-weighted risk scoring. Scores describe assessed risk, not certainty."""

from typing import Any


SIGNAL_WEIGHTS = {
    "Unusually long URL": 5,
    "Credentials embedded in URL": 20,
    "IP address used as hostname": 20,
    "Many hostname labels": 5,
    "Long hostname": 5,
    "TLD often seen in abuse reports": 10,
    "Known link-shortening domain": 5,
    "Internationalized hostname": 20,
    "Malformed percent encoding": 5,
    "Repeated percent encoding": 5,
    "Non-standard port": 5,
    "Several hyphens in hostname": 5,
    "Sensitive-action wording in URL": 10,
    "Encoded redirect destination": 15,
    "URL fragment present": 0,
}


def risk_level(score: int) -> str:
    if score < 30:
        return "LOW"
    if score < 60:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"


def assess_risk(findings: list[dict[str, Any]], scheme: str) -> dict[str, Any]:
    """Attach score impacts and return a reproducible score calculation."""
    scored_findings: list[dict[str, Any]] = []
    for item in findings:
        finding = dict(item)
        finding["score_impact"] = (40 if finding.get("category") == "THREAT_INTELLIGENCE"
                                    and finding.get("title") == "Known threat intelligence match"
                                    else 30 if finding.get("category") == "BRAND_IMPERSONATION"
                                    else 15 if finding.get("category") == "REDIRECT"
                                    and finding.get("title") == "Multiple redirects detected"
                                    else SIGNAL_WEIGHTS.get(finding["title"], 0))
        scored_findings.append(finding)

    # A configured brand appearing on a non-official hostname is a stronger
    # phishing signal when the URL also contains account/sign-in wording.
    # Keep the correlation bonus explicit so the score remains explainable.
    has_brand_match = any(item.get("category") == "BRAND_IMPERSONATION" for item in findings)
    has_sensitive_action = any(item.get("title") == "Sensitive-action wording in URL" for item in findings)
    if has_brand_match and has_sensitive_action:
        scored_findings.append({
            "category": "COMBINED_SIGNAL",
            "severity": "HIGH",
            "title": "Brand impersonation with account-action wording",
            "description": "A configured brand appears on a non-official hostname alongside sign-in or account-action wording. This combination is more concerning, but does not confirm phishing or malware.",
            "evidence": "Configured brand match and sensitive-action wording were both detected.",
            "score_impact": 25,
        })

    if scheme.lower() == "https":
        scored_findings.append({
            "category": "URL_STRUCTURE",
            "severity": "INFO",
            "title": "HTTPS transport observed",
            "description": "HTTPS encrypts transport but does not establish that the site or its content is trustworthy.",
            "evidence": "Scheme: HTTPS",
            "score_impact": -5,
        })

    components = [
        {"title": item["title"], "category": item["category"], "severity": item["severity"],
         "evidence": item["evidence"], "impact": item["score_impact"]}
        for item in scored_findings if item["score_impact"] != 0
    ]
    raw_total = sum(component["impact"] for component in components)
    score = max(0, min(100, raw_total))
    formula_terms = ["0"] + [f"{component['impact']:+d} ({component['title']})" for component in components]
    formula = " ".join(formula_terms) + f" = {raw_total}; clamp to 0–100 = {score}"
    level = risk_level(score)
    if raw_total <= 0:
        summary = "No positive weighted risk indicators were found. This assessment does not prove that the URL is safe."
    else:
        summary = f"Assessed {level.lower()} risk ({score}/100) from the weighted indicators listed below; this is not a verdict."
    calculation = {
        "method": "Deterministic sum of listed signal weights, including a 25-point bonus when a brand match and sensitive-action wording occur together, bounded to 0–100.",
        "formula": formula,
        "components": components,
        "raw_total": raw_total,
        "final_score": score,
    }
    return {"risk_score": score, "risk_level": level, "summary": summary,
            "findings": scored_findings, "risk_calculation": calculation}
