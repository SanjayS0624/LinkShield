def register(client, email):
    return client.post("/api/auth/register", json={"email": email, "password": "correct horse battery"}).json()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_scan_persists_findings_and_redacts_sensitive_url_data(client):
    response = client.post("/api/scans", json={"url": "https://example.xyz/login?token=supersecret#secret"})
    assert response.status_code == 201
    scan = response.json()
    assert scan["status"] == "COMPLETED"
    assert scan["risk_score"] == 15
    assert scan["risk_level"] == "LOW"
    assert scan["risk_calculation"]["final_score"] == 15
    assert "clamp to 0–100 = 15" in scan["risk_calculation"]["formula"]
    assert "supersecret" not in scan["normalized_url"]
    assert "secret" not in scan["normalized_url"]
    assert any(finding["title"] == "Sensitive-action wording in URL" for finding in scan["findings"])
    assert client.post(f"/api/scans", json={"url": "javascript:alert(1)"}).status_code == 422


def test_authenticated_history_is_scoped_and_anonymous_scans_are_not_listed(client):
    first = register(client, "first@example.com")
    second = register(client, "second@example.com")
    created = client.post("/api/scans", json={"url": "https://example.com"}, headers=bearer(first["access_token"]))
    scan_id = created.json()["scan_id"]
    assert client.get("/api/scans", headers=bearer(first["access_token"])).json()[0]["scan_id"] == scan_id
    assert client.get(f"/api/scans/{scan_id}", headers=bearer(second["access_token"])).status_code == 404
    client.post("/api/scans", json={"url": "https://another.example"})
    assert len(client.get("/api/scans", headers=bearer(first["access_token"])).json()) == 1
