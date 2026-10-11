"""Security tests: CSRF validation, security headers, cookie flags, and XSS escaping."""
from woofer.config import ProductionConfig


def test_csrf_protection_rejects_missing_token(csrf_client):
    """POST request without CSRF token is rejected with HTTP 400 when CSRF is enabled."""
    response = csrf_client.post(
        "/login",
        data={"username": "alice", "password": "Password123!"},
    )
    assert response.status_code == 400


def test_security_headers_present(client):
    """HTTP responses include cache-busting headers."""
    response = client.get("/login")
    assert response.status_code == 200
    assert "no-cache" in response.headers.get("Cache-Control", "")
    assert "no-store" in response.headers.get("Cache-Control", "")


def test_production_cookie_configuration():
    """Production configuration enables secure cookie settings."""
    assert ProductionConfig.SESSION_COOKIE_SECURE is True
    assert ProductionConfig.SESSION_COOKIE_HTTPONLY is True
    assert ProductionConfig.SESSION_COOKIE_SAMESITE == "Lax"


def test_xss_escaping_in_posts(auth_client):
    """Malicious script tags in posts are auto-escaped in HTML output."""
    payload = "<script>alert('xss')</script>"
    response = auth_client.post(
        "/",
        data={"send-woof": payload},
        follow_redirects=True,
    )
    assert response.status_code == 200
    # Escaped markup should be present, not raw executable script tag
    assert b"<script>alert('xss')</script>" not in response.data


def test_password_change_invalidates_other_sessions(app, verified_user):
    """When user changes password, any other active browser session is invalidated immediately."""
    client1 = app.test_client()
    client2 = app.test_client()

    # Log in both clients
    for cl in (client1, client2):
        cl.post("/login", data={"username": verified_user.username, "password": "Password123!"})

    # Client 1 changes password
    client1.post("/profile", data={
        "old_password": "Password123!",
        "new_password": "BrandNewPassword789$",
    }, follow_redirects=True)

    # Client 1 still has access
    resp1 = client1.get("/my-woofs")
    assert resp1.status_code == 200

    # Client 2 is rejected because its session_token is now stale
    resp2 = client2.get("/my-woofs", follow_redirects=True)
    assert b"Your session has expired or your password was changed" in resp2.data


