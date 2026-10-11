"""Tests for service health check endpoint."""
from unittest.mock import patch

from sqlalchemy.exc import OperationalError


def test_health_check_healthy(client):
    """Health endpoint returns HTTP 200 and connected status when database is reachable."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_health_check_unhealthy(client):
    """Health endpoint returns HTTP 503 when database execution fails."""
    with patch("woofer.blueprints.core.db.session.execute", side_effect=OperationalError("connection failed", None, None)):
        response = client.get("/health")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "unhealthy"
        assert data["database"] == "disconnected"


def test_pool_pre_ping_enabled_in_production(app):
    """Verify pool_pre_ping is active in production configuration."""
    from woofer.config import ProductionConfig
    assert ProductionConfig.SQLALCHEMY_ENGINE_OPTIONS.get("pool_pre_ping") is True
