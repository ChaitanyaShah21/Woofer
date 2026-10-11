"""Pytest fixtures for Woofer application tests."""
import pytest
from werkzeug.security import generate_password_hash

from woofer import create_app
from woofer.extensions import db
from woofer.models import User
from woofer.services.email import outbox


@pytest.fixture
def app():
    """Create and configure an isolated application instance for testing."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test HTTP client with CSRF disabled for functional route testing."""
    outbox.clear()
    return app.test_client()


@pytest.fixture
def csrf_client(app):
    """Test HTTP client with CSRF protection enabled for security tests."""
    app.config["WTF_CSRF_ENABLED"] = True
    return app.test_client()


@pytest.fixture
def verified_user(app):
    """Create a standard verified test user."""
    with app.app_context():
        user = User(
            firstName="Alice",
            lastName="Smith",
            username="alicesmith",
            email="alice@example.com",
            hash=generate_password_hash("Password123!"),
            is_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        return db.session.get(User, user.id)


@pytest.fixture
def auth_client(client, verified_user):
    """Client authenticated as verified_user."""
    with client.session_transaction() as sess:
        sess["user_id"] = verified_user.id
    return client
