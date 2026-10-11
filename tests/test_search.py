"""Tests for woof search and filtering functionality."""
from werkzeug.security import generate_password_hash

from woofer.extensions import db
from woofer.models import User, Woof


def test_search_empty_query_renders_page(auth_client):
    """Navigating to /search without parameters displays search prompt."""
    response = auth_client.get("/search")
    assert response.status_code == 200
    assert b"Search" in response.data


def test_search_by_keyword_matches(auth_client, app, verified_user):
    """Searching by keyword returns matching woofs."""
    with app.app_context():
        post1 = Woof(woof="Deep learning in Python and PyTorch", user_id=verified_user.id)
        post2 = Woof(woof="Database indexing with PostgreSQL", user_id=verified_user.id)
        db.session.add_all([post1, post2])
        db.session.commit()

    response = auth_client.get("/search?q=PostgreSQL")
    assert response.status_code == 200
    assert b"Database indexing with PostgreSQL" in response.data
    assert b"Deep learning in Python" not in response.data


def test_search_by_username_matches(auth_client, app, verified_user):
    """Searching by username or @handle returns posts authored by that user."""
    with app.app_context():
        other = User(
            firstName="Grace",
            lastName="Hopper",
            username="gracehopper",
            email="grace@example.com",
            hash=generate_password_hash("Password123!"),
            is_verified=True,
        )
        db.session.add(other)
        db.session.commit()

        post = Woof(woof="Compilers are amazing", user_id=other.id)
        db.session.add(post)
        db.session.commit()

    # Search with @ prefix
    response = auth_client.get("/search?q=@gracehopper")
    assert response.status_code == 200
    assert b"Compilers are amazing" in response.data
    assert b"Grace" in response.data


def test_search_case_insensitive(auth_client, app, verified_user):
    """Search matches regardless of letter casing."""
    with app.app_context():
        post = Woof(woof="Distributed Consensus via Raft", user_id=verified_user.id)
        db.session.add(post)
        db.session.commit()

    response = auth_client.get("/search?q=consensus")
    assert response.status_code == 200
    assert b"Distributed Consensus via Raft" in response.data


def test_search_no_results(auth_client):
    """Searching for a term with no matches provides friendly feedback."""
    response = auth_client.get("/search?q=nonexistentkeyword123")
    assert response.status_code == 200
    assert b"No woofs found matching" in response.data


def test_search_wildcard_escaping(auth_client, app, verified_user):
    """SQL wildcards % and _ are escaped and not treated as match-all."""
    with app.app_context():
        post = Woof(woof="Normal post without percent", user_id=verified_user.id)
        db.session.add(post)
        db.session.commit()

    # % should not match "Normal post without percent"
    response = auth_client.get("/search?q=%25")
    assert response.status_code == 200
    assert b"Normal post without percent" not in response.data


def test_search_unauthenticated_redirects(client):
    """Unauthenticated users attempting to search are redirected to /login."""
    response = client.get("/search?q=test")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

