"""Tests for post creation, feed display, pagination, and post deletion authorization."""
from werkzeug.security import generate_password_hash

from woofer.extensions import db
from woofer.models import User, Woof


def test_post_woof_success(auth_client, app, verified_user):
    """Authenticated user creates a woof; post is saved and displayed on feed."""
    response = auth_client.post(
        "/",
        data={"send-woof": "Hello Woofer community! #firstwoof"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Hello Woofer community! #firstwoof" in response.data

    with app.app_context():
        woof = Woof.query.filter_by(user_id=verified_user.id).first()
        assert woof is not None
        assert woof.woof == "Hello Woofer community! #firstwoof"
        assert woof.timestamp is not None


def test_post_woof_empty_fails(auth_client):
    """Blank or whitespace-only posts are rejected."""
    response = auth_client.post(
        "/",
        data={"send-woof": "   "},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"cannot send a blank WOOF" in response.data


def test_post_woof_too_long_fails(auth_client):
    """Posts exceeding 280 characters are rejected."""
    long_text = "w" * 281
    response = auth_client.post(
        "/",
        data={"send-woof": long_text},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"cannot exceed 280 characters" in response.data


def test_unauthenticated_post_redirects_to_login(client):
    """Unauthenticated users attempting to post are redirected to /login."""
    response = client.post(
        "/",
        data={"send-woof": "Unauthorized post"},
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_my_woofs_displays_user_posts_only(auth_client, app, verified_user):
    """The /my-woofs page displays only the current user's posts."""
    with app.app_context():
        # Create other user with a post
        other_user = User(
            firstName="Other",
            lastName="User",
            username="otheruser",
            email="other@example.com",
            hash=generate_password_hash("Password123!"),
            is_verified=True,
        )
        db.session.add(other_user)
        db.session.commit()

        my_post = Woof(woof="My personal woof", user_id=verified_user.id)
        other_post = Woof(woof="Someone else's post", user_id=other_user.id)
        db.session.add_all([my_post, other_post])
        db.session.commit()

    response = auth_client.get("/my-woofs")
    assert response.status_code == 200
    assert b"My personal woof" in response.data
    assert b"Someone else's post" not in response.data


def test_delete_own_woof_success(auth_client, app, verified_user):
    """Author can delete their own post."""
    with app.app_context():
        woof = Woof(woof="To be deleted", user_id=verified_user.id)
        db.session.add(woof)
        db.session.commit()
        woof_id = woof.id

    response = auth_client.post(
        "/delete-woof",
        data={"woof_id": woof_id},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Woof deleted successfully!" in response.data

    with app.app_context():
        assert db.session.get(Woof, woof_id) is None


def test_delete_other_user_woof_forbidden(auth_client, app):
    """User B cannot delete User A's post (server-side authorization enforcement)."""
    with app.app_context():
        author = User(
            firstName="Victim",
            lastName="Author",
            username="victimauthor",
            email="victim@example.com",
            hash=generate_password_hash("Password123!"),
            is_verified=True,
        )
        db.session.add(author)
        db.session.commit()

        victim_post = Woof(woof="Protected content", user_id=author.id)
        db.session.add(victim_post)
        db.session.commit()
        victim_post_id = victim_post.id

    # auth_client is logged in as verified_user, not victim author
    response = auth_client.post(
        "/delete-woof",
        data={"woof_id": victim_post_id},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"not authorized to delete this woof" in response.data

    # Verify post was not deleted
    with app.app_context():
        post = db.session.get(Woof, victim_post_id)
        assert post is not None
        assert post.woof == "Protected content"


def test_delete_invalid_woof_id_handled_gracefully(auth_client):
    """Submitting malformed or non-existent woof_id does not crash the server."""
    response = auth_client.post(
        "/delete-woof",
        data={"woof_id": "not-an-id"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Invalid woof ID" in response.data

