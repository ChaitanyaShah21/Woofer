"""Tests for user profile display and password updates."""
from werkzeug.security import check_password_hash

from woofer.extensions import db
from woofer.models import User, Woof


def test_view_profile(auth_client, app, verified_user):
    """Profile page renders user details and accurate woof count."""
    with app.app_context():
        woof = Woof(woof="A test post", user_id=verified_user.id)
        db.session.add(woof)
        db.session.commit()

    response = auth_client.get("/profile")
    assert response.status_code == 200
    assert b"Alice" in response.data
    assert b"Smith" in response.data
    assert b"@alicesmith" in response.data
    assert b"1" in response.data


def test_change_password_success(auth_client, app, verified_user):
    """Changing password with valid old password updates the password hash."""
    response = auth_client.post(
        "/profile",
        data={
            "old_password": "Password123!",
            "new_password": "BrandNewPassword789$",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Password successfully updated!" in response.data

    with app.app_context():
        user = db.session.get(User, verified_user.id)
        assert check_password_hash(user.hash, "BrandNewPassword789$")


def test_change_password_wrong_old_password_fails(auth_client, verified_user):
    """Supplying an incorrect old password is rejected."""
    response = auth_client.post(
        "/profile",
        data={
            "old_password": "IncorrectPassword123!",
            "new_password": "BrandNewPassword789$",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Incorrect Old Password" in response.data


def test_change_password_same_password_fails(auth_client, verified_user):
    """Setting new password identical to old password is rejected."""
    response = auth_client.post(
        "/profile",
        data={
            "old_password": "Password123!",
            "new_password": "Password123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"New password cannot be the same" in response.data


def test_change_password_weak_new_password_fails(auth_client):
    """Setting weak new password is rejected."""
    response = auth_client.post(
        "/profile",
        data={
            "old_password": "Password123!",
            "new_password": "short",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"New password must contain a minimum of 8 characters" in response.data

