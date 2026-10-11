"""Tests for user registration, authentication, verification, and password reset."""
from werkzeug.security import check_password_hash, generate_password_hash

from woofer.extensions import db
from woofer.models import User
from woofer.services.email import get_serializer, outbox


def test_register_success(client, app):
    """Registering a new account succeeds and dispatches a verification email."""
    response = client.post(
        "/register",
        data={
            "firstName": "John",
            "lastName": "Doe",
            "username": "johndoe",
            "registerEmail": "john@example.com",
            "password": "SecurePassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(username="johndoe").first()
        assert user is not None
        assert user.firstName == "John"
        assert user.lastName == "Doe"
        assert user.email == "john@example.com"
        assert user.is_verified is False
        assert check_password_hash(user.hash, "SecurePassword123!")

    assert len(outbox) == 1
    assert "Verify your Woofer Account" in outbox[0]["subject"]
    assert "john@example.com" in outbox[0]["recipients"]


def test_register_duplicate_username_fails(client, verified_user):
    """Attempting to register an existing username fails."""
    response = client.post(
        "/register",
        data={
            "firstName": "Another",
            "lastName": "User",
            "username": verified_user.username,
            "registerEmail": "different@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert response.status_code == 200
    assert b"Username already taken!" in response.data


def test_register_duplicate_email_fails(client, verified_user):
    """Attempting to register an existing email address fails."""
    response = client.post(
        "/register",
        data={
            "firstName": "Another",
            "lastName": "User",
            "username": "newusername",
            "registerEmail": verified_user.email,
            "password": "SecurePassword123!",
        },
    )
    assert response.status_code == 200
    assert b"Email already linked" in response.data


def test_register_weak_password_fails(client):
    """Passwords not meeting complexity standards are rejected."""
    # Under 8 chars
    response = client.post(
        "/register",
        data={
            "firstName": "John",
            "lastName": "Doe",
            "username": "shortpass",
            "registerEmail": "short@example.com",
            "password": "Pass1!",
        },
    )
    assert response.status_code == 200
    assert b"is-invalid" in response.data

    # Missing special character
    response = client.post(
        "/register",
        data={
            "firstName": "John",
            "lastName": "Doe",
            "username": "nosymbol",
            "registerEmail": "nosymbol@example.com",
            "password": "Password1234",
        },
    )
    assert response.status_code == 200
    assert b"is-invalid" in response.data


def test_confirm_email_success(client, app):
    """Confirming email with valid signed token marks user as verified."""
    with app.app_context():
        user = User(
            firstName="Bob",
            lastName="Taylor",
            username="bobtaylor",
            email="bob@example.com",
            hash=generate_password_hash("Password123!"),
            is_verified=False,
        )
        db.session.add(user)
        db.session.commit()

        serializer = get_serializer(app.secret_key)
        token = serializer.dumps(user.email, salt="email-confirm")

    response = client.get(f"/confirm/{token}", follow_redirects=True)
    assert response.status_code == 200
    assert b"Email verified successfully!" in response.data

    with app.app_context():
        updated_user = User.query.filter_by(username="bobtaylor").first()
        assert updated_user.is_verified is True


def test_confirm_email_invalid_token(client):
    """Invalid or tampered confirmation token returns HTTP 400."""
    response = client.get("/confirm/invalid-token-string")
    assert response.status_code == 400
    assert b"invalid or expired" in response.data


def test_login_success(client, verified_user):
    """Verified user with valid credentials logs in successfully."""
    response = client.post(
        "/login",
        data={
            "username": verified_user.username,
            "password": "Password123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("user_id") == verified_user.id


def test_login_unverified_rejected(client, app):
    """Unverified user cannot log in and receives warning message."""
    with app.app_context():
        user = User(
            firstName="Eve",
            lastName="Adams",
            username="eveadams",
            email="eve@example.com",
            hash=generate_password_hash("Password123!"),
            is_verified=False,
        )
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/login",
        data={
            "username": "eveadams",
            "password": "Password123!",
        },
    )
    assert response.status_code == 200
    assert b"Email not verified" in response.data
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_login_invalid_credentials(client, verified_user):
    """Invalid password is rejected."""
    response = client.post(
        "/login",
        data={
            "username": verified_user.username,
            "password": "WrongPassword123!",
        },
    )
    assert response.status_code == 200
    assert b"Invalid username and/or password" in response.data


def test_logout(client, auth_client):
    """Logging out clears user session."""
    response = client.get("/logout", follow_redirects=True)
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_password_reset_workflow(client, app, verified_user):
    """Complete password reset workflow: request, token verification, update."""
    # 1. Request reset link
    response = client.post(
        "/forgot-password",
        data={"email": verified_user.email},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert len(outbox) == 1
    assert "Woofer Password Reset" in outbox[0]["subject"]

    # 2. Extract token from outbox link
    body = outbox[0]["body"]
    token = body.split("/reset-password/")[1].split()[0]

    # 3. Submit new password
    reset_response = client.post(
        f"/reset-password/{token}",
        data={
            "new_password": "NewSecurePassword456!",
            "confirm_password": "NewSecurePassword456!",
        },
        follow_redirects=True,
    )
    assert reset_response.status_code == 200
    assert b"Password successfully reset!" in reset_response.data

    # 4. Confirm new password works
    with app.app_context():
        user = db.session.get(User, verified_user.id)
        assert check_password_hash(user.hash, "NewSecurePassword456!")

    # 5. Token replay protection: reusing the token fails
    replay_response = client.get(f"/reset-password/{token}")
    assert replay_response.status_code in (400, 403)

