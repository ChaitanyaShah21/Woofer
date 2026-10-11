import secrets

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
)
from itsdangerous import BadSignature, SignatureExpired
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from woofer.extensions import db, limiter
from woofer.helpers import check_email, check_password, validate_name
from woofer.models import User
from woofer.services.email import (
    get_serializer,
    send_password_reset_email,
    send_verification_email,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def register():
    """Register a new user account."""
    session.clear()
    if request.method == "GET":
        register_data = {
            "fname": "",
            "first_name": "",
            "lname": "",
            "last_name": "",
            "uname": "",
            "username": "",
            "uname_error": "Required.",
            "mail": "",
            "email": "",
            "email_error": "Please enter a valid email address.",
            "pword": "",
            "password": "",
        }
        return render_template("register.html", data=register_data)

    first_name = request.form.get("firstName", "").strip()
    last_name = request.form.get("lastName", "").strip()
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("registerEmail", "").strip().lower()
    password = request.form.get("password", "")

    fname = "is-valid" if validate_name(first_name) else "is-invalid"
    lname = "is-valid" if validate_name(last_name) else "is-invalid"

    uname_error = ""
    if not username or len(username) > 30:
        uname = "is-invalid"
        uname_error = "Username must be 1 to 30 characters."
    else:
        existing_user = User.query.filter(func.lower(User.username) == username).first()
        if existing_user:
            uname = "is-invalid"
            uname_error = "Username already taken!"
        else:
            uname = "is-valid"

    email_error = ""
    if not check_email(email):
        mail_status = "is-invalid"
        email_error = "Please enter a valid email address."
    else:
        existing_email = User.query.filter(func.lower(User.email) == email).first()
        if existing_email:
            mail_status = "is-invalid"
            email_error = "Email already linked to an existing account."
        else:
            mail_status = "is-valid"

    pword = "is-valid" if check_password(password) else "is-invalid"

    register_data = {
        "fname": fname,
        "first_name": first_name,
        "lname": lname,
        "last_name": last_name,
        "uname": uname,
        "username": username,
        "uname_error": uname_error,
        "mail": mail_status,
        "email_error": email_error,
        "email": email,
        "pword": pword,
        "password": password,
    }

    if any(status == "is-invalid" for status in (fname, lname, uname, mail_status, pword)):
        return render_template("register.html", data=register_data)

    password_hash = generate_password_hash(password)
    new_user = User(
        firstName=first_name,
        lastName=last_name,
        username=username,
        email=email,
        hash=password_hash,
    )
    db.session.add(new_user)
    try:
        # 1. Commit FIRST to guarantee transactional atomicity
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        err_str = str(e.orig).lower() if hasattr(e, "orig") else str(e).lower()

        # Identify which unique constraint failed
        if "username" in err_str:
            register_data["uname"] = "is-invalid"
            register_data["uname_error"] = "Username already taken!"
        elif "email" in err_str:
            register_data["mail"] = "is-invalid"
            register_data["email_error"] = "Email already linked to an existing account."
        else:
            register_data["uname"] = "is-invalid"
            register_data["uname_error"] = "Account with these details already exists."

        return render_template("register.html", data=register_data)
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Unexpected error during account persistence")
        flash("Could not create account due to a server error. Please try again.", "danger")
        return redirect("/register")

    # 2. ONLY dispatch verification email AFTER transaction successfully commits
    try:
        send_verification_email(new_user)
    except Exception:
        current_app.logger.exception("Failed to dispatch verification email to %s", new_user.email)
        flash(
            "Account created, but verification email could not be sent. Please use 'Resend verification'.",
            "warning",
        )
        return redirect("/login")

    flash("Verification link sent to your email.", "info")
    return redirect("/login")


@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    """Confirm user email address from emailed link."""
    serializer = get_serializer()
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)
    except (SignatureExpired, BadSignature):
        return "Confirmation link is invalid or expired.", 400

    user = User.query.filter(func.lower(User.email) == email.lower()).first()
    if not user:
        return "user not found", 404

    user.is_verified = True
    db.session.commit()
    flash("Email verified successfully!", "success")
    return redirect("/login")


@auth_bp.route("/resend-verification", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def resend_verification():
    """Resend verification link to an unverified account."""
    if request.method == "GET":
        return render_template("resend_verification.html", email="")

    email = request.form.get("email", "").strip().lower()
    if not check_email(email):
        flash("Please enter a valid email address.", "danger")
        return render_template("resend_verification.html", email=email), 400

    user = User.query.filter(func.lower(User.email) == email).first()
    if user and not user.is_verified:
        try:
            send_verification_email(user)
        except Exception:
            current_app.logger.exception("Unable to resend verification email")
            flash("The verification email could not be sent. Please try again later.", "danger")
            return redirect("/login")

    flash("If the account is unverified, a new verification link has been sent.", "info")
    return redirect("/login")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """Log in existing user."""
    if request.method == "GET":
        return render_template("login.html", error="")

    session.clear()
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    if not username or not password:
        error = "Please enter a username and password."
        return render_template("login.html", error=error)

    user = User.query.filter(func.lower(User.username) == username).first()
    if not user or not check_password_hash(user.hash, password):
        error = "Invalid username and/or password"
        return render_template("login.html", error=error)

    if not user.is_verified:
        error = "Email not verified. Check your inbox for verification mail"
        return render_template("login.html", error=error)

    # Purge pre-authentication session (fixes session fixation)
    session.clear()
    session["user_id"] = user.id
    session["session_token"] = user.session_token
    session.permanent = True
    return redirect("/")


@auth_bp.route("/logout")
def logout():
    """Log user out and clear session."""
    session.clear()
    return redirect("/")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def forgot_password():
    """Request a password reset link via email."""
    error = ""
    email = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            error = "Please enter your email."
        elif not check_email(email):
            error = "Invalid email address."

        if error:
            return render_template("forgot_password.html", error=error, email=email)

        user = User.query.filter(func.lower(User.email) == email).first()
        if user:
            user.reset_token_used = False
            db.session.commit()
            send_password_reset_email(user)

        flash("If the email exists, a reset link has been sent.", "info")
        return redirect("/login")

    return render_template("forgot_password.html", error=error, email=email)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Reset user password using token."""
    serializer = get_serializer()
    try:
        payload = serializer.loads(token, salt="reset-password", max_age=3600)
    except (SignatureExpired, BadSignature):
        return "Invalid or expired token", 400

    # Support dictionary payload (new secure) or legacy string payload (email)
    if isinstance(payload, dict):
        email = payload.get("email", "").lower()
        hash_prefix = payload.get("hash_prefix")
    else:
        email = str(payload).lower()
        hash_prefix = None

    user = User.query.filter(func.lower(User.email) == email).first()
    if not user:
        return "Invalid user", 404

    # If payload is bound to password hash and hash has changed, reject token
    if hash_prefix and not user.hash.startswith(hash_prefix):
        return "Invalid or expired token", 400

    if user.reset_token_used:
        return "This reset link has already been used.", 403

    error = ""
    confirm_error = ""
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password:
            error = "Please enter a new password"
        elif not check_password(new_password):
            error = (
                "Password must be at least 8 characters with 1 each of uppercase, "
                "lowercase, number and symbol."
            )
        elif check_password_hash(user.hash, new_password):
            error = "New password cannot be the same as the old password."

        if not confirm_password or confirm_password != new_password:
            confirm_error = "Passwords do not match."

        if error or confirm_error:
            return render_template(
                "reset_password.html",
                token=token,
                error=error,
                confirm_error=confirm_error,
            )

        user.hash = generate_password_hash(new_password)
        user.session_token = secrets.token_hex(32)  # Invalidate all active sessions
        user.reset_token_used = True
        db.session.commit()
        flash("Password successfully reset!", "success")
        return redirect("/login")

    return render_template("reset_password.html", token=token, error=error)

