"""Security, validation, and route helper utilities."""
import re
import string
from functools import wraps

from flask import flash, redirect, session

from woofer.extensions import db
from woofer.models import User


def login_required(f):
    """Decorate routes to require login and validate session token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        session_token = session.get("session_token")

        if not user_id or not session_token:
            session.clear()
            return redirect("/login")

        user = db.session.get(User, user_id)
        if not user or user.session_token != session_token:
            # Token mismatch means password changed or session was revoked
            session.clear()
            flash("Your session has expired or your password was changed. Please log in again.", "warning")
            return redirect("/login")

        return f(*args, **kwargs)
    return decorated_function


def check_email(email: str | None) -> bool:
    """Validate email format with RFC 5322 compatible regex."""
    if not email:
        return False
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.fullmatch(regex, email.strip()))


def check_password(password: str | None) -> bool:
    """Validate password according to security policy:
    - Minimum 8 characters.
    - At least 1 lowercase letter.
    - At least 1 uppercase letter.
    - At least 1 number.
    - At least 1 symbol.
    - No whitespace.
    """
    if not password or len(password) < 8:
        return False
    if re.search(r"\s", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False

    # Allow standard punctuation characters
    symbol_pattern = f"[{re.escape(string.punctuation)}]"
    return bool(re.search(symbol_pattern, password))


def validate_name(name: str | None) -> bool:
    """Validate first or last name: letters, hyphens, spaces, apostrophes; 1-50 chars."""
    if not name:
        return False
    name = name.strip()
    if len(name) < 1 or len(name) > 50:
        return False
    return bool(re.fullmatch(r"^[A-Za-z]+([ '\-][A-Za-z]+)*$", name))
