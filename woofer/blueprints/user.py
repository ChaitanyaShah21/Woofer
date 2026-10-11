"""User profile blueprint: profile view and password updates."""
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash

from woofer.extensions import db
from woofer.helpers import check_password, login_required
from woofer.models import User, Woof

user_bp = Blueprint("user", __name__)


@user_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Display user profile details and handle password change."""
    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        return redirect("/login")

    woof_num = Woof.query.filter_by(user_id=session["user_id"]).count()

    if request.method == "GET":
        return render_template(
            "profile.html",
            user=user,
            woof_num=woof_num,
            error="",
            success="",
        )

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not old_password or not new_password:
        flash("Please fill both old and new passwords!", "danger")
        return redirect("/profile")

    if not check_password_hash(user.hash, old_password):
        flash("Incorrect Old Password", "danger")
        return redirect("/profile")

    if not check_password(new_password):
        flash(
            "New password must contain a minimum of 8 characters, including at least 1 uppercase and lowercase letter, at least 1 number and at least one symbol.",
            "danger",
        )
        return redirect("/profile")

    if old_password == new_password:
        flash("New password cannot be the same as the old password.", "warning")
        return redirect("/profile")

    user.hash = generate_password_hash(new_password)
    db.session.commit()
    flash("Password successfully updated!", "success")
    return redirect("/profile")

