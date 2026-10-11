"""Woofs blueprint: posting, feeds, eager loading, pagination, and deletion."""
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
)

from woofer.extensions import db
from woofer.helpers import login_required
from woofer.models import User, Woof

woofs_bp = Blueprint("woofs", __name__)


@woofs_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Main feed displaying all woofs with eager loading and pagination."""
    error = ""
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("WOOFS_PER_PAGE", 20)

    if request.method == "POST":
        woof_content = request.form.get("send-woof", "").strip()
        if not woof_content:
            error = "You cannot send a blank WOOF!"
        elif len(woof_content) > 280:
            error = "Your WOOF cannot exceed 280 characters!"
        else:
            new_woof = Woof(woof=woof_content, user_id=session["user_id"])
            db.session.add(new_woof)
            db.session.commit()
            return redirect("/")

    # Eager load author to prevent N+1 query problem and paginate
    pagination = (
        Woof.query.options(db.joinedload(Woof.author))
        .order_by(Woof.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    woof_data = [
        {
            "id": item.id,
            "woof": item.woof,
            "timestamp": item.timestamp.isoformat(),
            "username": item.author.username,
            "firstName": item.author.firstName,
            "lastName": item.author.lastName,
        }
        for item in pagination.items
    ]

    return render_template(
        "index.html",
        error=error,
        woof_data=woof_data,
        pagination=pagination,
    )


@woofs_bp.route("/my-woofs", methods=["GET"])
@login_required
def my_woofs():
    """Display authenticated user's own woofs with pagination."""
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("WOOFS_PER_PAGE", 20)

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        return redirect("/login")

    pagination = (
        Woof.query.filter_by(user_id=user.id)
        .order_by(Woof.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    woof_data = [
        {
            "id": item.id,
            "woof": item.woof,
            "timestamp": item.timestamp.isoformat(),
            "username": user.username,
            "firstName": user.firstName,
            "lastName": user.lastName,
        }
        for item in pagination.items
    ]

    return render_template(
        "my_woofs.html",
        woof_data=woof_data,
        pagination=pagination,
    )


@woofs_bp.route("/delete-woof", methods=["POST"])
@login_required
def delete_woof():
    """Delete a woof owned by the current user."""
    raw_woof_id = request.form.get("woof_id")
    try:
        woof_id = int(raw_woof_id)
    except (TypeError, ValueError):
        flash("Invalid woof ID", "danger")
        return redirect("/my-woofs")

    woof = db.session.get(Woof, woof_id)
    if woof and woof.user_id == session["user_id"]:
        db.session.delete(woof)
        db.session.commit()
        flash("Woof deleted successfully!", "success")
    else:
        flash("Woof doesnt exist or You are not authorized to delete this woof", "danger")

    return redirect("/my-woofs")


@woofs_bp.route("/search", methods=["GET"])
@login_required
def search():
    """Search woofs by keyword, hashtag, or author username with pagination."""
    raw_query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("WOOFS_PER_PAGE", 20)

    if not raw_query:
        return render_template(
            "search.html",
            query="",
            woof_data=[],
            pagination=None,
        )

    search_term = raw_query.lstrip("@")
    escaped_term = search_term.replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped_term}%"

    pagination = (
        Woof.query.join(User, Woof.user_id == User.id)
        .options(db.contains_eager(Woof.author))
        .filter(
            db.or_(
                Woof.woof.ilike(pattern),
                User.username.ilike(pattern),
            )
        )
        .order_by(Woof.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    woof_data = [
        {
            "id": item.id,
            "woof": item.woof,
            "timestamp": item.timestamp.isoformat(),
            "username": item.author.username,
            "firstName": item.author.firstName,
            "lastName": item.author.lastName,
        }
        for item in pagination.items
    ]

    return render_template(
        "search.html",
        query=raw_query,
        woof_data=woof_data,
        pagination=pagination,
    )
