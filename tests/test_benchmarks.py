"""Repeatable benchmark and performance verification tests."""
from sqlalchemy import event, inspect
from werkzeug.security import generate_password_hash

from woofer.extensions import db
from woofer.models import User, Woof


def test_feed_query_count(auth_client, app):
    """Verify elimination of N+1 query problem: fetching feed executes a single joined query."""
    # Seed 50 posts across 20 distinct users
    with app.app_context():
        users = []
        for i in range(20):
            u = User(
                firstName=f"User{i}",
                lastName="Test",
                username=f"benchuser{i}",
                email=f"bench{i}@example.com",
                hash=generate_password_hash("Password123!"),
                is_verified=True,
            )
            users.append(u)
        db.session.add_all(users)
        db.session.commit()

        posts = []
        for i in range(50):
            p = Woof(
                woof=f"Benchmark test post #{i}",
                user_id=users[i % 20].id,
            )
            posts.append(p)
        db.session.add_all(posts)
        db.session.commit()

    # Track executed queries during feed render
    queries = []

    def count_queries(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    event.listen(db.engine, "before_cursor_execute", count_queries)
    try:
        response = auth_client.get("/")
        assert response.status_code == 200
        # Up to 3 queries: 1 for session token validation, 1 for joined posts+authors, and 1 for pagination COUNT(*)
        # Previously without eager loading and pagination: 1 (posts) + 50 (author N+1 queries) = 51 queries
        assert len(queries) <= 3, f"Expected <= 3 queries, but {len(queries)} executed:\n" + "\n".join(queries)
    finally:
        event.remove(db.engine, "before_cursor_execute", count_queries)


def test_pagination_limit(auth_client, app, verified_user):
    """Verify pagination restricts record loading to per_page limit."""
    with app.app_context():
        posts = [
            Woof(woof=f"Pagination post #{i}", user_id=verified_user.id)
            for i in range(35)
        ]
        db.session.add_all(posts)
        db.session.commit()

    # Page 1 should contain 20 items
    resp1 = auth_client.get("/?page=1")
    assert resp1.status_code == 200
    assert resp1.data.count(b"Pagination post #") == 20

    # Page 2 should contain the remaining 15 items
    resp2 = auth_client.get("/?page=2")
    assert resp2.status_code == 200
    assert resp2.data.count(b"Pagination post #") == 15


def test_indexes_exist(app):
    """Verify required performance indexes exist on User and Woof models."""
    with app.app_context():
        inspector = inspect(db.engine)
        user_indexes = [idx["name"] for idx in inspector.get_indexes("users")]
        woof_indexes = [idx["name"] for idx in inspector.get_indexes("woofs")]

        # Email index on users
        assert any("email" in str(idx).lower() for idx in user_indexes)

        # Timestamp and user_timestamp indexes on woofs
        assert any("timestamp" in str(idx).lower() for idx in woof_indexes)
        assert any("user_timestamp" in str(idx).lower() for idx in woof_indexes)

