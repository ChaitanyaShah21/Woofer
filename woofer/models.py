"""Database models for Woofer application."""
from datetime import UTC, datetime

from woofer.extensions import db


class User(db.Model):
    """User account model matching production schema."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.Text, nullable=False)
    lastName = db.Column(db.Text, nullable=False)
    username = db.Column(db.Text, nullable=False, unique=True, index=True)
    hash = db.Column(db.Text, nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reset_token_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC)
    )
    followers = db.Column(db.Integer, nullable=False, default=0)
    following = db.Column(db.Integer, nullable=False, default=0)
    email = db.Column(db.String(320), nullable=False, index=True)

    woofs = db.relationship(
        'Woof',
        backref='author',
        lazy=True,
        cascade='all, delete-orphan'
    )

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Woof(db.Model):
    """Microblogging post model matching production schema."""
    __tablename__ = 'woofs'

    id = db.Column(db.Integer, primary_key=True)
    woof = db.Column(db.Text, nullable=False)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    __table_args__ = (
        db.Index('idx_woofs_user_timestamp', 'user_id', 'timestamp'),
    )

    def __repr__(self) -> str:
        return f"<Woof {self.id} by User {self.user_id}>"
