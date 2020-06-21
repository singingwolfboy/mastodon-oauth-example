from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from sqlalchemy.ext.mutable import MutableDict
from flask_login import LoginManager, UserMixin


db = SQLAlchemy()


class MastodonServer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    users = db.relationship("User", back_populates="server")

    uri = db.Column(db.String, nullable=False, unique=True, index=True)
    client_id = db.Column(db.String)
    client_secret = db.Column(db.String)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)
    updated_at = db.Column(
        db.DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self):
        return f"<MastodonServer {self.uri}>"

    @classmethod
    def get_by_uri(cls, uri):
        return cls.query.filter_by(uri=uri).first()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey(MastodonServer.id), nullable=False)
    server = db.relationship(MastodonServer, back_populates="users")

    oauth_token = db.Column(MutableDict.as_mutable(db.JSON), nullable=False)
    username = db.Column(db.String, nullable=False)
    id_on_server = db.Column(db.String, nullable=False)
    url = db.Column(db.String)
    display_name = db.Column(db.String)
    note = db.Column(db.String)
    avatar = db.Column(db.String)
    avatar_static = db.Column(db.String)
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        db.UniqueConstraint(username, server_id),
        db.Index("idx_unique_username_per_server", username, server_id),
    )

    @property
    def server_uri(self):
        return self.server.uri

    @property
    def acct(self):
        return f"{self.username}@{self.server_uri}"

    @property
    def access_token(self):
        return self.oauth_token["access_token"]

    def __repr__(self):
        return f"<User {self.acct}>"


# setup login manager
login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
