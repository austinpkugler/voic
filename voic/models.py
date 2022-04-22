import flask_login
from itsdangerous import URLSafeTimedSerializer as TimedSerializer

from dataclasses import dataclass
from datetime import datetime

from voic import app, db, login_manager


users_documents = db.Table(
    'users_documents',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('document_id', db.Integer, db.ForeignKey('document.id'))
)
users_roles = db.Table(
    'users_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)
roles_documents = db.Table(
    'roles_documents',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
    db.Column('document_id', db.Integer, db.ForeignKey('document.id'))
)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@dataclass
class User(db.Model, flask_login.UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    picture = db.Column(db.String(20), nullable=False, default='default.jpg')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    roles = db.relationship('Role', backref='user', secondary=users_roles)
    documents = db.relationship('Document', backref='user', secondary=users_documents)

    def __repr__(self):
        return f'User(id={self.id}, username={self.username})'

    def get_reset_token(self):
        serializer = TimedSerializer(app.config['SECRET_KEY'])
        return serializer.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_in=900):
        serializer = TimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = serializer.loads(token, expires_in)['user_id']
        except:
            return None
        return User.query.get(user_id)


@dataclass
class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    documents = db.relationship('Document', backref='role', secondary=roles_documents)

    def __repr__(self):
        return f'Role(id={self.id}, title={self.title})'

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash(('id', self.id))


@dataclass
class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(320), nullable=False)
    content = db.Column(db.Text)
    graph = db.Column(db.String(320))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'Document(id={self.id}, title={self.title})'

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash(('id', self.id))
