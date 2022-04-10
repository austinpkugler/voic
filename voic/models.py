'''
User-Document many-to-many
Document-Role many-to-many
User-Role one-to-many

'''
import flask_login
from flask_sqlalchemy import SQLAlchemy

from dataclasses import dataclass
from datetime import datetime

from voic import db


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


@dataclass
class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    documents = db.relationship('Document', backref='role', secondary=roles_documents)

    def __repr__(self):
        return f'Role(id={self.id}, title={self.title})'


@dataclass
class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'Document(id={self.id}, title={self.title})'
