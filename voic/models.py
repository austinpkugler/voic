import flask_login

from dataclasses import dataclass

from voic import db


@dataclass
class User(db.Model, flask_login.UserMixin):
    id = db.Column(db.Integer, primary_key=True)

@dataclass
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)

@dataclass
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
