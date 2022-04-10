import flask
from flask_sqlalchemy import SQLAlchemy

import os


app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voic.db'

db = SQLAlchemy(app)

from voic import routes
