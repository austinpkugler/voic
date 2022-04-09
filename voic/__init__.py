import flask


app = flask.Flask(__name__)
from voic import routes
