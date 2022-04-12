import flask
import flask_bcrypt
import flask_ckeditor
import flask_login
import flask_sqlalchemy

import logging
import os


logger = logging.getLogger(__name__)
FORMAT = "[ %(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voic.db'
db = flask_sqlalchemy.SQLAlchemy(app)
bcrypt = flask_bcrypt.Bcrypt(app)
login_manager = flask_login.LoginManager(app)
ckeditor = flask_ckeditor.CKEditor(app)

from voic import routes

logger.debug(f'Flask app was successfully initialized')
