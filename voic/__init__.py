import flask
import flask_bcrypt
import flask_ckeditor
import flask_login
import flask_sqlalchemy
import flask_mobility
import flask_mail
import dotenv

import os

dotenv.load_dotenv()


app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db_url = os.environ.get('DATABASE_URL')
db_url = db_url.split(':')
if db_url[0] == 'postgres':
    db_url[0] = 'postgresql'
app.config['SQLALCHEMY_DATABASE_URI'] = ':'.join(db_url)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWOPRD')

mobility = flask_mobility.Mobility(app)
db = flask_sqlalchemy.SQLAlchemy(app)
bcrypt = flask_bcrypt.Bcrypt(app)
login_manager = flask_login.LoginManager(app)
mail = flask_mail.Mail(app)
ckeditor = flask_ckeditor.CKEditor(app)

from voic import routes
