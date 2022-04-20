import flask_wtf
from flask_ckeditor import CKEditorField
from flask_login import current_user
from flask_wtf.file import FileField, FileAllowed
from wtforms import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    SelectMultipleField
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Regexp,
    ValidationError
)

from voic import models


VALID_USERNAME = [DataRequired(), Length(min=1, max=32), Regexp(r'^[\w.@+-]+$')]
VALID_EMAIL = [DataRequired(), Email(), Length(min=5, max=320)]
VALID_PASSWORD = [DataRequired(), Length(min=1, max=32)]
VALID_TITLE = [DataRequired(), Length(min=1, max=320)]
VALID_CONTENT = [Length(min=0, max=32000)]
VALID_GRAPH = [Length(min=0, max=320), Regexp(r'^([A-Za-z0-9]+-[A-Za-z0-9]+(,|, ))*([A-Za-z0-9]+-[A-Za-z0-9]+)$|^$')]
VALID_SEARCH = [Length(min=0, max=320), Regexp(r'(^(?!graph:).*$)|(^graph:([A-Za-z0-9]+-[A-Za-z0-9]+(,|, ))*([A-Za-z0-9]+-[A-Za-z0-9]+)$)')]


class SearchForm(flask_wtf.FlaskForm):
    search_bar = StringField('Search Documents', validators=VALID_SEARCH)
    submit = SubmitField('Search')


class SignUpForm(flask_wtf.FlaskForm):
    username = StringField('Username', validators=VALID_USERNAME)
    email = StringField('Email', validators=VALID_EMAIL)
    password = PasswordField('Password', validators=VALID_PASSWORD)
    confirm_password = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = models.User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        user = models.User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists.')


class SignInForm(flask_wtf.FlaskForm):
    email = StringField('Email', validators=VALID_EMAIL)
    password = PasswordField('Password', validators=VALID_PASSWORD)
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class UpdateAccountForm(flask_wtf.FlaskForm):
    username = StringField('Username', validators=VALID_USERNAME)
    email = StringField('Email', validators=VALID_EMAIL)
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])

    roles = SelectMultipleField('Select your roles.*', choices=[], coerce=int)
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = models.User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exists.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = models.User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already exists.')


class DocumentForm(flask_wtf.FlaskForm):
    title = StringField('Title', validators=VALID_TITLE)
    content = CKEditorField('Content', validators=VALID_CONTENT)
    graph = StringField('Graph', validators=VALID_GRAPH)
    submit = SubmitField('Save')

    _role_field_text = 'Select roles that can read, edit, and delete this document.*'
    roles = SelectMultipleField(_role_field_text, choices=[], coerce=int)

    _user_field_text = 'Select users that can read, edit, and delete this document.'
    users = SelectMultipleField(_user_field_text, choices=[], coerce=int)


class RequestPasswordResetForm(flask_wtf.FlaskForm):
    email = StringField('Email', validators=VALID_EMAIL)
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = models.User.query.filter_by(email=email.data).first()
        if not user:
            raise ValidationError('No account could be found for that email address.')


class ResetPasswordForm(flask_wtf.FlaskForm):
    password = PasswordField('Password', validators=VALID_PASSWORD)
    confirm_password = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
