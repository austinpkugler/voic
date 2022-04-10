import flask_login
import flask_wtf
from flask_ckeditor import CKEditorField
from flask_wtf.file import (
    FileField,
    FileAllowed
)
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
    ValidationError
)

from voic import models


class SignUpForm(flask_wtf.FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
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
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class UpdateAccountForm(flask_wtf.FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])

    all_role_titles = []
    for role in models.Role.query.all():
        all_role_titles.append((role.id, role.title))

    roles = SelectMultipleField('Select All Roles', choices=all_role_titles, coerce=int)
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != flask_login.current_user.username:
            user = models.User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exists.')

    def validate_email(self, email):
        if email.data != flask_login.current_user.email:
            user = models.User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already exists.')


class DocumentForm(flask_wtf.FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Content', validators=[DataRequired()])
    submit = SubmitField('Create')
