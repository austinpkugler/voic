import flask
import flask_login
import PIL

import os
import secrets

from voic import app, db, bcrypt, forms, models


def save_picture(picture_data):
    random_hex = secrets.token_hex(8)
    _, filetype = os.path.splitext(picture_data.filename)
    picture = random_hex + filetype
    path = os.path.join(app.root_path, 'static', 'img', picture)
    output_size = (125, 125)
    image = PIL.Image.open(picture_data)
    image.thumbnail(output_size)
    image.save(path)
    return picture


@app.route('/')
@app.route('/home')
def home():
    return flask.render_template('home.html', title='Virtual Office in the Cloud')


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    form = forms.SignUpForm()
    if form.validate_on_submit():
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = models.User(username=form.username.data, email=form.email.data, password=password_hash)
        db.session.add(user)
        db.session.commit()
        flask.flash(f'Your account was created! You can now sign in.', 'success')
        return flask.redirect(flask.url_for('sign_in'))

    return flask.render_template('forms/sign-up.html', title='Sign Up', form=form)


@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    if flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    form = forms.SignInForm()
    if form.validate_on_submit():
        user = models.User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            flask_login.login_user(user, remember=form.remember.data)
            next_page = flask.request.args.get('next')
            return flask.redirect(next_page) if next_page else flask.redirect(flask.url_for('home'))
        else:
            flask.flash(f'Incorrect email or password.', 'danger')

    return flask.render_template('forms/sign-in.html', title='Sign In', form=form)


@app.route('/sign-out')
def sign_out():
    flask_login.logout_user()
    return flask.redirect(flask.url_for('home'))


@app.route('/account')
@flask_login.login_required
def account():
    form = forms.UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture = save_picture(form.picture.data)
            flask_login.current_user.picture = picture

        flask_login.current_user.username = form.username.data
        flask_login.current_user.email = form.email.data
        db.session.commit()
        flask.flash('Your account has been updated!', 'success')
        return flask.redirect(flask.url_for('account'))
    elif flask.request.method == 'GET':
        form.username.data = flask_login.current_user.username
        form.email.data = flask_login.current_user.email

    picture = flask.url_for('static', filename=os.path.join('assets', flask_login.current_user.picture))
    return flask.render_template('forms/account.html', title='Account', picture=picture, form=form)


@app.route('/new-document')
@flask_login.login_required
def new_document():
    return flask.render_template('forms/new-document.html')


@app.route('/edit-document')
@flask_login.login_required
def edit_document():
    return flask.render_template('forms/edit-document.html')
