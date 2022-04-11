import flask
import flask_login
import markupsafe
from PIL import Image

from datetime import datetime, timezone
import os
import secrets

from voic import app, db, bcrypt, forms, models


def save_picture(picture_data):
    random_hex = secrets.token_hex(8)
    _, filetype = os.path.splitext(picture_data.filename)
    picture = random_hex + filetype
    path = os.path.join(app.root_path, 'static', 'img', picture)
    output_size = (125, 125)
    image = Image.open(picture_data)
    image.thumbnail(output_size)
    image.save(path)
    return picture


@app.route('/')
@app.route('/home')
def home():
    if flask_login.current_user.is_authenticated:
        documents = flask_login.current_user.documents
        for role in flask_login.current_user.roles:
            documents += role.documents
        documents.sort(key=lambda d: d.updated_at, reverse=True)
        return flask.render_template('home.html', title='Virtual Office in the Cloud', documents=documents)
    else:
        return flask.render_template('home.html', title='Virtual Office in the Cloud')


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    form = forms.SignUpForm()
    if form.validate_on_submit():
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = models.User(username=form.username.data, email=form.email.data, password=password_hash)
        user.roles = [models.Role.query.filter_by(title='employee').first()]
        db.session.add(user)
        db.session.commit()
        flask.flash(f'Your account was created! You may now sign in.', 'success')
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
@flask_login.login_required
def sign_out():
    flask_login.logout_user()
    flask.flash('You have been signed out!', 'success')
    return flask.redirect(flask.url_for('home'))


@app.route('/account', methods=['GET', 'POST'])
@flask_login.login_required
def account():
    form = forms.UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture = save_picture(form.picture.data)
            flask_login.current_user.picture = picture

        flask_login.current_user.username = form.username.data
        flask_login.current_user.email = form.email.data

        flask_login.current_user.roles = [models.Role.query.filter_by(title='employee').first()]
        for role_id in form.roles.data:
            role = models.Role.query.filter_by(id=role_id).first()
            flask_login.current_user.roles.append(role)

        db.session.commit()

        flask.flash('Your account has been updated!', 'success')
        return flask.redirect(flask.url_for('account'))
    elif flask.request.method == 'GET':
        selected_role_ids = []
        for role in flask_login.current_user.roles:
            selected_role_ids.append(role.id)

        form.roles.default = selected_role_ids
        form.process()
        form.username.data = flask_login.current_user.username
        form.email.data = flask_login.current_user.email
    picture = flask.url_for('static', filename=os.path.join('img', flask_login.current_user.picture))
    return flask.render_template('forms/account.html', title='Account', picture=picture, form=form)


@app.route('/new-document', methods=['GET', 'POST'])
@flask_login.login_required
def new_document():
    form = forms.DocumentForm()
    if form.validate_on_submit():
        document = models.Document(title=form.title.data, content=form.content.data, creator_id=flask_login.current_user.id)
        db.session.add(document)
        flask_login.current_user.documents.append(document)
        db.session.commit()
        flask.flash('Your document was created!', 'success')
        return flask.redirect(flask.url_for('home'))
    return flask.render_template('forms/new-document.html', title='New Document', form=form)


@app.route('/edit-document/<int:document_id>', methods=['GET', 'POST'])
@flask_login.login_required
def edit_document(document_id):
    document = models.Document.query.get(document_id)
    if flask_login.current_user not in document.user:
        if not set(flask_login.current_user.role).intersection(document.role):
            flask.flash('You do not have the permissions to edit this document.', 'danger')
            return flask.redirect(flask.url_for('home'))

    form = forms.DocumentForm()
    if form.validate_on_submit():
        document.title = form.title.data
        document.content = markupsafe.Markup(form.content.data)
        document.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        flask.flash('Your document was edited!', 'success')
        return flask.redirect(flask.url_for('home'))
    elif flask.request.method == 'GET':
        form.title.data = document.title
        form.content.data = document.content
    return flask.render_template('forms/edit-document.html', title='Edit Document', form=form)


@app.route('/delete-document/<int:document_id>')
@flask_login.login_required
def delete_document(document_id):
    db.session.delete(models.Document.query.get(document_id))
    db.session.commit()
    flask.flash('Document was deleted!', 'success')
    return flask.redirect(flask.url_for('home'))
