import flask
import flask_mail
import flask_login
import markupsafe
import sqlalchemy
from bs4 import BeautifulSoup
from flask_login import current_user
from PIL import Image

from datetime import datetime, timezone
import os
import secrets

from voic import app, db, bcrypt, mail, models


def save_picture(picture_data):
    random_hex = secrets.token_hex(8)
    _, filetype = os.path.splitext(picture_data.filename)
    picture = random_hex + filetype
    path = os.path.join(app.root_path, 'static', 'img', 'profile', picture)
    output_size = (125, 125)
    image = Image.open(picture_data)
    image.thumbnail(output_size)
    image.save(path)
    return picture


def send_reset_password_email(user):
    token = user.get_reset_token()
    email_sender = os.environ.get('EMAIL_USERNAME')
    msg = flask_mail.Message('Password Reset Request', sender=email_sender, recipients=[user.email])
    msg.body = f'''Please reset your password by visting the following link:
{flask.url_for('reset_password', token=token, _external=True)}

Ignore this email if you did not request a password reset.
'''
    mail.send(msg)


def clean_graph(graph_str):
    if len(graph_str) == 0:
        return graph_str
    edges = graph_str.lower().split(',')
    for i, edge in enumerate(edges):
        edge = edge.strip()
        sorted_edge = edge.split('-')

        if sorted_edge[0] > sorted_edge[2]:
            sorted_edge[0], sorted_edge[2] = sorted_edge[2], sorted_edge[0]
        edges[i] = '-'.join(sorted_edge)

    edges = list(set(edges))
    edges.sort()
    graph = ','.join(edges)
    return graph


def save_document(document, form):
    # Set initial document attributes
    document.title = form.title.data
    document.content = form.content.data
    document.content = str(BeautifulSoup(markupsafe.Markup(document.content), features='html.parser'))
    document.graph = clean_graph(form.graph.data)
    document.updated_at = datetime.now(timezone.utc)
    document.creator_id = current_user.id
    document.role = []

    # update the embedded graph
    soup = BeautifulSoup(document.content, 'html.parser')
    old_embedded_graph = soup.find('document-graph')
    if not old_embedded_graph: # if there isnt a document-graph tag
        # add document graph tag, and restart the html parser, and find tag
        document.content += "<document-graph hidden=\"\"></document-graph>"
        soup = BeautifulSoup(document.content, 'html.parser')
        old_embedded_graph = soup.find('document-graph')
    new_embedded_graph = f"<document-graph hidden=\"\">{document.graph}</document-graph>"
    document.content = document.content.replace(str(old_embedded_graph), new_embedded_graph)

    # Reset users and roles who have access
    document.user = []
    document.role = []

    # Set document role ids from the form's role multiselect
    for role_id in form.roles.data:
        role = models.Role.query.get(role_id)
        document.role.append(role)

    # Set document user ids from the form's user multiselect
    for user_id in form.users.data:
        user = models.User.query.get(user_id)
        document.user.append(user)

    # Add and commit the document to the database
    db.session.add(document)
    db.session.commit()


def get_user_choices():
    return [tuple(t) for t in db.session.query(models.User.id, models.User.username).order_by(models.User.username)]


def get_role_choices():
    return [tuple(t) for t in db.session.query(models.Role.id, models.Role.title).order_by(models.Role.title)]


@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:

        # Get all documents the user has access to
        document_ids = []
        for document in current_user.documents:
            document_ids.append(document.id)

        for role in current_user.roles:
            for document in role.documents:
                document_ids.append(document.id)

        # Paginate all the user's documents
        page = flask.request.args.get('page', 1, type=int)
        document_ids = tuple(set(document_ids))
        documents = (
            models.Document.query.filter(models.Document.id.in_(document_ids))
            .order_by(models.Document.updated_at.desc())
            .paginate(page=page, per_page=5)
        )

        # Create search form
        from voic.forms import SearchForm
        form = SearchForm()

        # If the form is submitted, get all documents matching the search
        if form.validate_on_submit():
            if form.search_bar.data.startswith('graph:'):
                graph_query = clean_graph(form.search_bar.data[6:])
                form.search_bar.data = 'graph:' + graph_query
                graph_query = [models.Document.content.contains(x) for x in graph_query.split(',')]
                print(graph_query)

                documents = (
                    models.Document.query.filter(
                        models.Document.id.in_(document_ids)
                    )
                    .filter(sqlalchemy.and_(*graph_query))
                    .order_by(models.Document.updated_at.desc())
                    .paginate(page=page, per_page=5)
                )
            else:
                documents = (
                    models.Document.query.filter(
                        models.Document.id.in_(document_ids)
                    )
                    .filter(sqlalchemy.or_(
                        models.Document.content.contains(form.search_bar.data),
                        models.Document.title.contains(form.search_bar.data))
                    )
                    .order_by(models.Document.updated_at.desc())
                    .paginate(page=page, per_page=5)
                )

        # Render the documents on the home page
        return flask.render_template('home.html', documents=documents, form=form)
    else:
        # If the user is not signed in, render home with no documents
        return flask.render_template('home.html')


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    # Generate a form for sign up
    from voic.forms import SignUpForm
    form = SignUpForm()

    # If the form is submitted
    if form.validate_on_submit():
        # Create a new account
        pass_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = models.User(username=form.username.data, email=form.email.data.lower(), password=pass_hash)
        user.roles = [models.Role.query.filter_by(title='Employee').first()]
        db.session.add(user)
        db.session.commit()
        flask.flash(f'Your account was created. You may now sign in.', 'success')

        # Redirect to the sign in page
        return flask.redirect(flask.url_for('sign_in'))

    # Render sign up form
    return flask.render_template('forms/sign-up.html', title='Sign Up', form=form)


@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    # Generate a form for sign in
    from voic.forms import SignInForm
    form = SignInForm()

    # If the form is submitted
    if form.validate_on_submit():
        # Sign in if the email and password are valid
        user = models.User.query.filter_by(email=form.email.data.lower()).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            flask_login.login_user(user, remember=form.remember.data)
            next_page = flask.request.args.get('next')
            return flask.redirect(next_page) if next_page else flask.redirect(flask.url_for('home'))
        else:
            flask.flash(f'Incorrect email or password!', 'danger')

    # Render sign in form
    return flask.render_template('forms/sign-in.html', title='Sign In', form=form)


@app.route('/sign-out')
@flask_login.login_required
def sign_out():
    # Sign out the user
    flask_login.logout_user()
    flask.flash('You have been signed out.', 'success')

    # Redirect to the home page
    return flask.redirect(flask.url_for('home'))


@app.route('/account', methods=['GET', 'POST'])
@flask_login.login_required
def account():
    # Generate a form for updating account information
    from voic.forms import UpdateAccountForm
    form = UpdateAccountForm()
    form.roles.choices = get_role_choices()

    # If the form is submitted
    if form.validate_on_submit():
        # Save and set the new picture if the user updated their picture
        if form.picture.data:
            picture = save_picture(form.picture.data)
            current_user.picture = picture

        # Set the new username and email
        current_user.username = form.username.data
        current_user.email = form.email.data.lower()

        # Set the new user roles, always include the Employee role
        current_user.roles = [models.Role.query.filter_by(title='Employee').first()]
        for role_id in form.roles.data:
            role = models.Role.query.get(role_id)
            current_user.roles.append(role)

        # Commit the changes to the database
        db.session.commit()
        flask.flash('Your account has been updated.', 'success')

        # Redirect to the account page to show the updated information
        return flask.redirect(flask.url_for('account'))

    # If the user is just viewing their profile information
    elif flask.request.method == 'GET':
        # Get all the role ids assigned to the user
        selected_role_ids = []
        for role in current_user.roles:
            selected_role_ids.append(role.id)

        # Set the role ids to be preselected when page loads
        form.roles.default = selected_role_ids

        # Process the form to preselect roles
        form.process()

        # Populate the username and email to reflect the current user
        form.username.data = current_user.username
        form.email.data = current_user.email.lower()

    # Render the account page with the user's profile picture
    path = os.path.join('img', 'profile', current_user.picture)
    picture = flask.url_for('static', filename=path)
    return flask.render_template('forms/account.html', title='Account', picture=picture, form=form)


@app.route('/new-document', methods=['GET', 'POST'])
@flask_login.login_required
def new_document():
    # Generate a form for creating a new document
    from voic.forms import DocumentForm
    form = DocumentForm()

    form.users.choices = get_user_choices()
    form.roles.choices = get_role_choices()
    # adds empty embedded graph when creating NEW document
    if not form.content.data:
        form.content.data = "<document-graph hidden=\"\"></document-graph>"

    # If the form is submitted
    if form.validate_on_submit():
        document = models.Document()
        save_document(document, form)
        flask.flash('Your document was created.', 'success')

        # Redirect to the home page
        return flask.redirect(flask.url_for('home'))

    # Render the empty document form for the new document
    return flask.render_template('forms/edit-document.html', title='New Document', form=form)


@app.route('/edit-document/<int:document_id>', methods=['GET', 'POST'])
@flask_login.login_required
def edit_document(document_id):
    # Generate a form for editing an existing document
    from voic.forms import DocumentForm
    form = DocumentForm()
    form.users.choices = get_user_choices()
    form.roles.choices = get_role_choices()

    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to edit this document!', 'danger')
        return flask.redirect(flask.url_for('home'))

    # If the form is submitted
    if form.validate_on_submit():
        # Set initial document attributes to match updated values in form
        save_document(document, form)

        flask.flash('Your document was edited.', 'success')
        return flask.redirect(flask.url_for('home'))

    # If the user is just viewing the document
    elif flask.request.method == 'GET':
        # Get all the role ids assigned to the document
        selected_role_ids = []
        for role in document.role:
            selected_role_ids.append(role.id)

        # Get all the user ids assigned to the document
        selected_user_ids = []
        for user in document.user:
            selected_user_ids.append(user.id)

        # Preselect the documents role and user ids
        form.roles.default = selected_role_ids
        form.users.default = selected_user_ids

        # Process the form to preselect roles
        form.process()

        # Populate the title and content for the document
        form.title.data = document.title
        form.content.data = document.content
        form.graph.data = document.graph

    # Render the document form with its current attributes for editing
    return flask.render_template('forms/edit-document.html', title='Edit Document', form=form)


@app.route('/delete-document/<int:document_id>')
@flask_login.login_required
def delete_document(document_id):
    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to delete this document!', 'danger')
        return flask.redirect(flask.url_for('home'))

    # Get and delete the document from the database
    document = models.Document.query.get(document_id)
    db.session.delete(document)
    db.session.commit()
    flask.flash('Document was deleted.', 'success')

    # Redirect to the home page
    return flask.redirect(flask.url_for('home'))


@app.route('/duplicate-document/<int:document_id>')
@flask_login.login_required
def duplicate_document(document_id):
    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to copy this document!', 'danger')
        return flask.redirect(flask.url_for('home'))

    # Get and duplicate the document by creating a new document with the same content
    old = models.Document.query.get(document_id)
    new = models.Document(title=old.title + ' - Copy', content=old.content, creator_id=old.creator_id, graph=old.graph)
    new.role = old.role
    new.user = old.user
    db.session.add(new)
    db.session.commit()
    flask.flash('Document was copied.', 'success')

    # Redirect to the home page
    return flask.redirect(flask.url_for('home'))


@app.route('/delete-all-documents/')
@flask_login.login_required
def delete_all_documents():
    # Delete all documents accessible through the user's individual account
    for document in current_user.documents:
        db.session.delete(models.Document.query.get(document.id))

    # Delete all documents accessible through the user's roles
    for role in current_user.roles:
        for document in role.documents:
            db.session.delete(models.Document.query.get(document.id))

    # Commit the changes to the database
    db.session.commit()
    flask.flash('All documents were deleted.', 'success')

    # Redirect to the home page
    return flask.redirect(flask.url_for('home'))


@app.route('/document/<int:document_id>')
@flask_login.login_required
def view_document(document_id):
    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to view this document!', 'danger')
        return flask.redirect(flask.url_for('home'))

    document = models.Document.query.get(document_id)
    return flask.render_template('document.html', title='View Document', document=document)


@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    # Generate a form for requesting a password reset
    from voic.forms import RequestPasswordResetForm
    form = RequestPasswordResetForm()

    # If the form is submitted
    if form.validate_on_submit():
        user = models.User.query.filter_by(email=form.email.data.lower()).first()
        send_reset_password_email(user)
        flask.flash(f'A reset password link has been sent to your email. Make sure to check your spam.', 'success')
        return flask.redirect(flask.url_for('sign_in'))

    return flask.render_template('forms/request-password-reset.html', title='Request Password Reset', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        return flask.redirect(flask.url_for('home'))

    # If the token is invalid
    user = models.User.verify_reset_token(token)
    if not user:
        flask.flash('Invalid or expired token!', 'danger')
        return flask.redirect(flask.url_for('request-reset-password'))

    # Generate a form for reseting password
    from voic.forms import ResetPasswordForm
    form = ResetPasswordForm()

    # If the form is submitted
    if form.validate_on_submit():
        # Create a new account
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.roles = [models.Role.query.filter_by(title='Employee').first()]
        user.password = password_hash
        db.session.commit()
        flask.flash(f'Your password was updated. You may now sign in.', 'success')

        # Redirect to the sign in page
        return flask.redirect(flask.url_for('sign_in'))

    return flask.render_template('forms/reset-password.html', title='Reset Your Password', form=form)


@app.route('/danger-zone')
@flask_login.login_required
def danger_zone():
    # Render the account page with the user's profile picture
    path = os.path.join('img', 'profile', current_user.picture)
    picture = flask.url_for('static', filename=path)

    return flask.render_template('forms/danger-zone.html', title='Danger Zone', picture=picture)


@app.route('/delete-account')
@flask_login.login_required
def delete_account():
    # Delete the user from the database
    db.session.delete(current_user)
    db.session.commit()
    flask.flash('Your account was deleted.', 'success')

    # Redirect to the home page
    return flask.redirect(flask.url_for('home'))


@app.route('/help')
def help():
    return flask.render_template('help.html', title='Help')
