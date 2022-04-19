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

from voic import logger, app, db, bcrypt, mail, models


def save_picture(picture_data):
    logger.debug(f'Saving picture for {current_user}')

    random_hex = secrets.token_hex(8)
    _, filetype = os.path.splitext(picture_data.filename)
    picture = random_hex + filetype
    path = os.path.join(app.root_path, 'static', 'img', 'profile', picture)
    output_size = (125, 125)
    image = Image.open(picture_data)
    image.thumbnail(output_size)
    image.save(path)

    logger.debug(f'Saved picture to {path} for {current_user}')
    return picture


def send_reset_password_email(user):
    logger.debug(f'Sending reset password email to {user.email} for {user}')

    token = user.get_reset_token()
    email_sender = os.environ.get('EMAIL_USERNAME')
    msg = flask_mail.Message('Password Reset Request', sender=email_sender, recipients=[user.email])
    msg.body = f'''Please reset your password by visting the following link:
{flask.url_for('reset_password', token=token, _external=True)}

Ignore this email if you did not request a password reset.
'''
    mail.send(msg)

    logger.debug(f'Sent email to {user.email} for {user}')


def clean_graph(graph_str):
    logger.debug(f'Cleaning submitted graph {graph_str} for {current_user}')

    edges = graph_str.split(',')
    for i, edge in enumerate(edges):
        sorted_edge = edge.split('-')
        if sorted_edge[0] > sorted_edge[1]:
            sorted_edge[0], sorted_edge[1] = sorted_edge[1], sorted_edge[0]
        edges[i] = '-'.join(sorted_edge)

    edges = list(set(edges))
    edges.sort()
    graph = ','.join(edges)

    logger.debug(f'Cleaned graph {graph_str} for {current_user}')
    return graph


@app.route('/', methods=['GET', 'POST'])
def home():
    logger.debug(f'Routed to /')

    if current_user.is_authenticated:
        logger.debug(f'{current_user} is authenticated')

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
                edges = form.search_bar.data[6:].split(',')
                for i, edge in enumerate(edges):
                    sorted_edge = edge.split('-')
                    if sorted_edge[0] > sorted_edge[1]:
                        sorted_edge[0], sorted_edge[1] = sorted_edge[1], sorted_edge[0]
                    edges[i] = '-'.join(sorted_edge)

                edges = list(set(edges))
                edges.sort()
                graph_query = ','.join(edges)
                form.search_bar.data = 'graph:' + graph_query

                documents = (
                    models.Document.query.filter(
                        models.Document.id.in_(document_ids)
                    )
                    .filter(models.Document.graph.contains(graph_query))
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
        logger.debug(f'Found {len(document_ids)} document(s) for {current_user}')
        logger.debug(f'Rendering home.html with documents for {current_user}')
        return flask.render_template('home.html', documents=documents, form=form)
    else:
        # If the user is not signed in, render home with no documents
        logger.debug(f'Current User is not authenticated')
        logger.debug(f'Rendering home.html without documents')
        return flask.render_template('home.html')


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    logger.debug(f'Routed to /sign-up')

    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        logger.debug(f'{current_user} is authenticated')
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    # Generate a form for sign up
    from voic.forms import SignUpForm
    form = SignUpForm()

    # If the form is submitted
    if form.validate_on_submit():
        # Create a new account
        logger.debug(f'{current_user} is authenticated')
        pass_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = models.User(username=form.username.data, email=form.email.data.lower(), password=pass_hash)
        user.roles = [models.Role.query.filter_by(title='Employee').first()]
        db.session.add(user)
        db.session.commit()
        logger.debug(f'Committed {user} add to database')
        flask.flash(f'Your account was created. You may now sign in.', 'success')

        # Redirect to the sign in page
        logger.debug(f'Redirecting to sign_in for {current_user}')
        return flask.redirect(flask.url_for('sign_in'))

    # Render sign up form
    logger.debug(f'Rendering forms/sign-up.html with SignUpForm()')
    return flask.render_template('forms/sign-up.html', title='Sign Up', form=form)


@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    logger.debug(f'Routed to /sign-in')

    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        logger.debug(f'{current_user} is authenticated')
        logger.debug(f'Redirecting to home for {current_user}')
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
            logger.debug(f'Redirecting to next page or home for {current_user}')
            return flask.redirect(next_page) if next_page else flask.redirect(flask.url_for('home'))
        else:
            flask.flash(f'Incorrect email or password!', 'danger')

    # Render sign in form
    logger.debug(f'Rendering forms/sign-in.html with SignInForm()')
    return flask.render_template('forms/sign-in.html', title='Sign In', form=form)


@app.route('/sign-out')
@flask_login.login_required
def sign_out():
    logger.debug(f'Routed to /sign-in')

    # Sign out the user
    flask_login.logout_user()
    flask.flash('You have been signed out.', 'success')

    # Redirect to the home page
    logger.debug(f'Redirecting to home for {current_user}')
    return flask.redirect(flask.url_for('home'))


@app.route('/account', methods=['GET', 'POST'])
@flask_login.login_required
def account():
    logger.debug(f'Routed to /account')

    # Generate a form for updating account information
    from voic.forms import UpdateAccountForm
    form = UpdateAccountForm()

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
        logger.debug(f'Committed {current_user} update to database')
        flask.flash('Your account has been updated.', 'success')

        # Redirect to the account page to show the updated information
        logger.debug(f'Redirecting to account for {current_user}')
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
    logger.debug(f'Rendering forms/account.html with picture and form for {current_user}')
    return flask.render_template('forms/account.html', title='Account', picture=picture, form=form)


@app.route('/new-document', methods=['GET', 'POST'])
@flask_login.login_required
def new_document():
    logger.debug(f'Routed to /new-document')

    # Generate a form for creating a new document
    from voic.forms import DocumentForm
    form = DocumentForm()

    document = models.Document()

    # If the form is submitted
    if form.validate_on_submit():
        # Set initial document attributes
        document.title = form.title.data
        document.content = BeautifulSoup(markupsafe.Markup(form.content.data)).prettify()
        document.graph = clean_graph(form.graph.data)
        document.updated_at = datetime.now(timezone.utc)
        document.creator_id = current_user.id
        document.role = []

        # Reset users and roles who have access
        document.user = []
        document.role = []

        # Set document role ids from the form's role multiselect
        for role_id in form.roles.data:
            role = models.Role.query.get(role_id)
            logger.debug(f'Adding {role} to {document}')
            document.role.append(role)

        # Set document user ids from the form's user multiselect
        for user_id in form.users.data:
            user = models.User.query.get(user_id)
            logger.debug(f'Adding {user} to {document}')
            document.user.append(user)

        # Add and commit the document to the database
        db.session.add(document)
        db.session.commit()
        logger.debug(f'Committed {document} add to database')

        flask.flash('Your document was created.', 'success')

        # Redirect to the home page
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    # Render the empty document form for the new document
    logger.debug(f'Rendering forms/edit-document.html with DocumentForm() for {current_user}')
    return flask.render_template('forms/edit-document.html', title='New Document', form=form)


@app.route('/edit-document/<int:document_id>', methods=['GET', 'POST'])
@flask_login.login_required
def edit_document(document_id):
    logger.debug(f'Routed to /edit-document/{document_id}')

    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to edit this document!', 'danger')
        logger.debug(f'{current_user} does not have permission to edit {document}!')
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    # Generate a form for editing an existing document
    from voic.forms import DocumentForm
    form = DocumentForm()

    # If the form is submitted
    if form.validate_on_submit():
        # Set initial document attributes to match updated values in form
        document.title = form.title.data
        document.content = BeautifulSoup(markupsafe.Markup(form.content.data)).prettify()
        document.graph = clean_graph(form.graph.data)

        # Reset users and roles who have access
        document.user = []
        document.role = []

        # Set document role ids from the form's role multiselect
        for role_id in form.roles.data:
            role = models.Role.query.get(role_id)
            logger.debug(f'Adding {role} to {document}')
            document.role.append(role)

        # Set document user ids from the form's user multiselect
        for user_id in form.users.data:
            user = models.User.query.get(user_id)
            logger.debug(f'Adding {user} to {document}')
            document.user.append(user)

        db.session.commit()
        logger.debug(f'Committed {document} update to database')
        flask.flash('Your document was edited.', 'success')
        logger.debug(f'Redirecting to home for {current_user}')
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
    logger.debug(f'Rendering forms/edit-document.html with DocumentForm() for {current_user}')
    return flask.render_template('forms/edit-document.html', title='Edit Document', form=form)


@app.route('/delete-document/<int:document_id>')
@flask_login.login_required
def delete_document(document_id):
    logger.debug(f'Routed to /delete-document/{document_id}')

    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to delete this document!', 'danger')
        logger.debug(f'{current_user} does not have permission to delete {document}!')
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    # Get and delete the document from the database
    document = models.Document.query.get(document_id)
    db.session.delete(document)
    db.session.commit()
    logger.debug(f'Committed {document} delete to database')
    flask.flash('Document was deleted.', 'success')

    # Redirect to the home page
    logger.debug(f'Redirecting to home for {current_user}')
    return flask.redirect(flask.url_for('home'))


@app.route('/duplicate-document/<int:document_id>')
@flask_login.login_required
def duplicate_document(document_id):
    logger.debug(f'Routed to /duplicate-document/{document_id}')

    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to copy this document!', 'danger')
        logger.debug(f'{current_user} does not have permission to copy {document}!')
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    # Get and duplicate the document by creating a new document with the same content
    old = models.Document.query.get(document_id)
    new = models.Document(title=old.title, content=old.content, creator_id=old.creator_id, graph=old.graph)
    new.role = old.role
    new.user = old.user
    db.session.add(new)
    db.session.commit()
    logger.debug(f'Committed {new} add to database')
    flask.flash('Document was duplicated.', 'success')

    # Redirect to the home page
    logger.debug(f'Redirecting to home for {current_user}')
    return flask.redirect(flask.url_for('home'))


@app.route('/delete-all-documents/')
@flask_login.login_required
def delete_all_documents():
    logger.debug(f'Routed to /delete-all-documents/')

    # Delete all documents accessible through the user's individual account
    for document in current_user.documents:
        db.session.delete(models.Document.query.get(document.id))

    # Delete all documents accessible through the user's roles
    for role in current_user.roles:
        for document in role.documents:
            db.session.delete(models.Document.query.get(document.id))

    # Commit the changes to the database
    db.session.commit()
    logger.debug(f'Committed Document() mass delete to database')
    flask.flash('All documents were deleted.', 'success')

    # Redirect to the home page
    logger.debug(f'Redirecting to home for {current_user}')
    return flask.redirect(flask.url_for('home'))


@app.route('/document/<int:document_id>')
@flask_login.login_required
def view_document(document_id):
    logger.debug(f'Routed to /document/{document_id}')

    # Get the document from id and check whether the user has permission
    document = models.Document.query.get(document_id)
    if current_user not in document.user and not set(current_user.roles).intersection(document.role):
        flask.flash('You do not have the permissions to view this document!', 'danger')
        logger.debug(f'{current_user} does not have permission to view {document}!')
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    document = models.Document.query.get(document_id)
    logger.debug(f'Rendering document.html with document for {current_user}')
    return flask.render_template('document.html', title='View Document', document=document)


@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    logger.debug(f'Routed to /request-password-reset')

    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        logger.debug(f'{current_user} is authenticated')
        logger.debug(f'Redirecting to home for {current_user}')
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

    logger.debug(f'Rendering forms/request-password-reset.html with RequestPasswordResetForm()')
    return flask.render_template('forms/request-password-reset.html', title='Request Password Reset', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    logger.debug(f'Routed to /reset-password')

    # If the user is signed in, redirect to home
    if current_user.is_authenticated:
        logger.debug(f'{current_user} is authenticated')
        logger.debug(f'Redirecting to home for {current_user}')
        return flask.redirect(flask.url_for('home'))

    # If the token is invalid
    user = models.User.verify_reset_token(token)
    if not user:
        flask.flash('Invalid or expired token!', 'danger')
        logger.debug(f'Token {token} is invalid')
        return flask.redirect(flask.url_for('request-reset-password'))

    # Generate a form for reseting password
    from voic.forms import ResetPasswordForm
    form = ResetPasswordForm()

    # If the form is submitted
    if form.validate_on_submit():
        # Create a new account
        logger.debug(f'{current_user} is authenticated')
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.roles = [models.Role.query.filter_by(title='Employee').first()]
        user.password = password_hash
        db.session.commit()
        logger.debug(f'Committed {user} update to database')
        flask.flash(f'Your password was updated. You may now sign in.', 'success')

        # Redirect to the sign in page
        logger.debug(f'Redirecting to sign_in for {current_user}')
        return flask.redirect(flask.url_for('sign_in'))

    return flask.render_template('forms/reset-password.html', title='Reset Your Password', form=form)
