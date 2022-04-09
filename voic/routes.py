import flask
import flask_login
from voic import app
from voic import forms


@app.route('/')
@app.route('/home')
def home():
    return flask.render_template('home.html')

@app.route('/my-documents')
def my_documents():
    return flask.render_template('my-documents.html')

@app.route('/new-document')
def new_document():
    return flask.render_template('forms/new-document.html')

@app.route('/edit-document')
def edit_document():
    return flask.render_template('forms/edit-document.html')

@app.route('/sign-in')
def sign_in():
    return flask.render_template('forms/sign-in.html')

@app.route('/sign-up')
def sign_up():
    # if current_user.is_authenticated:
    #     return flask.redirect(url_for('home'))

    form = forms.RegistrationForm()
    if form.validate_on_submit():
        # password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # user = User(username=form.username.data, email=form.email.data, password=password_hash)
        # db.session.add(user)
        # db.session.commit()
        flash(f'Your account was created! You can now sign in.', 'success')
        return redirect(url_for('sign_in'))
    return flask.render_template('forms/sign-up.html', form=form)

@app.route('/account')
# @flask_login.login_required
def account():
    form = forms.UpdateAccountForm()
    # if form.validate_on_submit():
    #     if form.picture.data:
    #         picture = save_picture(form.picture.data)
    #         current_user.picture = picture
    #     current_user.username = form.username.data
    #     current_user.email = form.email.data
    #     db.session.commit()
    #     flash('Your account has been updated!', 'success')
    #     return redirect(url_for('account'))
    # elif flask.request.method == 'GET':
    #     form.username.data = current_user.username
    #     form.email.data = current_user.email
    # picture = url_for('static', filename=os.path.join('assets', current_user.picture))
    picture = 5 # delete this
    return flask.render_template('forms/account.html', title='Account', picture=picture, form=form)
@app.route('/sign-out')
def sign_out():
    return flask.render_template('sign-out.html')