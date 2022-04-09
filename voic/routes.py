import flask

from voic import app


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
    return flask.render_template('forms/sign-up.html')

@app.route('/account')
def account():
    return flask.render_template('forms/account.html')

@app.route('/sign-out')
def sign_out():
    return flask.render_template('sign-out.html')