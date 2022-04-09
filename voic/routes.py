import flask

from voic import app


@app.route('/')
@app.route('/home')
def home():
    return flask.render_template('home.html')
