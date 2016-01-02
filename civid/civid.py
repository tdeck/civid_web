from flask import Flask, session, render_template, redirect, url_for, request, jsonify
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound, HTTPException
from tokens import Tokenizer, InvalidCodeError, InvalidTokenError
from urlparse import urlparse
from urllib import urlencode
from datetime import timedelta
from flask_limiter import Limiter
from flask.ext.cors import cross_origin
import os
import uuid
import validators
import logging
import jinja2_highlight # This isn't used directly, but it's a sanity check

app = Flask(__name__)
app.jinja_options['extensions'].append('jinja2_highlight.HighlightExtension')
limiter = Limiter(app, global_limits=['20 per minute'])

# Load configuration from the environment
secret_key = os.environ.get('SECRET_KEY')
signing_key = os.environ.get('SIGNING_KEY')
if not secret_key: raise Exception("SECRET_KEY not set")
if not signing_key: raise Exception("SIGNING_KEY not set")

app.config['SERVER_NAME'] = os.environ.get('SERVER_NAME')
app.config['SECRET_KEY'] = secret_key
app.config['BOT_NAME'] = 'edsgar'
app.config['SESSION_LIFETIME_DAYS'] = 90 # Used in a template

tokenizer = Tokenizer(signing_key)

app.permanent_session_lifetime = timedelta(days=app.config['SESSION_LIFETIME_DAYS'])
@app.before_request
def before_request():
    session.permanent = True

# This is needed because of a stupid, old bug in Flask
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(429)
@app.errorhandler(500)
@app.errorhandler(Exception)
def show_error_page(error):
    app.logger.exception(error)

    code = 500
    title = 'Server Error'
    message = 'Something went wrong!'

    # Have to do it this way because of a bug in Flask
    # https://github.com/mitsuhiko/flask/issues/941
    if isinstance(error, HTTPException):
        code = error.code
        title = error.name
        message = error.description

    return render_template('error.html', title=title, message=message), code

def expected_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = uuid.uuid4().hex
    return session['csrf_token']

def validated_redirect_uri(uri_param):
    if uri_param is None:
        raise BadRequest("Missing required redirect URI")

    try:
        validators.url(uri_param)
    except:
        raise BadRequest("Malformed redirect URI")

    parsed = urlparse(uri_param)
    if parsed.scheme not in ['http', 'https']:
        raise BadRequest("Redirect URI must be http or https")

    return parsed

@app.route('/in/<token>', methods=['GET'])
def login(token):
    try:
        username = tokenizer.validate_login_token(token)
    except InvalidTokenError:
        # TODO this is a user-facing message and should be better
        raise Unauthorized('Invalid or expired login code')

    session['username'] = username
    return render_template('logged_in.html')

@app.route('/out', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """
    Query string parameters:
        redirect_uri (required)
        state (optional)
    POST parameters:
        csrf_token (required)
    """
    redirect_uri = validated_redirect_uri(request.args.get('redirect_uri'))

    if request.method == 'POST':
        if request.form.get('csrf_token') != expected_csrf_token():
            raise BadRequest('Invalid CSRF token')

        if 'username' not in session:
            raise BadRequest('No authenticated user to identify')

        target = '{}://{}{}'.format(
            redirect_uri.scheme,
            redirect_uri.netloc,
            redirect_uri.path
        )

        response = {}
        if 'state' in request.args: response['state'] = request.args['state']

        if request.form['action'] == 'identify':
            response['code'] = tokenizer.create_identity_code(session['username'])
        else:
            response['error'] = 'declined'

        return redirect(target + '?' + urlencode(response))
    else:
        return render_template(
            'authorize.html',
            app_domain=redirect_uri.netloc,
            csrf_token=expected_csrf_token()
        )

@app.route('/userinfo', methods=['GET'])
@cross_origin()
def userinfo():
    code = request.args.get('code')
    if not code:
        raise BadRequest('No login code provided')

    try:
        uname = tokenizer.validate_identity_code(code)
        return jsonify(
            user=uname.lower(),
            display_name=uname
        )
    except InvalidCodeError:
        raise BadRequest('Invalid or expired identity code')

if __name__ == '__main__':
    print "Enabling debug"
    app.debug = True
    app.run()
else:
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.INFO)
