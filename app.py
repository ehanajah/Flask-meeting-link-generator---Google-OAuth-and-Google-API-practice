import json
import logging
import os
import pathlib
import requests
from google.oauth2.credentials import Credentials
from flask import Flask, abort, redirect, url_for, session, request
from pip._vendor import cachecontrol
from google.apps import meet_v2
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.apps.meet_v2.types.resource import SpaceConfig

app = Flask(__name__)
app.secret_key = 'cobameeting'  # Ganti dengan kunci rahasia yang lebih aman

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Buka file json dan baca isinya
with open('credentials.json', 'r') as f:
    data = json.load(f)

# Ambil client_secret dari data
CLIENT_SECRET = data['web']['client_secret']

CLIENT_ID = '35107937628-mnbmunk4dqp6ektc869tfgf87l8j0sdc.apps.googleusercontent.com'
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "credentials.json")
SCOPES = [
    "https://www.googleapis.com/auth/meetings.space.created",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

flow = Flow.from_client_secrets_file(
    'credentials.json',
    scopes=SCOPES,
    redirect_uri="http://127.0.0.1:5000/callback",
)


def require_login(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/")
def home():
    if "google_id" in session:
        return redirect(url_for("user_page"))
    return (f"Hello <a href='{url_for('login', _external=True)}'><button>Login</button></a>")


# Rute autentikasi OAuth 2.0
@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session["state"] = state
    return redirect(authorization_url)


# Callback
@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return redirect("/user_page")

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = Request(session=cached_session)

    print(credentials.__dict__)

    session['access_token'] = credentials.token
    session['refresh_token'] = credentials._refresh_token
    session['expiry'] = credentials.expiry.isoformat()

    print(session['refresh_token'])

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect(url_for('user_page'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")


# Rute pembuatan pertemuan
@require_login
@app.route('/user_page')
def user_page():
    if 'access_token' not in session:
        return redirect(url_for('login'))
    message = session.get("message", "")
    session.pop('message', None)

    meeting_url = session.get("meeting_url", "")
    return f"Hello {session['name']}! <br/> <a href='{meeting_url}'>{meeting_url}</a>{message} <br/><br/> <a href='{url_for('logout')}'><button>Logout</button></a> <br/> <a href='{url_for('create_meeting')}'><button>Create Meeting</button></a>"


@require_login
@app.route("/create_meeting")
def create_meeting():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    session.pop('meeting_url', None)

    refresh_token = session['refresh_token']

    creds = Credentials.from_authorized_user_info(
        {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'refresh_token': refresh_token
        }
    )

    try:
        client = meet_v2.SpacesServiceClient(credentials=creds)
        request = meet_v2.CreateSpaceRequest()

        request.space.config = SpaceConfig()
        request.space.config.access_type = SpaceConfig.AccessType.OPEN

        response = client.create_space(request=request)
        meeting_url = response.meeting_uri

        print(f'Space created: {meeting_url}')
        session['meeting_url'] = meeting_url
        return redirect(url_for('user_page'))

    except Exception as error:
        logging.error(f'An error occurred: {error}')
        session['message'] = f"Gagal: {error}"
        return redirect(url_for('user_page'))


if __name__ == '__main__':
    app.run(debug=True)
