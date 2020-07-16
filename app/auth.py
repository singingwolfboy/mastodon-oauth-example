from urllib.parse import urlencode
import random
import re
from string import ascii_letters, digits
import httpx
from httpcore import ConnectError
import flask
from flask import Blueprint, current_app, request, url_for, redirect
from flask_login import current_user, login_user
from sqlalchemy.orm.exc import NoResultFound
from .models import db, User, MastodonServer

letters_and_digits = ascii_letters + digits

URL_REGEX = re.compile("(https://)?[^/]+")


def random_string(length=10):
    return "".join(random.choice(letters_and_digits) for i in range(length))


blueprint = Blueprint("auth", __name__)


@blueprint.route("/login", methods=["POST"])
def login():
    server_uri = request.form.get("server_uri")
    if not server_uri:
        return {"message": "missing `server_uri` parameter"}, 400
    if not URL_REGEX.match(server_uri):
        return {"message": "invalid `server_uri` parameter"}, 400
    if server_uri.startswith("https://"):
        server_uri = server_uri[8:]  # strip off the protocol

    # get the MastodonServer object from the database, or create one if necessary
    server = MastodonServer.get_by_uri(server_uri)
    if not server:
        # we need a client_id/client_secret to create a MastodonServer object,
        # so make the API call to get them
        app_data = {
            "client_name": current_app.config["APP_NAME"],
            "redirect_uris": url_for(".authorized", _external=True),
            "scopes": "read:accounts",
            "website": request.url_root,
        }
        try:
            app_resp = httpx.post(f"https://{server_uri}/api/v1/apps", data=app_data)
        except ConnectError:
            return {"message": f"could not connect to https://{server_uri}"}, 400
        if app_resp.status_code != 200:
            return (
                {
                    "message": "could not create OAuth app on Mastodon server",
                    "response": app_resp.text,
                },
                502,
            )
        resp_data = app_resp.json()
        server = MastodonServer(
            uri=server_uri,
            client_id=resp_data["client_id"],
            client_secret=resp_data["client_secret"],
        )
        db.session.add(server)
        db.session.commit()

    # generate and save a `state` token
    state = random_string(10)
    flask.session["state"] = state
    # also save the server_uri
    flask.session["server_uri"] = server_uri

    # redirect the user to start the OAuth dance
    auth_data = {
        "response_type": "code",
        "client_id": server.client_id,
        "redirect_uri": url_for(".authorized", _external=True),
        "scope": "read:accounts",
        "state": state,
    }
    auth_data_qs = urlencode(auth_data)
    redirect_url = f"https://{server_uri}/oauth/authorize?{auth_data_qs}"
    return redirect(redirect_url)


@blueprint.route("/authorized", methods=["GET"])
def authorized():
    # check for `code` param; needed to prove that user provided consent
    code = request.args.get("code")
    if not code:
        return {"message": "missing `code` query param"}, 400

    # validate `state` token, if present
    saved_state = flask.session.get("state")
    if saved_state:
        state = request.args.get("state")
        if state != saved_state:
            return {"message": "missing or invalid `state` query param"}, 400
        # delete `state` token from Flask session; we don't need it anymore
        del flask.session["state"]

    # get the Mastodon server info from the database
    server_uri = flask.session.get("server_uri")
    if not server_uri:
        return {"message": "missing `server_uri` from session cookie"}, 400
    server = MastodonServer.get_by_uri(server_uri)
    if not server:
        return {"message": f"unknown Mastodon server: {server_uri}"}, 400
    # delete the `server_uri` from Flask session; we don't need it anymore
    del flask.session["server_uri"]

    # get the OAuth access token from the server
    auth_data = {
        "client_id": server.client_id,
        "client_secret": server.client_secret,
        "redirect_uri": url_for(".authorized", _external=True),
        "scope": "read:accounts",
        "grant_type": "authorization_code",
        "code": code,
    }
    try:
        auth_resp = httpx.post(f"https://{server_uri}/oauth/token", data=auth_data)
    except ConnectError:
        return {"message": f"could not connect to https://{server_uri}"}, 502
    if auth_resp.status_code != 200:
        return (
            {
                "message": "could not get OAuth access token from Mastodon server",
                "response": auth_resp.text,
            },
            502,
        )
    auth_resp_data = auth_resp.json()
    access_token = auth_resp_data["access_token"]

    # use the access token to get information from Mastodon about the user
    account_resp = httpx.get(
        f"https://{server_uri}/api/v1/accounts/verify_credentials",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if account_resp.status_code != 200:
        return (
            {
                "message": "could not get profile info from Mastodon server",
                "response": account_resp.text,
            },
            502,
        )
    account_resp_data = account_resp.json()

    # find or create our local user account
    user = User.query.filter_by(
        server=server, id_on_server=account_resp_data["id"]
    ).first()
    if not user:
        user = User(
            server=server,
            id_on_server=account_resp_data["id"],
            username=account_resp_data["username"],
            display_name=account_resp_data["display_name"],
            url=account_resp_data["url"],
            note=account_resp_data["note"],
            avatar=account_resp_data["avatar"],
            avatar_static=account_resp_data["avatar_static"],
            oauth_token=auth_resp_data,
        )
        db.session.add(user)
        db.session.commit()

    # login the local user account
    login_user(user)

    return redirect(url_for("index"))
