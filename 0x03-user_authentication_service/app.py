#!/usr/bin/env python3
"""app Module
"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route("/")
def index() -> str:
    """Set up basic Flask app
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'], strict_slashes=False)
def users() -> str:
    """Register a user
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            u = AUTH.register_user(email, password)
            return jsonify({"email": f"{u.email}", "message": "user created"})
        except ValueError:
            return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=['POST'], strict_slashes=False)
def login() -> str:
    """Login user
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
    user_exists = AUTH.valid_login(email, password)
    if user_exists is False:
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie('session_id', session_id)

    return response


@app.route("/sessions", methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """Logout user
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is not None:
        AUTH.destroy_session(user.id)
    else:
        abort(403)

    return redirect(url_for('index'))


@app.route("/profile", methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Find a user, respond with 200 HTTP status code
    If the session ID is invalid or the user does not exist,
    respond with a 403 HTTP status.
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is not None:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


@app.route("/reset_password", methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """Implement a get_reset_password_token function
    to respond to the POST /reset_password route.
    """
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route("/reset_password", methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """Implement the update_password function in the app
    module to respond to the PUT /reset_password route.
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
