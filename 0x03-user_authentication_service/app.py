#!/usr/bin/env python3
"""app Module
"""
from flask import Flask, jsonify, request, abort, redirect
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
    user = Auth.get_user_from_session_id(session_id)
    if user is not None:
        Auth.destroy_session(user.id)
    else:
        abort(403)

    return redirect('/index')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
