#!/usr/bin/env python3
"""app Module
"""
from flask import Flask, jsonify, request
from auth import Auth

Auth = Auth()
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
            u = Auth.register_user(email, password)
            return jsonify({"email": f"{u.email}", "message": "user created"})
        except ValueError:
            return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
