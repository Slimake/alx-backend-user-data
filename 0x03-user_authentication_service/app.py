#!/usr/bin/env python3
"""app Module
"""
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def basic_app():
    """Set up basic Flask app
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
