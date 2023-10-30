#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test flask-ishuman"""

import logging
from warnings import filterwarnings as filter_warnings

import flask

import flask_ishuman

TEMPLATE: str = """<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>captcha test</title>

        <meta property="og:type" content="website" />

        <meta name="color-scheme" content="dark" />
        <meta name="theme-color" content="black" />

        <style>
            *, *::before, *::after {
                background-color: black;
                color: whitesmoke;
            }
        </style>
    </head>

    <body>
        <form method=POST>%s <input type="text" name="code" id="code" />
        <button type="submit">submit</button></form>
    </body>
</html>"""

app: flask.Flask = flask.Flask(__name__)
h: flask_ishuman.IsHuman = flask_ishuman.IsHuman()


@app.route("/image", methods=["GET"])
def image() -> str:
    return TEMPLATE % (h.new().image(),)


@app.route("/audio", methods=["GET"])
def audio() -> str:
    return TEMPLATE % (h.new().audio(),)


@app.route("/audio", methods=["POST"])
@app.route("/image", methods=["POST"])
def captcha_verify() -> str:
    return f"{'' if h.verify_captcha(flask.request.form.get('code', '')) else 'in'}\
valid captcha"


@app.route("/", methods=["GET"])
def index() -> str:
    return """<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>test</title>

        <meta property="og:type" content="website" />

        <meta name="color-scheme" content="dark" />
        <meta name="theme-color" content="black" />

        <style>
            *, *::before, *::after {
                background-color: black;
                color: whitesmoke;
            }
        </style>
    </head>

    <body>
        <a href=/image>image captcha</a>
        <a href=/audio>audio captcha</a>
    </body>
</html>"""


def main() -> int:
    """entry / main function"""

    logging.getLogger().setLevel(logging.DEBUG)

    app.config["SECRET_KEY"] = h.rand.randbytes(2048)
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True

    h.init_app(app)
    app.run("127.0.0.1", 8080, True)

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
