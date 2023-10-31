# flask-ishuman

> simple flask app captcha validation

# usage

a good example of usage can be found in [/tests/main.py](/tests/main.py), although heres a basic example

```py
import flask
import flask_ishuman

app = flask.Flask(__name__)
h = flask_ishuman.IsHuman()

@app.get("/")
def index():
    c = h.new()
    return ...  # now render it, like c.image() maybe or c.rawpng() or something

@app.post("/")
def validate():
    code = flask.request.form.get("code")  # this if u have a <form> that has name=code in it, but ur free to get the `code` in any way u want

    # if code is None then itll return false regardless

    if h.verify(code):
        pass  # captcha valid
    else:
        pass  # captcha invalid

app.config["SECRET_KEY"] = h.rand.randbytes(2048)

# firefox throws warnings if these are not set
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

h.init_app(app)
app.run("127.0.0.1", 8080)
```

heres the functions and classes we have :

-   `IsHuman` -- captcha wrapper
    -   `__init__(image_args: dict, audio_args: dict) -> None` -- constructor, passes `image_args` to captcha.image.ImageCaptcha and same with `audio_args`, just for audio ( [underlying captcha library](https://pypi.org/project/captcha/), although [i forked it](https://pypi.org/project/more-captcha/) )
        -   `cimage` attr is an instance of `captcha.image.ImageCaptcha`
        -   `caudio` attr is an instance of `captcha.audio.AudioCaptcha`
        -   `rand` is a cryptographically secure randomness source, or `secrets.SystemRandom()`
        -   `skey` is the unique captcha key in the session
        -   `app` is the flask app ( can be `None` if `init_app()` was not called )
        -   `pepper` is the pepper of captchas ( also can b `None` if `init_app()` was not called )
    -   `init_app(app: flask.Flask) -> Self` -- initialize flask app, set up variables, configuration, generate keys
    -   `digest(code: str, salt: bytes | None) -> (bytes, bytes)` -- returns a salted and peppered sha3-512 digest of a code, returns `(salt, digest)
    -   `split_digest(s: bytes | None) -> (bytes, bytes)` -- splits a digest into a tuple of `(salt, digest)`, by default uses the current captcha
    -   `random(length: int | None) -> str` -- returns a random code of `length` length, uses a random number in `CAPTCHA_RANGE` length by default
    -   `set_code(code: str) -> Self` -- sets the captcha to a code
    -   `get_digest() -> (bytes, bytes) | None` -- returns the current captcha digest if available, returns `(salt, digest)_`
    -   `verify(code: str | None, expire: bool = True) -> bool` -- returns if a code is a valid hash, if `code` is `None` will always return `False`, which helps to work with flask apis like `flask.request.from.get`, will also call `expire()` if `expire=True` ( default ) is passed
    -   `new(code: str | None, length: str | None, set_c: bool = True)` -- returns a new `CaptchaGenerator`, passes code as the code and uses `random(length)` by default, `set_code()` is called if `set_c` is `True`, which is the default
    -   `expire() -> Self` -- expire the current captcha
-   `CaptchaGenerator` -- generate captchas
    -   `__init__(code: str, cimage: captcha.image.ImageCaptcha, caudio: captcha.audio.AudioCaptcha) -> None` -- constructor, takes in the captcha code and captcha helpers
        -   `code` is the captcha code
        -   `cimage` is an instance of `captcha.image.ImageCaptcha`
        -   `caudio` is an instance of `captcha.audio.AudioCaptcha`
    -   `rawpng() -> bytes` -- returns raw png data used in `png()`
    -   `rawwav() -> bytes` -- returns raw wav data used in `wav()`
    -   `png() -> str` -- returns base64 encoded png of the image captcha
    -   `wav() -> str` -- returns base64 encoded wav of the audio captcha
    -   `image(alt: str = "Image CAPTCHA") -> str` -- returns html to embed for the captcha, `alt` attr is set as `alt`, note tht `alt` is not escaped
    -   `audio(alt: str = "Audio CAPTCHA", controls: bool = True) -> str` -- returns the audio captcha embedding html, `alt` attr is not set, but embded in the `audio` element as `alt`, and `controls` is added too if `controls` is set to `True`, note tht `alt` is not escaped

what u have to do is basically :

-   create `IsHuman`
-   call `init_app` on it
-   call `new` on it
-   use functions provided in` CaptchaGenerator` to display captcha
    -   for example embed it in html using `.png()` or have a route like `/captcha.png` to return the actual png although do whatever u want

# configuration

-   `SECRET_KEY` -- this is default in flask, set this to a secure random value, this is used for session storage and protection, will throw a warning if unset
-   `CAPTCHA_SALT_LEN` -- the salt length to use for salting of hashes, by default `32`
-   `CAPTCHA_CHARSET` -- the charset to use in captchas, by default all ascii letters, digits and characters `@#%?`
-   `CAPTCHA_RANGE` -- a 2 value tuple storing `(from, to)` arguments, used to generation of random captcha lengths, by default from 4 to 8 ( `(4, 8)` )
-   `CAPTCHA_PEPPER_SIZE` -- the size of the pepper value, by default `2048`
-   `CAPTCHA_PEPPER_FILE` -- the pepper file to use, which is like a constant salt not stored in the session, by default `captcha_pepper`

these should be a part of `app.config`, although optional -- will use default values if unspecified

## best configuration practices

-   large, cryptographically secure, random secret key
-   a salt length that is anywhere from 16 to 64 bytes, dont go overboard though as that will increase the size of the session
-   charset of readable characters when messed with in a captcha sense
-   a sensible range, so it isnt too large like 100 characters or too small like 1 characters
-   a big pepper size, maybe like from 512 to 4096 bytes

## logging

all logging of flask-ishuman is done through `logging.DEBUG`
