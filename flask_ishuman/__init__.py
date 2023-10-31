#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flask_ishuman"""

import os
import string
import typing as t
import warnings
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha3_512
from logging import debug as debug_log
from secrets import SystemRandom

import captcha
import captcha.audio
import captcha.image
from flask import Flask, session

__version__: t.Final[str] = "2.0.1"

CHARSET: t.Final[str] = string.ascii_letters + string.digits + "@#%?"


@dataclass
class CaptchaGenerator:
    """captcha generator and renderer"""

    code: str
    cimage: captcha.image.ImageCaptcha
    caudio: captcha.audio.AudioCaptcha

    def rawpng(self) -> bytes:
        """return raw png"""

        debug_log(f"generating PNG for {self.code!r}")
        return self.cimage.generate(self.code, "png").read()

    def rawwav(self) -> bytes:
        """return raw wav"""

        debug_log(f"generating WAV For {self.code!r}")
        return bytes(self.caudio.generate(self.code))

    def png(self) -> str:
        """return base64 encoded png of the image captcha"""

        debug_log(f"base64 encoding CAPTCHA's {self.code!r} PNG image")
        return b64encode(self.rawpng()).decode("ascii")

    def wav(self) -> str:
        """return base64 encoded wav of the audio captcha"""

        debug_log(f"base64 encoding CAPTCHA's {self.code!r} WAV audio")
        return b64encode(self.rawwav()).decode("ascii")

    def image(self, alt: str = "Image CAPTCHA") -> str:
        """return image html"""

        debug_log(f"generating image HTML for CAPTCHA {self.code!r}")
        return f'<img id=image-captcha src="data:image/png;base64,{self.png()}" \
alt="{alt}" />'

    def audio(self, alt: str = "Audio CAPTCHA", controls: bool = True) -> str:
        """return audio html"""

        debug_log(f"generating audio HTML for CAPTCHA {self.code!r}")
        return f'<audio id=audio-captcha{" controls" if controls else ""}> \
<source src="data:audio/wav;base64,{self.wav()}" type=audio/wav /> {alt} </audio>'


@dataclass
class IsHuman:
    """captcha support in flask"""

    _c: int = 0

    def __init__(
        self,
        image_args: t.Optional[t.Dict[str, t.Any]] = None,
        audio_args: t.Optional[t.Dict[str, t.Any]] = None,
    ) -> None:
        self.cimage: captcha.image.ImageCaptcha = captcha.image.ImageCaptcha(
            **(image_args or {}),
        )
        self.caudio: captcha.audio.AudioCaptcha = captcha.audio.AudioCaptcha(
            **(audio_args or {}),
        )

        self.rand: SystemRandom = SystemRandom()
        self.skey: str = f"__captcha{self._c}__"

        self.app: t.Optional[Flask] = None
        self.pepper: t.Optional[bytes] = None

        IsHuman._c += 1

    def init_app(self, app: Flask) -> "IsHuman":
        """initialize flask app"""

        if "SECRET_KEY" not in app.config:
            warnings.warn("no `SECRET_KEY` set, session may be unavailable")

        if "CAPTCHA_SALT_LEN" not in app.config:
            debug_log("setting `CAPTCHA_SALT_LEN` ( used for salting hashes ) to `32`")
            app.config["CAPTCHA_SALT_LEN"] = 32

        if "CAPTCHA_CHARSET" not in app.config:
            debug_log(
                f"setting `CAPTCHA_CHARSET` ( charset of generated CAPTCHAs ) \
to `{CHARSET}`"
            )
            app.config["CAPTCHA_CHARSET"] = CHARSET

        if "CAPTCHA_RANGE" not in app.config:
            debug_log(
                "setting `CAPTCHA_RANGE` ( range is a (from, to) to use \
in generating lengths of captchas ) to `(4, 8)`"
            )
            app.config["CAPTCHA_RANGE"] = 4, 8

        if "CAPTCHA_EXPIRY" not in app.config:
            debug_log(
                "as `CAPTCHA_EXPIRY` is not set it will be set to `None`, \
all captchas will have an infinite lifetime"
            )
            app.config["CAPTCHA_EXPIRY"] = None

        if "CAPTCHA_PEPPER_SIZE" not in app.config:
            debug_log(
                "setting `CAPTCHA_PEPPER_SIZE` to `2048` ( only affects \
anything if `CAPTCHA_PEPPER_FILE` is being created )"
            )
            app.config["CAPTCHA_PEPPER_SIZE"] = 2048

        if "CAPTCHA_PEPPER_FILE" not in app.config:
            debug_log(
                "setting `CAPTCHA_PEPPER_FILE` to `captcha_pepper`, a file \
called `captcha_pepper` might get created and read"
            )
            app.config["CAPTCHA_PEPPER_FILE"] = "captcha_pepper"

        if not os.path.exists(app.config["CAPTCHA_PEPPER_FILE"]):
            with open(app.config["CAPTCHA_PEPPER_FILE"], "wb") as fp:
                debug_log(
                    f"wrote \
{fp.write(self.rand.randbytes(app.config['CAPTCHA_PEPPER_SIZE']))} bytes to "
                    f"{fp.name!r} pepper file",
                )

        with open(app.config["CAPTCHA_PEPPER_FILE"], "rb") as fp:
            self.pepper = fp.read()
            debug_log(f"read {fp.tell()} bytes from {fp.name!r} pepper file")

        self.app = app

        debug_log("app initialized")

        return self

    def random(self, length: t.Optional[int] = None) -> str:
        """returns a random code"""

        if self.app is None:
            raise ValueError("uninitialized app, try `init_app(app)`")

        return "".join(
            self.rand.choices(
                self.app.config["CAPTCHA_CHARSET"],
                k=length or self.rand.randint(*self.app.config["CAPTCHA_RANGE"]),
            ),
        )

    def digest(
        self,
        code: str,
        salt: t.Optional[bytes] = None,
        ts: t.Optional[float] = None,
    ) -> t.Tuple[bytes, bytes, float]:
        """digest a `code`"""

        if self.pepper is None or self.app is None:
            raise ValueError("uninitialized app, try `init_app(app)`")

        debug_log(f"digesting CAPTCHA {code!r}")

        salt = salt or self.rand.randbytes(self.app.config["CAPTCHA_SALT_LEN"])

        return (
            sha3_512(salt + code.encode("ascii") + self.pepper).digest(),
            salt,
            ts or datetime.now().timestamp(),
        )

    def set_code(self, code: str) -> "IsHuman":
        """set captcha to `code`"""
        session[self.skey] = self.digest(code)
        return self

    def get_digest(self) -> t.Optional[t.Tuple[bytes, bytes, float]]:
        """get captcha"""
        return session.get(self.skey)

    def verify(self, code: t.Optional[str], expire: bool = True) -> bool:
        """returns `True` is captcha code is valid, else `False`"""

        debug_log(f"verifying CAPTCHA {code!r}")

        if code is None:
            debug_log("no code specified, ignoring")
            return False

        try:
            d: t.Optional[t.Tuple[bytes, bytes, float]] = self.get_digest()
        except ValueError:
            return False

        if d is None:
            return False

        if expire:
            self.expire()

        if self.auto_expire(d[2]):
            return False

        return self.digest(code, d[1], d[2]) == d

    def new(
        self,
        code: t.Optional[str] = None,
        length: t.Optional[int] = None,
        set_c: bool = True,
    ) -> CaptchaGenerator:
        """create a new captcha generator"""

        code = code or self.random(length)

        if set_c:
            self.set_code(code)

        return CaptchaGenerator(
            code,
            self.cimage,
            self.caudio,
        )

    def expire(self) -> "IsHuman":
        """expire current captcha"""

        if session.pop(self.skey, None) is not None:
            debug_log("expired the current CAPTCHA")

        return self

    def expired_dt(self, ts: float) -> bool:
        """return if the current captcha is expired based off delta time"""

        if self.app is None:
            raise ValueError("uninitialized app, try `init_app(app)`")

        dt: float = datetime.now().timestamp() - ts
        exp: t.Optional[float] = self.app.config["CAPTCHA_EXPIRY"]

        if exp is None:
            return False  # exp is None, so it will never expire

        debug_log(f"checking delta time {dt} in (0; {exp})")
        return dt < 0 or dt > exp

    def auto_expire(self, ts: float) -> bool:
        """auto-expire captcha if expired_dt() is true,
        returns result of expired_dt()"""

        if exp := self.expired_dt(ts):
            debug_log("detected that CAPTCHA Is expired, invalidating it")
            self.expire()

        return exp
