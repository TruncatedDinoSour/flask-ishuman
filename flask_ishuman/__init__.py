#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flask_ishuman"""

import os
import string
import typing as t
import warnings
from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha3_512
from logging import debug as debug_log
from secrets import SystemRandom

import captcha
import captcha.audio
import captcha.image
from flask import Flask, session

__version__: t.Final[str] = "1.0.0"

CHARSET: t.Final[str] = string.ascii_letters + string.digits + "@#%?"


@dataclass
class CaptchaGenerator:
    code: str
    cimage: captcha.image.ImageCaptcha
    caudio: captcha.audio.AudioCaptcha

    def png(self) -> str:
        """return base64 encoded png of the image captcha"""

        debug_log(f"base64 encoding CAPTCHA's {self.code!r} PNG image")
        return b64encode(self.cimage.generate(self.code, "png").read()).decode("ascii")

    def wav(self) -> str:
        """return base64 encoded wav of the audio captcha"""

        debug_log(f"base64 encoding CAPTCHA's {self.code!r} WAV audio")
        return b64encode(self.caudio.generate(self.code)).decode("ascii")

    def image(self, alt: str = "Image CAPTCHA") -> str:
        """return image html"""

        debug_log(f"generating image html for captcha {self.code!r}")
        return f'<img id=image-captcha src="data:image/png;base64,{self.png()}" \
alt="{alt}" />'

    def audio(self, alt: str = "Audio CAPTCHA", controls: bool = True) -> str:
        """return audio html"""

        debug_log(f"generating audio html for captcha {self.code!r}")
        return f'<audio id=audio-captcha{" controls" if controls else ""}> \
<source src="data:audio/wav;base64,{self.wav()}" type=audio/wav /> {alt} </audio>'


@dataclass
class IsHuman:
    """captcha support in flask"""

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
        self.skey: str = f"__captcha_{self.rand.random() * 1024}__"

        self.app: t.Optional[Flask] = None
        self.pepper: t.Optional[bytes] = None

    def init_app(self, app: Flask) -> "IsHuman":
        """initialize flask app"""

        if "SECRET_KEY" not in app.config:
            warnings.warn("no `SECRET_KEY` set, session may be unavailable")

        if "CAPTCHA_SALT_LEN" not in app.config:
            debug_log("setting `CAPTCHA_SALT_LEN` to `32`")
            app.config["CAPTCHA_SALT_LEN"] = 32

        if "CAPTCHA_CHARSET" not in app.config:
            debug_log(f"setting `CAPTCHA_CHARSET` to `{CHARSET}`")
            app.config["CAPTCHA_CHARSET"] = CHARSET

        if "CAPTCHA_RANGE" not in app.config:
            debug_log("setting `CAPTCHA_RANGE` to `(4, 8)`")
            app.config["CAPTCHA_RANGE"] = 4, 8

        if "CAPTCHA_PEPPER_FILE" not in app.config:
            debug_log("setting `CAPTCHA_PEPPER_FILE` to `captcha_pepper`")
            app.config["CAPTCHA_PEPPER_FILE"] = "captcha_pepper"

        if not os.path.exists(app.config["CAPTCHA_PEPPER_FILE"]):
            with open(app.config["CAPTCHA_PEPPER_FILE"], "wb") as fp:
                debug_log(
                    f"wrote {fp.write(self.rand.randbytes(2048))} bytes to "
                    f"{fp.name!r} pepper file",
                )

        with open(app.config["CAPTCHA_PEPPER_FILE"], "rb") as fp:
            self.pepper = fp.read()
            debug_log(f"read {fp.tell()} bytes from {fp.name!r} pepper file")

        self.app = app
        debug_log("app initialized")

        return self

    def digest(self, code: str, salt: t.Optional[bytes] = None) -> bytes:
        """digest a `code`"""

        if self.pepper is None or self.app is None:
            raise ValueError("uninitialized app, try `init_app(app)`")

        debug_log(f"digesting captcha {code!r}")

        salt = salt or self.rand.randbytes(self.app.config["CAPTCHA_SALT_LEN"])
        return salt + sha3_512(salt + code.encode("ascii") + self.pepper).digest()

    def split_digest(self, s: t.Optional[bytes] = None) -> t.Tuple[bytes, bytes]:
        """split digest into its salt and digest parts"""

        if self.app is None:
            raise ValueError("uninitialized app, try `init_app(app)`")

        sl: int = self.app.config["CAPTCHA_SALT_LEN"]
        s = s or self.get_captcha()

        if s is None:
            raise ValueError("no digest")

        debug_log(f"splitting {s!r} into salt and digest")
        return s[:sl], s[sl:]

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

    def set_captcha(self, code: str) -> "IsHuman":
        """set captcha to `code`"""
        session[self.skey] = self.digest(code)
        return self

    def get_captcha(self) -> t.Optional[bytes]:
        """get captcha"""
        return session.get(self.skey)

    def verify_captcha(self, code: str) -> bool:
        """returns `True` is captcha code is valid, else `False`"""

        try:
            d: t.Optional[bytes] = self.get_captcha()
            salt, _ = self.split_digest(d)
        except ValueError:
            return False

        debug_log(f"verifying captcha {code!r}")

        return self.digest(code, salt) == d

    def new(
        self,
        code: t.Optional[str] = None,
        length: t.Optional[int] = None,
    ) -> CaptchaGenerator:
        """create a new captcha generator"""

        code = code or self.random(length)

        self.set_captcha(code)

        return CaptchaGenerator(
            code,
            self.cimage,
            self.caudio,
        )
