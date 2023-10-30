#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flask_ishuman"""

import os
import string
import typing as t
import warnings
from dataclasses import dataclass
from hashlib import sha3_512
from logging import debug as debug_log
from secrets import SystemRandom

import captcha
import captcha.audio
import captcha.image
from flask import Flask, session

__version__: str = "1.0.0"


class Captcha:
    """base captcha class"""

    def __init__(self, code: str, ishuman: "IsHuman") -> None:
        self.code: str = code
        self.ishuman: "IsHuman" = ishuman

    def digest(
        self,
        code: t.Optional[str] = None,
        salt: t.Optional[bytes] = None,
    ) -> bytes:
        """hashes and returns the digest of a code"""

        if self.ishuman.app is None:
            raise ValueError("app uninitialized")

        salt = salt or self.ishuman.rand.randbytes(
            self.ishuman.app.config["CAPTCHA_SALT_LEN"]
        )
        return salt + sha3_512(salt + (code or self.code).encode("utf-8")).digest()

    def split_digest(self, d: bytes) -> t.Tuple[bytes, bytes]:
        """splits the digest into its salt and digest parts"""

        if self.ishuman.app is None:
            raise ValueError("app uninitialized")

        sl: int = self.ishuman.app.config["CAPTCHA_SALT_LEN"]
        return d[:sl], d[sl:]

    def compare(self, code: str) -> bool:
        """returns if `code` is valid or not"""

        c: t.Optional[bytes] = self.ishuman.get_captcha()
        return c is not None and c == self.digest(code, self.split_digest(c)[0])

    def set(self) -> "Captcha":
        """set the captcha to the current captcha"""

        self.ishuman.set_captcha(self)
        return self


@dataclass
class IsHuman:
    """captcha support in flask"""

    def __init__(
        self,
        image_args: t.Dict[str, t.Any],
        audio_args: t.Dict[str, t.Any],
    ) -> None:
        self.cimage: captcha.image.ImageCaptcha = captcha.image.ImageCaptcha(
            **image_args
        )
        self.caudio: captcha.audio.AudioCaptcha = captcha.audio.AudioCaptcha(
            os.path.join(os.path.abspath(os.path.dirname(__file__)), "data"),
            **audio_args,
        )
        self.rand: SystemRandom = SystemRandom()
        self.skey: str = f"__captcha_{self.rand.random() * 1024}__"
        self.app: t.Optional[Flask] = None

    def init_app(self, app: Flask) -> Flask:
        """initialize flask app"""

        if "SECRET_KEY" not in app.config:
            warnings.warn("no `SECRET_KEY` set, session may be unavailable")

        if "CAPTCHA_SALT_LEN" not in app.config:
            debug_log("setting CAPTCHA_SALT_LEN to 32")
            app.config["CAPTCHA_SALT_LEN"] = 32

        self.app = app
        return app

    def new(self, code: str) -> Captcha:
        """new captcha"""
        return Captcha(code, self)

    def random(self, length: t.Optional[int] = None) -> Captcha:
        """return a random captcha"""
        return self.new(
            "".join(
                self.rand.choices(
                    string.ascii_letters + string.digits,
                    k=length or max(4, round(self.rand.random() * 8)),
                )
            )
        )

    def set_captcha(self, c: Captcha) -> "IsHuman":
        """set captcha"""

        session[self.skey] = c.digest()
        return self

    def get_captcha(self) -> t.Optional[bytes]:
        """get captcha"""
        return session.get(self.skey)
