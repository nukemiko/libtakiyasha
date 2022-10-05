# -*- coding: utf-8 -*-
from __future__ import annotations


class LibTakiyashaException(Exception):
    pass


class CipherEncryptError(LibTakiyashaException):
    pass


class CipherDecryptError(LibTakiyashaException):
    pass
