# -*- coding: utf-8 -*-
from __future__ import annotations


class LibTakiyashaException(Exception):
    pass


class CipherEncryptingError(LibTakiyashaException):
    pass


class CipherDecryptingError(LibTakiyashaException):
    pass


class CrypterCreatingError(LibTakiyashaException):
    pass


class CrypterSavingError(LibTakiyashaException):
    pass
