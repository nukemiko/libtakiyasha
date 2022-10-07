#!/bin/env python
# -*- coding: utf-8 -*-
from __future__ import annotations


class LibTakiyashaWarning(Warning):
    pass


class CipherEncryptWarning(LibTakiyashaWarning):
    pass


class CipherDecryptWarning(LibTakiyashaWarning):
    pass


class CrypterCreateWarning(LibTakiyashaWarning):
    pass


class CrypterSaveWarning(LibTakiyashaWarning):
    pass
