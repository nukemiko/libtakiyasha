#!/bin/env python
# -*- coding: utf-8 -*-
from __future__ import annotations


class LibTakiyashaWarning(Warning):
    pass


class CipherEncryptingWarning(LibTakiyashaWarning):
    pass


class CipherDecryptingWarning(LibTakiyashaWarning):
    pass


class CrypterCreatingWarning(LibTakiyashaWarning):
    pass


class CrypterSavingWarning(LibTakiyashaWarning):
    pass
