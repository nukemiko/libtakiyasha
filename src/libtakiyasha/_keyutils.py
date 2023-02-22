# -*- coding: utf-8 -*-
from __future__ import annotations

import secrets
import string

__all__ = [
    'make_random_number_string',
    'make_random_alphabet_string',
    'make_random_ascii_string',
    'make_salt'
]


def make_random_number_string(nchars: int) -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(nchars))


def make_random_alphabet_string(nchars: int) -> str:
    return ''.join(secrets.choice(string.ascii_letters) for _ in range(nchars))


def make_random_ascii_string(nchars: int) -> str:
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(nchars))


def make_salt(nbytes: int) -> bytes:
    return secrets.token_bytes(nbytes)
