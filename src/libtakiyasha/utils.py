# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Iterable, SupportsBytes


def bytestrxor(bytestr1: SupportsBytes | Iterable[int],
               bytestr2: SupportsBytes | Iterable[int],
               /
               ) -> bytes:
    bytestr1 = bytes(bytestr1)
    bytestr2 = bytes(bytestr2)

    if len(bytestr1) != len(bytestr2):
        raise ValueError('only byte strings of equal length can be xored')

    return bytes(b1 ^ b2 for b1, b2 in zip(bytestr1, bytestr2))
