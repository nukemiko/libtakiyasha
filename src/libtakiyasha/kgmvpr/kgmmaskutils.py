# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Generator

from ..typedefs import BytesLike, IntegerLike
from ..typeutils import tobytes, toint_nofloat

__all__ = ['make_maskstream', 'xor_half_lower_byte']


def xor_half_lower_byte(byte: int) -> int:
    return byte ^ ((byte % 16) << 4)


def make_maskstream(offset: IntegerLike,
                    length: IntegerLike, /,
                    table1: BytesLike,
                    table2: BytesLike,
                    tablev2: BytesLike
                    ) -> Generator[int, None, None]:
    offset = toint_nofloat(offset)
    length = toint_nofloat(length)
    if offset < 0:
        raise ValueError("first argument 'offset' must be a non-negative integer")
    if length < 0:
        raise ValueError("second argument 'length' must be a non-negative integer")
    table1 = tobytes(table1)
    table2 = tobytes(table2)
    tablev2 = tobytes(tablev2)
    if not (len(table1) == len(table2) == len(tablev2)):
        raise ValueError("argument 'table1', 'table2', 'tablev2' must have the same length")
    tablesize = len(tablev2)

    for idx in range(offset, offset + length):
        idx_urs4 = idx >> 4
        value = 0
        while idx_urs4 >= 17:
            value ^= table1[idx_urs4 % tablesize]
            idx_urs4 >>= 4
            value ^= table2[idx_urs4 % tablesize]
            idx_urs4 >>= 4
        yield value ^ tablev2[idx % tablesize]
