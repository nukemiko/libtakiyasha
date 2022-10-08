# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import cached_property
from os import PathLike
from typing import ByteString, IO, Iterable, Protocol, Sequence, SupportsBytes, SupportsIndex, SupportsInt, TypeVar, Union

__all__ = [
    'T',
    'KT',
    'VT',
    'AbleConvertToBytes',
    'AbleConvertToInt',
    'BytesLike',
    'IntegerLike',
    'FilePath',
    'Cipher',
    'CryptedIO'
]

T = TypeVar('T')
KT = TypeVar('KT')
VT = TypeVar('VT')

AbleConvertToBytes = Union[SupportsBytes, Iterable[int], Sequence[int]]
AbleConvertToInt = Union[SupportsInt, SupportsIndex]

BytesLike = Union[ByteString, AbleConvertToBytes]
IntegerLike = Union[int, AbleConvertToInt]

FilePath = Union[str, bytes, bytearray, PathLike]


class Cipher(Protocol):
    @cached_property
    def offset_related(self) -> bool:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError


class CryptedIO(Protocol):
    @property
    def cipher(self) -> Cipher:
        raise NotImplementedError

    def read(self, size: IntegerLike = -1, /) -> bytes:
        raise NotImplementedError

    def write(self, data: BytesLike, /) -> int:
        raise NotImplementedError

    def seek(self, offset: IntegerLike, whence: IntegerLike = 0, /) -> int:
        raise NotImplementedError

    def tell(self) -> int:
        raise NotImplementedError

    def readable(self) -> bool:
        raise NotImplementedError

    def writable(self) -> bool:
        raise NotImplementedError

    def seekable(self) -> bool:
        raise NotImplementedError
