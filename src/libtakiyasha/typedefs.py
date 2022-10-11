# -*- coding: utf-8 -*-
from __future__ import annotations

from os import PathLike
from typing import ByteString, Iterable, Protocol, Sequence, SupportsBytes, SupportsIndex, SupportsInt, TypeVar, Union

__all__ = [
    'T',
    'KT',
    'VT',
    'PT',
    'RT',
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
PT = TypeVar('PT')
RT = TypeVar('RT')

AbleConvertToBytes = Union[SupportsBytes, Iterable[int], Sequence[int]]
AbleConvertToInt = Union[SupportsInt, SupportsIndex]

BytesLike = Union[ByteString, AbleConvertToBytes]
IntegerLike = Union[int, AbleConvertToInt]

FilePath = Union[str, bytes, bytearray, PathLike]


class Cipher(Protocol):
    @property
    def offset_related(self) -> bool:
        raise NotImplementedError

    @property
    def keys(self) -> list[str]:
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
