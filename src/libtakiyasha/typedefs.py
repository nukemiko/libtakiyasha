# -*- coding: utf-8 -*-
from __future__ import annotations

import array
import mmap
from os import PathLike
from typing import ByteString, Iterable, Protocol, Sequence, SupportsBytes, SupportsIndex, SupportsInt, TypeVar, Union, runtime_checkable

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
    'WritableBuffer',
    'FilePath',
    'CipherProto',
    'StreamCipherProto',
    'StreamCipherBasedCryptedIOProto'
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
WritableBuffer = Union[bytearray, memoryview, array.array, mmap.mmap]

FilePath = Union[str, bytes, bytearray, PathLike]


@runtime_checkable
class CipherProto(Protocol):
    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        raise NotImplementedError


@runtime_checkable
class StreamCipherProto(Protocol):
    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Iterable[int]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError


@runtime_checkable
class StreamCipherBasedCryptedIOProto(Protocol):
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
