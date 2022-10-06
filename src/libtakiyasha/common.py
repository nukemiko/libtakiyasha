# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from functools import cached_property, lru_cache
from io import BytesIO, IOBase, UnsupportedOperation
from random import randint
from typing import IO, Literal, Protocol

__all__ = ['BaseCipher', 'Cipher', 'Crypter', 'TransparentCryptIOWrapper']


class Cipher(Protocol):
    def encrypt(self, plaindata: bytes, offset: int, /) -> bytes:
        ...

    def decrypt(self, cipherdata: bytes, offset: int, /) -> bytes:
        ...

    @property
    def blocksize(self) -> int | None:
        return None

    @property
    def key(self) -> bytes:
        return b''


class Crypter(Protocol):
    @property
    def cipher(self) -> Cipher:
        return Cipher()

    def readable(self) -> bool:
        ...

    def writable(self) -> bool:
        ...

    def seekable(self) -> bool:
        ...

    def read(self, size: int = -1, /) -> bytes:
        ...

    def write(self, data: bytes, /) -> int:
        ...

    def seek(self, offset: int, whence: int = 0, /) -> int:
        ...

    @property
    def closed(self) -> bool:
        return bool()

    def close(self) -> None:
        ...

    @classmethod
    def loadfrom(cls,
                 filething: str | bytes | os.PathLike | IO[bytes],
                 /,
                 key: bytes | None = None,
                 **kwargs
                 ) -> Crypter:
        ...

    @classmethod
    def saveto(cls,
               filething: str | bytes | os.PathLike | IO[bytes] | None = None,
               /,
               **kwargs
               ) -> None:
        ...


class BaseCipher:
    def __init__(self, key: bytes, /) -> None:
        if not isinstance(key, bytes):
            raise TypeError("'__init__()' requires a bytes-like object as the key of cipher, "
                            f"not '{type(key).__name__}'"
                            )
        self._key = bytes(key)

    @cached_property
    def blocksize(self) -> int | None:
        return None

    @cached_property
    def key(self) -> bytes:
        return self._key


class TransparentCryptIOWrapper(IOBase, IO[bytes]):
    def __init__(self,
                 cipher: Cipher,
                 initial_encrypted_data: bytes = b'',
                 /
                 ) -> None:
        self._internal_bytesio = BytesIO(initial_encrypted_data)
        self._internal_bytesio_endpos = self._internal_bytesio.seek(0, 2)
        self._internal_bytesio.seek(0, 0)
        self._cipher = cipher
        self._name: str | None = None

    @lru_cache
    def __repr__(self) -> str:
        ret = f"<{type(self).__name__} file object at {hex(id(self))}, " \
              f"cipher {repr(self._cipher)}"
        if self._name is not None:
            ret += f", from file '{self._name}'"

        ret += '>'

        return ret

    @property
    def cipher(self) -> Cipher:
        return self._cipher

    @cached_property
    def name(self) -> str | None:
        return self._name

    @property
    def raw(self) -> BytesIO:
        return self._internal_bytesio

    def _raise_while_closed(self) -> None:
        if self._internal_bytesio.closed:
            raise ValueError('I/O operation on closed file.')

    def _test_cipher_supported_functions(self,
                                         operation: Literal['encrypt', 'decrypt']
                                         ) -> tuple[bytes, bytes]:
        self._raise_while_closed()

        if operation == 'encrypt':
            method = self._cipher.encrypt
        elif operation == 'decrypt':
            method = self._cipher.decrypt
        else:
            raise ValueError(f"'operation' must be str 'encrypt' or 'decrypt', not {repr(operation)}")

        test_blksize: int | None = self._cipher.blocksize
        if test_blksize is None:
            test_blksize: int = 4096
        test_data = bytes([randint(0, 255) for _ in range(test_blksize)])

        result = method(test_data, randint(0, self._internal_bytesio_endpos))

        return test_data, result

    def readable(self) -> bool:
        self._raise_while_closed()

        try:
            self._test_cipher_supported_functions(operation='decrypt')
        except NotImplementedError:
            return False
        else:
            return True

    def writable(self) -> bool:
        self._raise_while_closed()

        try:
            self._test_cipher_supported_functions(operation='encrypt')
        except NotImplementedError:
            return False
        else:
            return True

    def seekable(self) -> bool:
        self._raise_while_closed()

        return self._internal_bytesio.seekable()

    def read(self, size: int = -1, /) -> bytes:
        self._raise_while_closed()

        if not self.readable():
            raise UnsupportedOperation('read')

        offset = self._internal_bytesio.tell()

        return self._cipher.decrypt(self._internal_bytesio.read(size), offset)

    def write(self, data: bytes, /) -> int:
        self._raise_while_closed()

        if not self.writable():
            raise UnsupportedOperation('write')

        offset = self._internal_bytesio.tell()

        return self._internal_bytesio.write(self._cipher.encrypt(data, offset))

    def seek(self, offset: int, whence: int = 0, /) -> int:
        self._raise_while_closed()

        if not self.seekable():
            raise UnsupportedOperation('seek')

        return self._internal_bytesio.seek(offset, whence)

    def truncate(self, size: int | None = None) -> int:
        self._raise_while_closed()

        if not self.seekable():
            raise UnsupportedOperation('truncate')

        return self._internal_bytesio.truncate(size)

    @property
    def closed(self) -> bool:
        return self._internal_bytesio.closed

    def close(self) -> None:
        self._internal_bytesio.close()

    @classmethod
    def loadfrom(cls,
                 filething: str | bytes | os.PathLike | IO[bytes],
                 /,
                 **kwargs
                 ) -> Crypter:
        raise NotImplementedError

    @classmethod
    def saveto(cls,
               filething: str | bytes | os.PathLike | IO[bytes] | None = None,
               /,
               **kwargs
               ) -> None:
        raise NotImplementedError
