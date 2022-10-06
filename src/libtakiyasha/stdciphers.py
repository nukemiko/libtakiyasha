# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import partial
from io import BytesIO
from typing import Generator

from pyaes import AESModeOfOperationECB
from pyaes.util import append_PKCS7_padding, strip_PKCS7_padding

from .common import BaseCipher

__all__ = ['StreamedAESWithModeECB']


class StreamedAESWithModeECB(BaseCipher):
    @property
    def blocksize(self) -> int | None:
        return 16

    def __init__(self, key, /) -> None:
        super().__init__(key)

        self._raw_cipher = AESModeOfOperationECB(key=self.key)

    def yield_block(self, data: bytes) -> Generator[bytes, None, None]:
        for blk in iter(partial(BytesIO(data).read, self.blocksize), b''):
            yield blk

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        return b''.join(
            self._raw_cipher.encrypt(b) for b in self.yield_block(append_PKCS7_padding(plaindata))
        )

    def decrypt(self, cipherdata: bytes, /, *args) -> bytes:
        return strip_PKCS7_padding(
            b''.join(self._raw_cipher.decrypt(b) for b in self.yield_block(cipherdata))
        )
