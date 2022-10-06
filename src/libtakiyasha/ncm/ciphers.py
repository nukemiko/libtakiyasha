# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Generator

from ..common import BaseCipher
from ..utils import bytestrxor

__all__ = ['RC4WithNCMSpecs', 'XorWithRepeatedByteChar']


class RC4WithNCMSpecs(BaseCipher):
    def __init__(self, key: bytes, /):
        super().__init__(key)

        # 使用 RC4-KSA 生成 S-box
        S = bytearray(range(256))
        j = 0
        key_len = len(key)
        for idx in range(256):
            j = (j + S[idx] + key[idx % key_len]) & 0xff
            S[idx], S[j] = S[j], S[idx]

        # 使用 PRGA 从 S-box 生成密钥流
        meta_keystream = bytearray(256)
        for idx in range(256):
            idx1 = (idx + 1) & 0xff
            si = S[idx1] & 0xff
            sj = S[(idx1 + si) & 0xff] & 0xff
            meta_keystream[idx] = S[(si + sj) & 0xff]

        self._meta_keystream = bytes(meta_keystream)

    @property
    def offset_related(self) -> bool:
        return True

    def gen_keystream(self, d_len: int, d_offset: int) -> Generator[int, None, None]:
        for idx in range(d_offset, d_offset + d_len):
            yield self._meta_keystream[idx & 0xff]

    def encrypt(self, plaindata: bytes, offset: int, /) -> bytes:
        return self.decrypt(plaindata, offset)

    def decrypt(self, cipherdata: bytes, offset: int, /) -> bytes:
        return bytestrxor(cipherdata, self.gen_keystream(len(bytes(cipherdata)), offset))


class XorWithRepeatedByteChar(BaseCipher):
    def __init__(self):
        super().__init__(b'')

    @property
    def offset_related(self) -> bool:
        return False

    @classmethod
    def make_keystream(cls, d_len: int) -> bytes:
        return b'\xa3' * d_len

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        return self.decrypt(plaindata)

    def decrypt(self, cipherdata: bytes, /, *args) -> bytes:
        return bytestrxor(cipherdata, self.make_keystream(len(bytes(cipherdata))))
