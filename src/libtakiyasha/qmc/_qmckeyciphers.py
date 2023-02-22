# -*- coding: utf-8 -*-
from __future__ import annotations

from base64 import b64decode, b64encode
from math import tan
from typing import Iterable

from .._prototypes import CipherSkel
from .._stdciphers import TarsCppTCTEAWithModeCBC
from .._typeutils import tobytes
from ..typedefs import BytesLike

__all__ = [
    'make_core_key',
    'QMCv2KeyEncryptV1',
    'QMCv2KeyEncryptV2'
]


def make_core_key(salt: int, length: int) -> bytes:
    return bytes(int(abs(tan(salt + _ * 0.1) * 100)) for _ in range(length))


class QMCv2KeyEncryptV1(CipherSkel):
    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'master':
            return self._core_key

    def __init__(self, key: BytesLike, /):
        self._core_key = tobytes(key)

        self._half_of_keysize = TarsCppTCTEAWithModeCBC.master_key_size // 2
        if len(self._core_key) != self._half_of_keysize:
            raise ValueError(f"invalid length of core key: "
                             f"should be {self._half_of_keysize}, not {len(self._core_key)}"
                             )

        self._key_buf = bytearray(TarsCppTCTEAWithModeCBC.master_key_size)
        for idx in range(TarsCppTCTEAWithModeCBC.blocksize):
            self._key_buf[idx << 1] = self._core_key[idx]

    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        plaindata = tobytes(plaindata)
        if len(plaindata) < 8:  # 明文长度不可小于 8
            raise ValueError('invalid plaindata length: should be greater than or equal to 8, '
                             f'not {len(plaindata)}'
                             )

        recipe = plaindata[:8]
        payload = plaindata[8:]

        for idx in range(self._half_of_keysize):
            self._key_buf[(idx << 1) + 1] = recipe[idx]

        tea_cipher = TarsCppTCTEAWithModeCBC(self._key_buf, rounds=32)

        return recipe + tea_cipher.encrypt(payload)  # 返回值应当在 b64encode 后使用

    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        # cipherdata 应当为 b64decode 之后的结果
        cipherdata = tobytes(cipherdata)
        if len(cipherdata) < 8:  # 密文长度不可小于 8
            raise ValueError('invalid cipherdata length: should be greater than or equal to 8, '
                             f'not {len(cipherdata)}'
                             )

        recipe = cipherdata[:8]
        payload = cipherdata[8:]

        for idx in range(self._half_of_keysize):
            self._key_buf[(idx << 1) + 1] = recipe[idx]

        tea_cipher = TarsCppTCTEAWithModeCBC(self._key_buf, rounds=32)

        return recipe + tea_cipher.decrypt(payload, zero_check=True)


class QMCv2KeyEncryptV2(QMCv2KeyEncryptV1):
    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'master':
            return self._core_key
        elif keyname.startswith('garble'):
            garble_key_strno = keyname[6:]
            if garble_key_strno.isdecimal():
                garble_key_no = int(garble_key_strno)
                if 1 <= garble_key_no <= len(self._garble_ciphers):
                    return self._garble_ciphers[garble_key_no - 1].getkey()

    def __init__(self, key: BytesLike, garble_keys: Iterable[BytesLike], /) -> None:
        super().__init__(key)

        if not isinstance(garble_keys, Iterable):
            raise TypeError(
                f"argument 'garble_keys' must be an Iterable or bytes-like object, not {type(garble_keys).__name__}"
            )
        self._garble_ciphers: list[TarsCppTCTEAWithModeCBC] = []
        for idx, garble_key in enumerate(garble_keys, start=1):
            self._garble_ciphers.append(
                TarsCppTCTEAWithModeCBC(garble_key, rounds=32)
            )

    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        # self.decrypt() 的反向操作
        result = tobytes(plaindata)

        result = b64encode(super().encrypt(result))

        for garble_cipher in self._garble_ciphers[::-1]:
            result = garble_cipher.encrypt(result)

        return result

    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        result = tobytes(cipherdata)
        # cipherdata 应当是 b64decode 之后，去除了开头 18 个字符的结果

        for garble_cipher in self._garble_ciphers:
            result = garble_cipher.decrypt(result, zero_check=True)
        # 结束循环时，cipherdata 应当是使用 QMCv2 Key Encrypt V1 加密的密钥
        return super().decrypt(b64decode(result, validate=True))
