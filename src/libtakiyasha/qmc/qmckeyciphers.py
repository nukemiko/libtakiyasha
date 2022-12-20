# -*- coding: utf-8 -*-
from __future__ import annotations

from base64 import b64decode, b64encode
from math import tan

from ..exceptions import CipherDecryptingError, CipherEncryptingError
from ..prototypes import CipherSkel
from ..stdciphers import TarsCppTCTEAWithModeCBC
from ..typedefs import BytesLike
from ..typeutils import tobytes

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
        elif keyname == 'garble1':
            return self._garble_key1
        elif keyname == 'garble2':
            return self._garble_key2

    def __init__(self, key: BytesLike, garble_key1: BytesLike, garble_key2: BytesLike, /):
        self._garble_key1 = tobytes(garble_key1)
        self._garble_key2 = tobytes(garble_key2)

        self._encrypt_stage1_decrypt_stage2_tea_cipher = TarsCppTCTEAWithModeCBC(self._garble_key2,
                                                                                 rounds=32
                                                                                 )
        self._encrypt_stage2_decrypt_stage1_tea_cipher = TarsCppTCTEAWithModeCBC(self._garble_key1,
                                                                                 rounds=32
                                                                                 )

        super().__init__(key)

    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        plaindata = tobytes(plaindata)

        qmcv2_key_encv1_key_encrypted = super().encrypt(plaindata)
        qmcv2_key_encv1_key_encrypted_b64encoded = b64encode(qmcv2_key_encv1_key_encrypted)

        try:
            encrypt_stage1 = self._encrypt_stage1_decrypt_stage2_tea_cipher.encrypt(
                qmcv2_key_encv1_key_encrypted_b64encoded
            )
        except Exception as exc:
            raise CipherEncryptingError('QMCv2 key encrypt v2 stage 1 key encrypt failed') from exc
        try:
            encrypt_stage2 = self._encrypt_stage2_decrypt_stage1_tea_cipher.encrypt(
                encrypt_stage1
            )
        except Exception as exc:
            raise CipherEncryptingError('QMCv2 key encrypt v2 stage 2 key encrypt failed') from exc

        return encrypt_stage2

    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        cipherdata = tobytes(cipherdata)
        # cipherdata 应当是 b64decode 之后，去除了开头 18 个字符的结果

        try:
            decrypt_stage1: bytes = self._encrypt_stage2_decrypt_stage1_tea_cipher.decrypt(
                cipherdata, zero_check=True
            )
        except Exception as exc:
            raise CipherDecryptingError('QMCv2 key encrypt v2 stage 1 key decrypt failed') from exc
        try:
            decrypt_stage2: bytes = self._encrypt_stage1_decrypt_stage2_tea_cipher.decrypt(
                decrypt_stage1, zero_check=True
            )  # 实际上就是 QMCv2 Key Encrypt V1 的密钥
        except Exception as exc:
            raise CipherDecryptingError('QMCv2 key encrypt v2 stage 2 key decrypt failed') from exc

        qmcv2_key_encv1_key_encrypted = b64decode(decrypt_stage2, validate=True)
        qmcv2_key_encv1_key = super().decrypt(qmcv2_key_encv1_key_encrypted)

        return qmcv2_key_encv1_key
