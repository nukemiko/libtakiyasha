# -*- coding: utf-8 -*-
from __future__ import annotations

from base64 import b64decode, b64encode

from ..common import BaseCipher
from ..exceptions import CipherDecryptError, CipherEncryptError
from ..stdciphers import TencentTEAWithModeCBC


class QMCv2KeyEncryptV1(BaseCipher):
    @property
    def offset_related(self) -> bool:
        return False

    def __init__(self, simple_key: bytes, /):
        super().__init__(simple_key)

        if len(self.key['main']) != TencentTEAWithModeCBC.blocksize():
            raise ValueError(f"invalid length of simple key "
                             f"(should be {TencentTEAWithModeCBC.blocksize()}, got {len(simple_key)})"
                             )

        self._tea_key_buf = bytearray(TencentTEAWithModeCBC.keysize())
        for idx in range(TencentTEAWithModeCBC.blocksize()):
            self._tea_key_buf[idx << 1] = self.key['main'][idx]

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        recipe = plaindata[:8]
        payload = plaindata[8:]

        for idx in range(TencentTEAWithModeCBC.blocksize()):
            self._tea_key_buf[(idx << 1) + 1] = recipe[idx]

        tea_cipher = TencentTEAWithModeCBC(self._tea_key_buf, rounds=32)

        return recipe + tea_cipher.encrypt(payload)  # 返回值应当在 b64encode 后使用

    def decrypt(self, cipherdata: bytes, /, *args) -> bytes:
        # cipherdata 应当为 b64decode 之后的结果
        recipe = cipherdata[:8]
        payload = cipherdata[8:]

        for idx in range(TencentTEAWithModeCBC.blocksize()):
            self._tea_key_buf[(idx << 1) + 1] = recipe[idx]

        tea_cipher = TencentTEAWithModeCBC(self._tea_key_buf, rounds=32)

        return recipe + tea_cipher.decrypt(payload, zero_check=True)


class QMCv2KeyEncryptV2(QMCv2KeyEncryptV1):
    def __init__(self, simple_key: bytes, mix_key1: bytes, mix_key2: bytes, /):
        self._mix_key1 = bytes(mix_key1)
        self._mix_key2 = bytes(mix_key2)

        self._encrypt_stage1_decrypt_stage2_tea_cipher = TencentTEAWithModeCBC(self._mix_key2,
                                                                               rounds=32
                                                                               )
        self._encrypt_stage2_decrypt_stage1_tea_cipher = TencentTEAWithModeCBC(self._mix_key1,
                                                                               rounds=32
                                                                               )

        super().__init__(simple_key)

    @property
    def key(self) -> dict[str, bytes]:
        return {
            'main'   : self._key,
            'MixKey1': self._mix_key1,
            'MixKey2': self._mix_key2
        }

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        qmcv2_key_encv1_key_encrypted = super().encrypt(plaindata)
        qmcv2_key_encv1_key_encrypted_b64encoded = b64encode(qmcv2_key_encv1_key_encrypted)

        try:
            encrypt_stage1 = self._encrypt_stage1_decrypt_stage2_tea_cipher.encrypt(qmcv2_key_encv1_key_encrypted_b64encoded)
        except Exception as exc:
            raise CipherEncryptError('QMCv2 key encrypt v2 stage 1 key encrypt failed') from exc
        try:
            encrypt_stage2 = self._encrypt_stage2_decrypt_stage1_tea_cipher.encrypt(encrypt_stage1)
        except Exception as exc:
            raise CipherEncryptError('QMCv2 key encrypt v2 stage 2 key encrypt failed') from exc

        return encrypt_stage2

    def decrypt(self, cipherdata: bytes, /, *args) -> bytes:
        # cipherdata 应当是 b64decode 之后，去除了开头 18 个字符的结果
        try:
            decrypt_stage1: bytes = self._encrypt_stage2_decrypt_stage1_tea_cipher.decrypt(cipherdata, zero_check=True)
        except Exception as exc:
            raise CipherDecryptError('QMCv2 key encrypt v2 stage 1 key decrypt failed') from exc
        try:
            decrypt_stage2: bytes = self._encrypt_stage1_decrypt_stage2_tea_cipher.decrypt(decrypt_stage1, zero_check=True)  # 实际上就是 QMCv2 Key Encrypt V1 的密钥
        except Exception as exc:
            raise CipherDecryptError('QMCv2 key encrypt v2 stage 2 key decrypt failed') from exc

        qmcv2_key_encv1_key_encrypted = b64decode(decrypt_stage2, validate=True)
        qmcv2_key_encv1_key = super().decrypt(qmcv2_key_encv1_key_encrypted)

        return qmcv2_key_encv1_key
