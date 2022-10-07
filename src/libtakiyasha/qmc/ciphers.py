# -*- coding: utf-8 -*-
from __future__ import annotations

from base64 import b64decode, b64encode
from typing import Generator, Iterable, SupportsBytes

from .consts import KEY256_MAPPING
from ..common import BaseCipher
from ..exceptions import CipherDecryptError, CipherEncryptError
from ..stdciphers import TencentTEAWithModeCBC
from ..utils import bytestrxor

__all__ = [
    'QMCMask128',
    'qmcv1mask256to128',
    'qmcv1mask44to128',
    'qmcv2key256tomask128',
    'QMCv2KeyEncryptV1',
    'QMCv2KeyEncryptV2'
]


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


def qmcv1mask44to128(mask44: SupportsBytes | Iterable[int]) -> bytes:
    mask44: bytes = bytes(mask44)
    if len(mask44) != 44:
        raise ValueError(f'invalid mask length (should be 44, got {len(mask44)})')

    mask128 = bytearray(128)
    idx44 = 0
    for it256 in KEY256_MAPPING:
        if it256:
            for idx128 in it256:
                mask128[idx128] = mask44[idx44]
            idx44 += 1

    return bytes(mask128)


def qmcv1mask256to128(mask256: SupportsBytes | Iterable[int]) -> bytes:
    mask256: bytes = bytes(mask256)
    if len(mask256) != 256:
        raise ValueError(f'invalid mask length (should be 256, got {len(mask256)})')

    mask128 = bytearray(128)
    for idx128 in range(128):
        if idx128 > 0x7fff:
            idx128 %= 0x7fff
        idx = (idx128 ** 2 + 27) & 0xff
        mask128[idx128] = mask256[idx]

    return bytes(mask128)


def qmcv2key256tomask128(key256: SupportsBytes | Iterable[int]) -> bytes:
    key256: bytes = bytes(key256)
    if len(key256) != 256:
        raise ValueError(f'invalid key length (should be 256, got {len(key256)})')

    mask128 = bytearray(128)
    for idx128 in range(128):
        if idx128 > 0x7fff:
            idx128 %= 0x7fff
        idx = (idx128 ** 2 + 71214) & 0xff

        value = key256[idx]
        rotate = ((idx & 7) + 4) % 8

        mask128[idx128] = ((value << rotate) % 256) | ((value >> rotate) % 256)

    return bytes(mask128)


class QMCMask128(BaseCipher):
    def __init__(self, mask128: SupportsBytes | Iterable[int], /):
        super().__init__(mask128)

        if len(self.key['main']) != 128:
            raise ValueError(f"invalid mask length (should be 128, got {len(self.key['main'])})")

    @classmethod
    def from_qmcv1_mask44(cls, mask44: SupportsBytes | Iterable[int]) -> QMCMask128:
        return cls(qmcv1mask44to128(mask44))

    @classmethod
    def from_qmcv1_mask256(cls, mask256: SupportsBytes | Iterable[int]) -> QMCMask128:
        return cls(qmcv1mask256to128(mask256))

    @classmethod
    def from_qmcv2_key256(cls, key256: SupportsBytes | Iterable[int]) -> QMCMask128:
        return cls(qmcv2key256tomask128(key256))

    @property
    def offset_related(self) -> bool:
        return True

    @classmethod
    def yield_keystream(cls,
                        mask128: SupportsBytes | Iterable[int],
                        d_len: int,
                        d_offset: int
                        ) -> Generator[int, None, None]:
        mask128: bytes = bytes(mask128)
        if len(mask128) != 128:
            raise ValueError(f"invalid mask length (should be 128, got {len(mask128)})")

        idx = d_offset - 1
        idx128 = (d_offset % 128) - 1

        for _ in range(d_len):
            idx += 1
            idx128 += 1
            if idx == 0x8000 or (idx > 0x8000 and idx % 0x8000 == 0x7fff):
                idx += 1
                idx128 += 1
            idx128 %= 128

            yield mask128[idx128]

    def encrypt(self, plaindata: bytes, offset: int, /) -> bytes:
        return self.decrypt(plaindata, offset)

    def decrypt(self, cipherdata: bytes, offset: int, /) -> bytes:
        return bytestrxor(cipherdata, self.yield_keystream(self.key['main'],
                                                           len(cipherdata),
                                                           offset
                                                           )
                          )
