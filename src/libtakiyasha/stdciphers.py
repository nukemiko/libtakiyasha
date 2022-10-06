# -*- coding: utf-8 -*-
from __future__ import annotations

import random
from functools import partial
from io import BytesIO
from typing import Generator

from pyaes import AESModeOfOperationECB
from pyaes.util import append_PKCS7_padding, strip_PKCS7_padding

from .common import BaseCipher
from .exceptions import CipherDecryptError

__all__ = ['StreamedAESWithModeECB', 'TEAWithModeECB', 'TencentTEAWithModeCBC']

from .utils import bytestrxor

# 为 TencentTEAWithModeCBC 的加密初始化随机数生成器
random.seed()

rand = partial(random.randint, 0, 255)


class StreamedAESWithModeECB(BaseCipher):
    _blocksize = 16

    def __init__(self, key, /) -> None:
        super().__init__(key)

        self._raw_cipher = AESModeOfOperationECB(key=self.key)

    def yield_block(self, data: bytes) -> Generator[bytes, None, None]:
        for blk in iter(partial(BytesIO(data).read, self.blocksize()), b''):
            yield blk

    @property
    def offset_related(self) -> bool:
        return False

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        return b''.join(
            self._raw_cipher.encrypt(b) for b in self.yield_block(append_PKCS7_padding(plaindata))
        )

    def decrypt(self, cipherdata: bytes, /, *args) -> bytes:
        return strip_PKCS7_padding(
            b''.join(self._raw_cipher.decrypt(b) for b in self.yield_block(cipherdata))
        )


class TEAWithModeECB(BaseCipher):
    _blocksize = 16

    def __init__(self,
                 key: bytes,
                 /,
                 rounds: int = 64,
                 magic_number: int = 0x9e3779b9
                 ) -> None:
        if len(key) != self.blocksize():
            raise ValueError(f"invalid key length {len(key)} (should be {self.blocksize()})")
        if rounds % 2 != 0:
            raise ValueError(f'even number of rounds required (got {rounds})')

        super().__init__(key)
        self._rounds = rounds
        self._delta = magic_number

    @property
    def offset_related(self) -> bool:
        return False

    @classmethod
    def transvalues(cls, data: bytes, key: bytes) -> tuple[int, int, int, int, int, int]:
        v0 = int.from_bytes(data[:4], 'big')
        v1 = int.from_bytes(data[4:8], 'big')
        k0 = int.from_bytes(key[:4], 'big')
        k1 = int.from_bytes(key[4:8], 'big')
        k2 = int.from_bytes(key[8:12], 'big')
        k3 = int.from_bytes(key[12:], 'big')

        return v0, v1, k0, k1, k2, k3

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        v0, v1, k0, k1, k2, k3 = self.transvalues(plaindata, self.key)

        delta = self._delta
        rounds = self._rounds
        ciphersum = 0

        for i in range(rounds // 2):
            ciphersum += delta
            ciphersum &= 0xffffffff
            v0 += ((v1 << 4) + k0) ^ (v1 + ciphersum) ^ ((v1 >> 5) + k1)
            v0 &= 0xffffffff
            v1 += ((v0 << 4) + k2) ^ (v0 + ciphersum) ^ ((v0 >> 5) + k3)
            v1 &= 0xffffffff

        return v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')

    def decrypt(self, cipherdata: bytes, /, *args) -> bytes:
        v0, v1, k0, k1, k2, k3 = self.transvalues(cipherdata, self.key)

        delta = self._delta
        rounds = self._rounds
        ciphersum = (delta * (rounds // 2)) & 0xffffffff

        for i in range(rounds // 2):
            v1 -= ((v0 << 4) + k2) ^ (v0 + ciphersum) ^ ((v0 >> 5) + k3)
            v1 &= 0xffffffff
            v0 -= ((v1 << 4) + k0) ^ (v1 + ciphersum) ^ ((v1 >> 5) + k1)
            v0 &= 0xffffffff
            ciphersum -= delta
            ciphersum &= 0xffffffff

        return v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')


class TencentTEAWithModeCBC(BaseCipher):
    _blocksize = 8

    @property
    def offset_related(self) -> bool:
        return False

    @property
    def keysize(self) -> int:
        return 16

    @property
    def salt_len(self) -> int:
        return 2

    @property
    def zero_len(self) -> int:
        return 7

    def __init__(self,
                 key: bytes,
                 /,
                 rounds: int = 64,
                 magic_number: int = 0x9e3779b9,
                 ) -> None:
        """
        Args:
            key: 密钥，长度必须等于 16
            rounds: 加/解密的轮转次数，必须为偶数
            magic_number: 加/解密使用的魔数
        """
        if len(key) != self.keysize:
            raise ValueError(f"invalid key length {len(key)} (should be {self.keysize})")
        if rounds % 2 != 0:
            raise ValueError(f"'rounds' must be an even integer, got {rounds}")

        super().__init__(key)
        self._cipher_per_block = TEAWithModeECB(key, rounds, magic_number)

    def encrypt(self, plaindata: bytes, /, *args) -> bytes:
        # 根据 plaindata 长度计算 pad_len，最小长度必须为 8 的整数倍
        pad_salt_body_zero_len = (len(plaindata) + self.salt_len + self.zero_len + 1)
        pad_len = pad_salt_body_zero_len % self.blocksize()
        if pad_len != 0:
            # 模 8 余 0 需补 0，余 1 补 7，余 2 补 6，...，余 7 补 1
            pad_len = self.blocksize() - pad_len

        src_buf = bytearray(self.blocksize())

        # 加密第一块数据（8 个字节）
        src_buf[0] = (rand() & 0xf8)  # 最低三位存 pad_len，清零
        src_buf[0] |= pad_len
        src_idx = 1  # src_idx 指向 src_buf 下一个位置

        # 填充
        while pad_len > 0:
            src_buf[src_idx] = rand()
            src_idx += 1
            pad_len -= 1

        # 到此处为止，src_idx 必须小于 8

        iv_plain = bytearray(self.blocksize())
        iv_crypt = iv_plain[:]  # 制造一个空初始向量

        # 获取加密结果预期长度，并据此创建一个空数组
        out_buf_len = self.get_encrypt_result_len(plaindata)
        out_buf = bytearray(out_buf_len)
        out_buf_pos = 0

        def crypt_block():  # CBC 加密操作流程
            nonlocal src_idx, out_buf_pos
            # 加密前异或前 8 个字节的密文（iv_crypt 指向的）
            src_buf[:] = bytestrxor(src_buf, iv_crypt)

            # 使用 TEA ECB 模式加密
            out_buf[out_buf_pos:out_buf_pos + self.blocksize()] = self._cipher_per_block.encrypt(src_buf)

            # 加密后异或前8个字节的密文（iv_crypt 指向的）
            out_buf[out_buf_pos:out_buf_pos + self.blocksize()] = bytestrxor(
                out_buf[out_buf_pos:out_buf_pos + self.blocksize()], iv_plain
            )

            # 保存当前的 iv_plain
            iv_plain[:] = src_buf[:]

            # 更新 iv_crypt
            iv_crypt[:] = out_buf[out_buf_pos:out_buf_pos + self.blocksize()]
            out_buf_pos += self.blocksize()

        # 填充2个字节的 Salt
        i = 1
        while i <= self.salt_len:
            if src_idx < self.blocksize():
                src_buf[src_idx] = rand()
                src_idx += 1
                i += 1
            if src_idx == self.blocksize():
                crypt_block()
                src_idx = 0

        # src_idx 指向 src_buf 下一个位置

        plaindata_pos = 0
        while plaindata_pos < len(plaindata):
            if src_idx < self.blocksize():
                src_buf[src_idx] = plaindata[plaindata_pos]
                src_idx += 1
                plaindata_pos += 1
            if src_idx == self.blocksize():
                crypt_block()
                src_idx = 0

        # src_idx 指向 src_buf 下一个位置

        i = 1
        while i <= self.zero_len:
            if src_idx < 8:
                src_buf[src_idx] = 0
                src_idx += 1
                i += 1
            if src_idx == 8:
                crypt_block()
                src_idx = 0

        return bytes(out_buf)

    def get_encrypt_result_len(self, plaindata: bytes) -> int:
        # 根据 plaindata 长度计算 pad_len ，最小长度必须为8的整数倍
        pad_salt_body_zero_len = (len(plaindata) + self.salt_len + self.zero_len + 1)
        pad_len = pad_salt_body_zero_len % self.blocksize()
        if pad_len != 0:
            # 模8余0需补0，余1补7，余2补6，...，余7补1
            pad_len = self.blocksize() - pad_len

        # 返回的是加密结果预期的长度
        return pad_salt_body_zero_len + pad_len

    def decrypt(self,
                cipherdata: bytes,
                /,
                *args,
                zero_check: bool = False
                ) -> bytes:
        if len(cipherdata) % self.blocksize() != 0:
            raise ValueError(f"encrypted key size ({len(cipherdata)}) "
                             f"is not a multiple of the block size ({self.blocksize()})"
                             )
        if len(cipherdata) < self.blocksize() * 2:
            raise ValueError(f"encrypted keydata length is too short "
                             f"(should be >= {self.blocksize() * 2}, got {len(cipherdata)})"
                             )

        dest_buf = bytearray(self._cipher_per_block.decrypt(cipherdata))
        pad_len = dest_buf[0] & 0x7
        out_buf_len = len(cipherdata) - pad_len - self.salt_len - self.zero_len - 1
        if pad_len + self.salt_len != 8:
            raise CipherDecryptError(f'invalid pad length {pad_len}')
        out_buf = bytearray(out_buf_len)

        iv_previous = bytearray(8)
        iv_current = bytearray(cipherdata[:8])

        cipherdata_pos = 8
        dest_idx = 1 + pad_len

        def crypt_block() -> None:
            nonlocal cipherdata_pos
            iv_previous[:] = iv_current[:]
            iv_current[:] = cipherdata[cipherdata_pos:cipherdata_pos + 8]
            dest_buf[:] = self._cipher_per_block.decrypt(
                bytestrxor(
                    dest_buf[:8], iv_current[:8]
                )
            )
            cipherdata_pos += 8

        i = 1
        while i <= self.salt_len:
            if dest_idx < 8:
                dest_idx += 1
                i += 1
            elif dest_idx == 8:
                crypt_block()
                dest_idx = 0

        out_buf_pos = 0
        while out_buf_pos < out_buf_len:
            if dest_idx < 8:
                out_buf[out_buf_pos] = dest_buf[dest_idx] ^ iv_previous[dest_idx]
                dest_idx += 1
                out_buf_pos += 1
            elif dest_idx == 8:
                crypt_block()
                dest_idx = 0

        if zero_check:
            for i in range(1, self.zero_len):
                if dest_idx < 8:
                    if dest_buf[dest_idx] ^ iv_previous[dest_idx] != 0:
                        raise CipherDecryptError('zero check failed')
                    dest_idx += 1
                elif dest_idx == 8:
                    crypt_block()
                    dest_idx = 0

        return bytes(out_buf)
