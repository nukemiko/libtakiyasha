# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import partial
from secrets import randbelow as srandbelow

try:
    import io
except ImportError:
    import _pyio as io
from typing import Generator

from pyaes import AESModeOfOperationECB
from pyaes.util import append_PKCS7_padding, strip_PKCS7_padding

from .common import StreamCipherSkel, CipherSkel
from .exceptions import CipherDecryptingError
from .typedefs import IntegerLike, BytesLike
from .miscutils import bytestrxor
from .typeutils import CachedClassInstanceProperty, tobytes, toint_nofloat

__all__ = [
    'StreamedAESWithModeECB',
    'TEAWithModeECB',
    'TarsCppTCTEAWithModeCBC',
    'ARC4'
]

rand = partial(srandbelow, 256)


class StreamedAESWithModeECB(CipherSkel):
    @CachedClassInstanceProperty
    def blocksize(self) -> int:
        return 16

    @property
    def master_key(self) -> bytes:
        return self._key

    def __init__(self, key: BytesLike, /) -> None:
        self._key = tobytes(key)
        self._base_aes_cipher = AESModeOfOperationECB(self._key)

    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        plaindata_padded = append_PKCS7_padding(tobytes(plaindata))
        iterable_by_blksize = iter(partial(io.BytesIO(plaindata_padded).read, self.blocksize), b'')
        return b''.join(self._base_aes_cipher.encrypt(blk) for blk in iterable_by_blksize)

    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        cipherdata = tobytes(cipherdata)
        iterable_by_blksize = iter(partial(io.BytesIO(cipherdata).read, self.blocksize), b'')
        plaindata_padded = b''.join(self._base_aes_cipher.decrypt(blk) for blk in iterable_by_blksize)
        return strip_PKCS7_padding(plaindata_padded)


class TEAWithModeECB(CipherSkel):
    @CachedClassInstanceProperty
    def blocksize(self) -> int:
        return 16

    @property
    def master_key(self) -> bytes:
        """主要的密钥。"""
        return self._key

    def __init__(self,
                 key: BytesLike,
                 /,
                 rounds: IntegerLike = 64,
                 magic_number: IntegerLike = 0x9e3779b9
                 ) -> None:
        self._key = tobytes(key)
        self._rounds = toint_nofloat(rounds)
        self._delta = toint_nofloat(magic_number)

        if len(self._key) != self.blocksize:
            raise ValueError(f"invalid key length: should be {self.blocksize}, not {len(self._key)}")
        if self._rounds % 2 != 0:
            raise ValueError(f'an even number of rounds is required (but got {self._rounds})')

    @classmethod
    def transvalues(cls, data: bytes, key: bytes) -> tuple[int, int, int, int, int, int]:
        v0 = int.from_bytes(data[:4], 'big')
        v1 = int.from_bytes(data[4:8], 'big')
        k0 = int.from_bytes(key[:4], 'big')
        k1 = int.from_bytes(key[4:8], 'big')
        k2 = int.from_bytes(key[8:12], 'big')
        k3 = int.from_bytes(key[12:], 'big')

        return v0, v1, k0, k1, k2, k3

    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        v0, v1, k0, k1, k2, k3 = self.transvalues(tobytes(plaindata), self.master_key)

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

    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        v0, v1, k0, k1, k2, k3 = self.transvalues(tobytes(cipherdata), self.master_key)

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


class TarsCppTCTEAWithModeCBC(CipherSkel):
    @CachedClassInstanceProperty
    def blocksize(self) -> int:
        return 8

    @CachedClassInstanceProperty
    def master_key_size(self) -> int:
        return 16

    @CachedClassInstanceProperty
    def salt_len(self) -> int:
        return 2

    @CachedClassInstanceProperty
    def zero_len(self) -> int:
        return 7

    @property
    def master_key(self) -> bytes:
        """主要的密钥。"""
        return self._lower_level_tea_cipher.master_key

    @property
    def lower_level_cipher(self) -> TEAWithModeECB:
        """使用的下层 Cipher。"""
        return self._lower_level_tea_cipher

    def __init__(self,
                 key: BytesLike,
                 /,
                 rounds: IntegerLike = 64,
                 magic_number: IntegerLike = 0x9e3779b9,
                 ) -> None:
        """TarsCpp 的 util/tc_tea 的完整实现。

        Args:
            key: 密钥，长度必须等于 16
            rounds: 加/解密的轮转次数，必须为偶数
            magic_number: 加/解密使用的魔数
        """
        key = tobytes(key)
        rounds = toint_nofloat(rounds)
        magic_number = toint_nofloat(magic_number)
        if len(key) != self.master_key_size:
            raise ValueError(f"invalid key length {len(key)}: "
                             f"should be {self.master_key_size}, not {len(key)}"
                             )
        if rounds % 2 != 0:
            raise ValueError(f"'rounds' must be an even integer, not {rounds}")

        self._lower_level_tea_cipher = TEAWithModeECB(key, rounds, magic_number)

    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        # 根据 plaindata 长度计算 pad_len，最小长度必须为 8 的整数倍
        plaindata = tobytes(plaindata)
        if len(plaindata) < self.blocksize:
            raise ValueError(
                f'invalid plaindata length: should be greater than '
                f'{self.blocksize}, not {len(plaindata)}'
            )
        if len(plaindata) % self.blocksize != 0:
            raise ValueError(
                f'invalid plaindata length ({len(plaindata)}): '
                f'not a integer multiple of {self.blocksize}'
            )

        pad_salt_body_zero_len = (len(plaindata) + self.salt_len + self.zero_len + 1)
        pad_len = pad_salt_body_zero_len % self.blocksize
        if pad_len != 0:
            # 模 8 余 0 需补 0，余 1 补 7，余 2 补 6，...，余 7 补 1
            pad_len = self.blocksize - pad_len

        src_buf = bytearray(self.blocksize)

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

        iv_plain = bytearray(self.blocksize)
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
            out_buf[out_buf_pos:out_buf_pos + self.blocksize] = self._lower_level_tea_cipher.encrypt(src_buf)

            # 加密后异或前8个字节的密文（iv_crypt 指向的）
            out_buf[out_buf_pos:out_buf_pos + self.blocksize] = bytestrxor(
                out_buf[out_buf_pos:out_buf_pos + self.blocksize], iv_plain
            )

            # 保存当前的 iv_plain
            iv_plain[:] = src_buf[:]

            # 更新 iv_crypt
            iv_crypt[:] = out_buf[out_buf_pos:out_buf_pos + self.blocksize]
            out_buf_pos += self.blocksize

        # 填充2个字节的 Salt
        i = 1
        while i <= self.salt_len:
            if src_idx < self.blocksize:
                src_buf[src_idx] = rand()
                src_idx += 1
                i += 1
            if src_idx == self.blocksize:
                crypt_block()
                src_idx = 0

        # src_idx 指向 src_buf 下一个位置

        plaindata_pos = 0
        while plaindata_pos < len(plaindata):
            if src_idx < self.blocksize:
                src_buf[src_idx] = plaindata[plaindata_pos]
                src_idx += 1
                plaindata_pos += 1
            if src_idx == self.blocksize:
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
        pad_len = pad_salt_body_zero_len % self.blocksize
        if pad_len != 0:
            # 模8余0需补0，余1补7，余2补6，...，余7补1
            pad_len = self.blocksize - pad_len

        # 返回的是加密结果预期的长度
        return pad_salt_body_zero_len + pad_len

    def decrypt(self,
                cipherdata: BytesLike, /,
                zero_check: bool = False
                ) -> bytes:
        cipherdata = tobytes(cipherdata)

        if len(cipherdata) < self.blocksize * 2:
            raise ValueError(
                f'invalid cipherdata length: should be greater than '
                f'{self.blocksize * 2}, not {len(cipherdata)}'
            )
        if len(cipherdata) % self.blocksize != 0:
            raise ValueError(
                f'invalid cipherdata length ({len(cipherdata)}): '
                f'not a integer multiple of {self.blocksize}'
            )

        dest_buf = bytearray(self._lower_level_tea_cipher.decrypt(cipherdata[:8]))
        pad_len = dest_buf[0] & 0x7
        out_buf_len = len(cipherdata) - pad_len - self.salt_len - self.zero_len - 1
        if out_buf_len < 0:
            raise CipherDecryptingError(
                'estimated plaindata length is less than 0'
            )
        out_buf = bytearray(out_buf_len)

        iv_previous = bytearray(8)
        iv_current = bytearray(cipherdata[:8])

        cipherdata_pos = 8
        dest_idx = 1 + pad_len

        def crypt_block() -> None:
            nonlocal cipherdata_pos
            iv_previous[:] = iv_current[:]
            iv_current[:] = cipherdata[cipherdata_pos:cipherdata_pos + 8]
            dest_buf[:] = self._lower_level_tea_cipher.decrypt(
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
                        raise CipherDecryptingError('zero check failed')
                    dest_idx += 1
                elif dest_idx == 8:
                    crypt_block()
                    dest_idx = 0

        return bytes(out_buf)


class ARC4(StreamCipherSkel):
    @property
    def master_key(self) -> bytes:
        return self._key

    def __init__(self, key: BytesLike, /) -> None:
        """标准的 RC4 加密算法实现。

        Args:
            key: 密钥，长度不可大于 256
        """
        key = tobytes(key)
        self._key = key
        key_len = len(key)
        if key_len > 256:
            raise ValueError(f'key length should be less than 256, got {key_len}')

        # 使用 RC4-KSA 生成 S-box
        S = bytearray(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % key_len]) % 256
            S[i], S[j] = S[j], S[i]

        # 使用 PRGA 生成密钥流
        meta_keystream = bytearray(256)
        for i, idx in enumerate(range(256), start=1):
            i %= 256
            si = S[i] % 256
            sj = S[(i + si) % 256] % 256
            K = S[(si + sj) % 256]
            meta_keystream[idx] = K

        self._meta_keystream = bytes(meta_keystream)

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        offset = toint_nofloat(offset)
        length = toint_nofloat(length)
        if offset < 0:
            raise ValueError("first argument 'offset' must be a non-negative integer")
        if length < 0:
            raise ValueError("second argument 'length' must be a non-negative integer")

        for i in range(offset, offset + length):
            yield self._meta_keystream[i % 256]
