# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import lru_cache
from typing import Generator

from .consts import KEY256_MAPPING
from ..common import StreamCipherSkel
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import CachedClassInstanceProperty, tobytes, toint_nofloat

__all__ = [
    'HardenedRC4',
    'Mask128'
]


class Mask128(StreamCipherSkel):
    @property
    def original_master_key(self) -> bytes | None:
        if hasattr(self, '_original_master_key'):
            return self._original_master_key

    @property
    def mask128(self) -> bytes:
        return self._mask128

    @classmethod
    def from_qmcv1_mask44(cls, mask44: BytesLike) -> Mask128:
        mask44: bytes = tobytes(mask44)
        if len(mask44) != 44:
            raise ValueError(f'invalid mask length (should be 44, got {len(mask44)})')

        mask128 = bytearray(128)
        idx44 = 0
        for it256 in KEY256_MAPPING:
            if it256:
                for idx128 in it256:
                    mask128[idx128] = mask44[idx44]
                idx44 += 1

        return cls(mask128)

    @classmethod
    def from_qmcv1_mask256(cls, mask256: BytesLike) -> Mask128:
        mask256: bytes = tobytes(mask256)
        if len(mask256) != 256:
            raise ValueError(f'invalid mask length (should be 256, got {len(mask256)})')

        mask128 = bytearray(128)
        for idx128 in range(128):
            if idx128 > 0x7fff:
                idx128 %= 0x7fff
            idx = (idx128 ** 2 + 27) & 0xff
            mask128[idx128] = mask256[idx]

        return cls(mask128)

    @classmethod
    def from_qmcv2_key256(cls, key256: BytesLike) -> Mask128:
        key256: bytes = tobytes(key256)
        if len(key256) != 256:
            raise ValueError(f'invalid key length (should be 256, got {len(key256)})')

        mask128 = bytearray(128)
        for idx128 in range(128):
            if idx128 > 0x7fff:
                idx128 %= 0x7fff
            idx = (idx128 ** 2 + 71214) % 256

            value = key256[idx]
            rotate = ((idx & 7) + 4) % 8

            mask128[idx128] = ((value << rotate) % 256) | ((value >> rotate) % 256)

        instance = cls(mask128)
        instance._original_master_key = key256

        return instance

    def __init__(self, mask128: BytesLike, /):
        self._mask128 = tobytes(mask128)
        if len(self._mask128) != 128:
            raise ValueError(f"invalid mask length: should be 128, got {len(self._mask128)}")

    @classmethod
    def cls_keystream(cls,
                      offset: IntegerLike,
                      length: IntegerLike, /,
                      mask128: BytesLike
                      ) -> Generator[int, None, None]:
        mask128: bytes = tobytes(mask128)
        if len(mask128) != 128:
            raise ValueError(f"invalid mask length (should be 128, got {len(mask128)})")
        firstblk_data = mask128 * 256  # 前 32768 字节
        secondblk_data = firstblk_data[1:-1]  # 第 32769 至 65535 字节
        startblk_data = firstblk_data + secondblk_data  # 初始块：前 65535 字节
        startblk_len = len(startblk_data)
        commonblk_data = firstblk_data[:-1]  # 普通块：第 65536 字节往后每一个 32767 大小的块
        commonblk_len = len(commonblk_data)
        offset = toint_nofloat(offset)
        length = toint_nofloat(length)
        if offset < 0:
            raise ValueError("first argument 'offset' must be a non-negative integer")
        if length < 0:
            raise ValueError("second argument 'length' must be a non-negative integer")

        if 0 <= offset < startblk_len:
            max_target_in_startblk_len = startblk_len - offset
            target_in_commonblk_len = length - max_target_in_startblk_len
            target_in_startblk_len = min(length, max_target_in_startblk_len)
            yield from startblk_data[offset:offset + target_in_startblk_len]
            if target_in_commonblk_len <= 0:
                return
            else:
                offset = 0
        else:
            offset -= startblk_len
            target_in_commonblk_len = length

        target_offset_in_commonblk = offset % commonblk_len
        if target_offset_in_commonblk == 0:
            target_before_commonblk_area_len = 0
        else:
            target_before_commonblk_area_len = commonblk_len - target_offset_in_commonblk
        yield from commonblk_data[target_offset_in_commonblk:target_offset_in_commonblk + target_before_commonblk_area_len]
        target_in_commonblk_len -= target_before_commonblk_area_len

        target_overrided_whole_commonblk_count = target_in_commonblk_len // commonblk_len
        target_after_commonblk_area_len = target_in_commonblk_len % commonblk_len

        for _ in range(target_overrided_whole_commonblk_count):
            yield from commonblk_data
        yield from commonblk_data[:target_after_commonblk_area_len]

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        yield from self.cls_keystream(offset, length, mask128=self._mask128)


class HardenedRC4(StreamCipherSkel):
    @property
    def hash_base(self) -> int:
        base = 1
        key = self._key512

        for i in range(len(key)):
            v: int = key[i]
            if v == 0:
                continue
            next_hash: int = (base * v) & 0xffffffff
            if next_hash == 0 or next_hash <= base:
                break
            base = next_hash
        return base

    @CachedClassInstanceProperty
    def first_segment_size(self) -> int:
        return 128

    @CachedClassInstanceProperty
    def common_segment_size(self) -> int:
        return 5120

    @property
    def key512(self) -> bytes:
        return self._key512

    def __init__(self, key512: BytesLike, /):
        self._key512 = tobytes(key512)

        key_len = len(self._key512)

        self._box = bytearray(i % 256 for i in range(key_len))
        j = 0
        for i in range(key_len):
            j = (j + self._box[i] + self._key512[i % key_len]) % key_len
            self._box[i], self._box[j] = self._box[j], self._box[i]

    @lru_cache(maxsize=65536)
    def _get_segment_skip(self, value: int) -> int:
        key = self._key512
        key_len = len(self._key512)

        seed = key[value % key_len]
        idx = int(self.hash_base / ((value + 1) * seed) * 100)

        return idx % key_len

    def _yield_first_segment_keystream(self,
                                       blksize: int,
                                       offset: int
                                       ) -> Generator[int, None, None]:
        key = self._key512
        for i in range(offset, offset + blksize):
            yield key[self._get_segment_skip(i)]

    def _yield_common_segment_keystream(self,
                                        blksize: int,
                                        offset: int
                                        ) -> Generator[int, None, None]:
        key_len = len(self._key512)
        box = self._box.copy()
        j, k = 0, 0

        skip_len = offset % self.common_segment_size + self._get_segment_skip(
            offset // self.common_segment_size
        )
        for i in range(-skip_len, blksize):
            j = (j + 1) % key_len
            k = (box[j] + k) % key_len
            box[j], box[k] = box[k], box[j]
            if i >= 0:
                yield box[(box[j] + box[k]) % key_len]

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        pending = toint_nofloat(length)
        done = 0
        offset = toint_nofloat(offset)

        def mark(p: int) -> None:
            nonlocal pending, done, offset

            pending -= p
            done += p
            offset += p

        if 0 <= offset < self.first_segment_size:
            blksize = min(pending, self.first_segment_size - offset)
            yield from self._yield_first_segment_keystream(blksize, offset)
            mark(blksize)
            if pending <= 0:
                raise StopIteration

        if offset % self.common_segment_size != 0:
            blksize = min(pending, self.common_segment_size - (offset % self.common_segment_size))
            yield from self._yield_common_segment_keystream(blksize, offset)
            mark(blksize)
            if pending <= 0:
                raise StopIteration

        while pending > self.common_segment_size:
            yield from self._yield_common_segment_keystream(self.common_segment_size, offset)
            mark(self.common_segment_size)

        if pending > 0:
            yield from self._yield_common_segment_keystream(length - done, offset)
