# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import lru_cache
from typing import Generator, Literal

from .qmcconsts import KEY256_MAPPING
from ..prototypes import KeyStreamBasedStreamCipherSkel
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import CachedClassInstanceProperty, tobytes, toint


class Mask128(KeyStreamBasedStreamCipherSkel):
    def __init__(self, mask128: BytesLike, /):
        self._mask128 = tobytes(mask128)
        if len(self._mask128) != 128:
            raise ValueError(f"invalid mask length: should be 128, got {len(self._mask128)}")

    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'master':
            return self._mask128
        elif keyname == 'original':
            return getattr(self, '_original_qmcv2_key256', None)

    @classmethod
    def cls_keystream(cls,
                      mask128: BytesLike,
                      nbytes: IntegerLike,
                      offset: IntegerLike, /
                      ) -> Generator[int, None, None]:
        mask = tobytes(mask128)
        if len(mask) != 128:
            raise ValueError(f"invalid mask length: should be 128, got {len(mask)}")
        nbytes = toint(nbytes)
        offset = toint(offset)
        if offset < 0:
            raise ValueError("third argument 'offset' must be a non-negative integer")
        if nbytes < 0:
            raise ValueError("second argument 'nbytes' must be a non-negative integer")

        firstblk_data = mask * 256  # 前 32768 字节
        secondblk_data = firstblk_data[1:-1]  # 第 32769 至 65535 字节
        startblk_data = firstblk_data + secondblk_data  # 初始块：前 65535 字节
        startblk_len = len(startblk_data)
        commonblk_data = firstblk_data[:-1]  # 普通块：第 65536 字节往后每一个 32767 大小的块
        commonblk_len = len(commonblk_data)

        if 0 <= offset < startblk_len:
            max_target_in_startblk_len = startblk_len - offset
            target_in_commonblk_len = nbytes - max_target_in_startblk_len
            target_in_startblk_len = min(nbytes, max_target_in_startblk_len)
            yield from startblk_data[offset:offset + target_in_startblk_len]
            if target_in_commonblk_len <= 0:
                return
            else:
                offset = 0
        else:
            offset -= startblk_len
            target_in_commonblk_len = nbytes

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

    def keystream(self,
                  operation: Literal['encrypt', 'decrypt'],
                  nbytes: IntegerLike,
                  offset: IntegerLike, /
                  ) -> Generator[int, None, None]:
        yield from self.cls_keystream(self._mask128, nbytes, offset)

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
        instance._original_qmcv2_key256 = key256

        return instance


class HardenedRC4(KeyStreamBasedStreamCipherSkel):
    def __init__(self, key: BytesLike, /):
        self._key = tobytes(key)

        key_len = len(self._key)
        if key_len == 0:
            raise ValueError("first argument 'key' cannot be an empty bytestring")
        if b'\x00' in self._key:
            raise ValueError("first argument 'key' cannot contain null bytes")

        self._box = bytearray(i % 256 for i in range(key_len))
        j = 0
        for i in range(key_len):
            j = (j + self._box[i] + self._key[i]) % key_len
            self._box[i], self._box[j] = self._box[j], self._box[i]

    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'master':
            return self._key

    @property
    @lru_cache
    def hash_base(self) -> int:
        base = 1
        key = self._key

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

    @lru_cache(maxsize=65536)
    def _get_segment_skip(self, value: int) -> int:
        key = self._key
        key_len = len(self._key)

        seed = key[value % key_len]
        idx = int(self.hash_base / ((value + 1) * seed) * 100)

        return idx % key_len

    def _yield_first_segment_keystream(self,
                                       blksize: int,
                                       offset: int
                                       ) -> Generator[int, None, None]:
        key = self._key
        for i in range(offset, offset + blksize):
            yield key[self._get_segment_skip(i)]

    def _yield_common_segment_keystream(self,
                                        blksize: int,
                                        offset: int
                                        ) -> Generator[int, None, None]:
        key_len = len(self._key)
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

    def keystream(self,
                  operation: Literal['encrypt', 'decrypt'],
                  nbytes: IntegerLike,
                  offset: IntegerLike, /
                  ) -> Generator[int, None, None]:
        common_segment_size: int = self.common_segment_size

        pending = toint(nbytes)
        done = 0
        offset = toint(offset)
        if offset < 0:
            raise ValueError("third argument 'offset' must be a non-negative integer")
        if pending < 0:
            raise ValueError("second argument 'nbytes' must be a non-negative integer")

        if 0 <= offset < self.first_segment_size:
            blksize = min(pending, self.first_segment_size - offset)
            yield from self._yield_first_segment_keystream(blksize, offset)
            pending -= blksize
            done += blksize
            offset += blksize
            if pending <= 0:
                return

        if offset % common_segment_size != 0:
            blksize = min(pending, common_segment_size - (offset % common_segment_size))
            yield from self._yield_common_segment_keystream(blksize, offset)
            pending -= blksize
            done += blksize
            offset += blksize
            if pending <= 0:
                return

        while pending > common_segment_size:
            yield from self._yield_common_segment_keystream(common_segment_size, offset)
            pending -= common_segment_size
            done += common_segment_size
            offset += common_segment_size

        if pending > 0:
            yield from self._yield_common_segment_keystream(nbytes - done, offset)
