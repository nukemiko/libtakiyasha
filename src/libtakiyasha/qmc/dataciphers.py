# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import cached_property, lru_cache
from typing import Generator, Iterable, SupportsBytes

from .consts import KEY256_MAPPING
from ..common import BaseCipher
from ..utils import bytestrxor


class Mask128(BaseCipher):
    def __init__(self, mask128: SupportsBytes | Iterable[int], /):
        super().__init__(mask128)

        if len(self.key['main']) != 128:
            raise ValueError(f"invalid mask length (should be 128, got {len(self.key['main'])})")

    @classmethod
    def from_qmcv1_mask44(cls, mask44: SupportsBytes | Iterable[int]) -> Mask128:
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

        return cls(mask128)

    @classmethod
    def from_qmcv1_mask256(cls, mask256: SupportsBytes | Iterable[int]) -> Mask128:
        mask256: bytes = bytes(mask256)
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
    def from_qmcv2_key256(cls, key256: SupportsBytes | Iterable[int]) -> Mask128:
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

        return cls(mask128)

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


class HardenedRC4(BaseCipher):
    @property
    def offset_related(self) -> bool:
        return True

    @cached_property
    def hash_base(self) -> int:
        base = 1
        key = self.key['main']

        for i in range(len(key)):
            v: int = key[i]
            if v == 0:
                continue
            next_hash: int = (base * v) & 0xffffffff
            if next_hash == 0 or next_hash <= base:
                break
            base = next_hash
        return base

    @cached_property
    def first_segment_size(self) -> int:
        return 128

    @cached_property
    def common_segment_size(self) -> int:
        return 5120

    def __init__(self, key: SupportsBytes | Iterable[int], /):
        super().__init__(key)
        key_len = len(self.key['main'])

        self._box = bytearray(i % 256 for i in range(key_len))
        j = 0
        for i in range(key_len):
            j = (j + self._box[i] + self.key['main'][i % key_len]) % key_len
            self._box[i], self._box[j] = self._box[j], self._box[i]

    @lru_cache(maxsize=65536)
    def _get_segment_skip(self, value: int) -> int:
        key = self.key['main']
        key_len = len(self.key['main'])

        seed = key[value % key_len]
        idx = int(self.hash_base / ((value + 1) * seed) * 100)

        return idx % key_len

    def _yield_first_segment_keystream(self,
                                       blksize: int,
                                       offset: int
                                       ) -> Generator[int, None, None]:
        key = self.key['main']
        for i in range(offset, offset + blksize):
            yield key[self._get_segment_skip(i)]

    def _yield_common_segment_keystream(self,
                                        blksize: int,
                                        offset: int
                                        ) -> Generator[int, None, None]:
        key_len = len(self.key['main'])
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

    def encrypt(self, plaindata: bytes, offset: int, /) -> bytes:
        return self.decrypt(plaindata, offset)

    def decrypt(self, cipherdata: bytes, offset: int, /) -> bytes:
        pending = len(cipherdata)
        done = 0
        offset = int(offset)
        target_buffer = bytearray(cipherdata)

        def mark(p: int) -> None:
            nonlocal pending, done, offset

            pending -= p
            done += p
            offset += p

        if 0 <= offset < self.first_segment_size:
            if pending > self.first_segment_size - offset:
                blksize = self.first_segment_size - offset
            else:
                blksize = pending
            target_buffer[:blksize] = bytestrxor(
                target_buffer[:blksize],
                self._yield_first_segment_keystream(blksize, offset)
            )
            mark(blksize)
            if pending <= 0:
                return bytes(target_buffer)

        if offset % self.common_segment_size != 0:
            if pending > self.common_segment_size - (offset % self.common_segment_size):
                blksize = self.common_segment_size - (offset % self.common_segment_size)
            else:
                blksize = pending
            target_buffer[done:done + blksize] = bytestrxor(
                target_buffer[done:done + blksize],
                self._yield_common_segment_keystream(blksize, offset)
            )
            mark(blksize)
            if pending <= 0:
                return bytes(target_buffer)

        while pending > self.common_segment_size:
            target_buffer[done:done + self.common_segment_size] = bytestrxor(
                target_buffer[done:done + self.common_segment_size],
                self._yield_common_segment_keystream(self.common_segment_size, offset)
            )
            mark(self.common_segment_size)

        if pending > 0:
            target_buffer[done:] = bytestrxor(
                target_buffer[done:],
                self._yield_common_segment_keystream(len(target_buffer[done:]), offset)
            )

        return bytes(target_buffer)
