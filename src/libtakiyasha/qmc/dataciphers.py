# -*- coding: utf-8 -*-
from __future__ import annotations

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
