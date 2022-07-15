from __future__ import annotations

from typing import Generator

from .legacyconstants import key256mapping_all
from ...common import Cipher
from ...utils import bytesxor

__all__ = ['Key256Mask128']


class Key256Mask128(Cipher):
    @staticmethod
    def cipher_name() -> str:
        return 'Dynamic Mapping (from Mask-128 or Mask-44)'

    def __init__(self, mask: bytes):
        if len(mask) == 44:
            # 从 44 位转换为 128 位
            key = self.mask44_to_mask128(mask)
        elif len(mask) == 128:
            key = mask[:]
        else:
            raise ValueError(f'invalid mask length (should be 44 or 128, got {len(mask)}')

        super().__init__(key)

    @staticmethod
    def mask44_to_mask128(mask44: bytes) -> bytes:
        if len(mask44) != 44:
            raise ValueError(f'invalid mask length (should be 44, got {len(mask44)})')

        mask128 = bytearray(128)
        idx44 = 0
        for it256 in key256mapping_all:
            if it256:
                for idx128 in it256:
                    mask128[idx128] = mask44[idx44]
                idx44 += 1

        return bytes(mask128)

    @classmethod
    def yield_mask(cls,
                   mask: bytes,
                   data_offset: int,
                   data_len: int
                   ) -> Generator[int, None, None]:
        index = data_offset - 1
        mask_idx = (data_offset % 128) - 1

        for _ in range(data_len):
            index += 1
            mask_idx += 1
            if index == 0x8000 or (index > 0x8000 and ((index + 1) % 0x8000 == 0)):
                index += 1
                mask_idx += 1
            if mask_idx >= 128:
                mask_idx -= 128

            yield mask[mask_idx]

    def gen_mask(self, data_offset: int, data_len: int) -> Generator[int, None, None]:
        yield from self.yield_mask(self._key, data_offset, data_len)

    def decrypt(self, cipherdata: bytes, start_offset: int = 0) -> bytes:
        keystream = bytes(self.gen_mask(start_offset, len(cipherdata)))
        return bytesxor(cipherdata, keystream)
