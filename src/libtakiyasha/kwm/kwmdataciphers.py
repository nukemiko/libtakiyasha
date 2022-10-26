# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Generator

from ..common import StreamCipherSkel
from ..miscutils import bytestrxor
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import tobytes, toint_nofloat

__all__ = ['Mask32']


class Mask32(StreamCipherSkel):
    @property
    def core_key(self) -> bytes:
        return self._core_key

    @property
    def master_key(self) -> bytes:
        return self._master_key

    @property
    def mask32(self) -> bytes:
        return self._mask32

    def __init__(self, core_key: BytesLike, master_key=BytesLike, /) -> None:
        core_key = tobytes(core_key)
        master_key = tobytes(master_key)

        for varname, var, expectlen in ('core_key', core_key, 32), ('master_key', master_key, 8):
            if len(var) != expectlen:
                f"invalid length of argument '{varname}': should be {expectlen}, not {len(var)}"

        self._core_key = core_key
        self._master_key = master_key

        mask_stage1 = str(int.from_bytes(master_key, 'little'))
        if len(mask_stage1) >= 32:
            mask_stage2 = mask_stage1[:32]
        else:
            mask_stage2_pad_len = 32 - len(mask_stage1)
            mask_stage2_stage1_fullpad_count = (mask_stage2_pad_len // len(mask_stage1))
            mask_stage2_stage1_fullpad_len = len(mask_stage1) * mask_stage2_stage1_fullpad_count
            mask_stage2_remain_len = mask_stage2_pad_len - mask_stage2_stage1_fullpad_len

            mask_stage2_composition = [mask_stage1]
            for _ in range(mask_stage2_stage1_fullpad_count):
                mask_stage2_composition.append(mask_stage1)
            mask_stage2_composition.append(mask_stage1[:mask_stage2_remain_len])
            mask_stage2 = ''.join(mask_stage2_composition).encode('utf-8')

        mask_final = bytestrxor(mask_stage2, core_key)
        self._mask32 = mask_final

    @classmethod
    def cls_keystream(cls,
                      offset: IntegerLike,
                      length: IntegerLike, /,
                      mask32: BytesLike
                      ) -> Generator[int, None, None]:
        offset = toint_nofloat(offset)
        length = toint_nofloat(length)
        if offset < 0:
            raise ValueError("first argument 'offset' must be a non-negative integer")
        if length < 0:
            raise ValueError("second argument 'length' must be a non-negative integer")
        maskblk_data: bytes = tobytes(mask32)
        maskblk_len = len(maskblk_data)
        if maskblk_len != 32:
            raise ValueError(f"invalid mask length: should be 32, not {maskblk_len}")

        target_in_maskblk_len = length
        target_offset_in_maskblk = offset % maskblk_len
        if target_offset_in_maskblk == 0:
            target_before_maskblk_area_len = 0
        else:
            target_before_maskblk_area_len = maskblk_len - target_offset_in_maskblk
        yield from maskblk_data[target_offset_in_maskblk:target_offset_in_maskblk + target_before_maskblk_area_len]
        target_in_maskblk_len -= target_before_maskblk_area_len

        target_overrided_whole_maskblk_count = target_in_maskblk_len // maskblk_len
        target_after_maskblk_area_len = target_in_maskblk_len % maskblk_len

        for _ in range(target_overrided_whole_maskblk_count):
            yield from maskblk_data
        yield from maskblk_data[:target_after_maskblk_area_len]

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        yield from self.cls_keystream(offset, length, self._mask32)
