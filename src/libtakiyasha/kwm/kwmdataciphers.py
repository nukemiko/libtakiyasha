# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Generator, Literal

from ..miscutils import bytestrxor
from ..prototypes import KeyStreamBasedStreamCipherSkel
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import tobytes, toint

__all__ = ['Mask32', 'Mask32FromRecipe']


class Mask32(KeyStreamBasedStreamCipherSkel):
    def __init__(self, mask32: BytesLike, /) -> None:
        self._mask32 = tobytes(mask32)
        if len(self._mask32) != 32:
            raise ValueError(f"invalid mask length: should be 32, got {len(self._mask32)}")

    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'master':
            return self._mask32

    @classmethod
    def cls_keystream(cls, mask32: BytesLike, nbytes: IntegerLike, offset: IntegerLike, /) -> Generator[int, None, None]:
        offset = toint(offset)
        nbytes = toint(nbytes)
        if offset < 0:
            raise ValueError("third argument 'offset' must be a non-negative integer")
        if nbytes < 0:
            raise ValueError("second argument 'nbytes' must be a non-negative integer")
        maskblk_data: bytes = tobytes(mask32)
        maskblk_len = len(maskblk_data)
        if maskblk_len != 32:
            raise ValueError(f"invalid mask length: should be 32, not {maskblk_len}")

        target_in_maskblk_len = nbytes
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

    def keystream(self,
                  operation: Literal['encrypt', 'decrypt'],
                  nbytes: IntegerLike,
                  offset: IntegerLike, /
                  ) -> Generator[int, None, None]:
        yield from self.cls_keystream(self._mask32, nbytes, offset)


class Mask32FromRecipe(Mask32):
    def __init__(self, recipe: BytesLike, core_key: BytesLike, /) -> None:
        recipe = tobytes(recipe)
        core_key = tobytes(core_key)

        for varname, var, expectlen in ('core_key', core_key, 32), ('recipe', recipe, 8):
            if len(var) != expectlen:
                f"invalid length of argument '{varname}': should be {expectlen}, not {len(var)}"

        mask_recipe_unpacked = int.from_bytes(recipe, 'little')
        mask_stage1 = str(mask_recipe_unpacked).encode('ascii')
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
            mask_stage2 = b''.join(mask_stage2_composition)

        mask_final = bytestrxor(mask_stage2, core_key)

        self._source_recipe = recipe
        self._core_key = core_key

        super().__init__(mask_final)

    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'original':
            return self._source_recipe
        elif keyname == 'core':
            return self._core_key
        else:
            return super().getkey(keyname)
