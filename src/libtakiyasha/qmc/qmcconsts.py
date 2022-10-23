# -*- coding: utf-8 -*-
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Final

__all__ = ['KEY256_MAPPING']

# KEY256_MAPPING = [[]] * 256
#
# for i in range(128):
#     real_idx = (i * i + 27) % 256
#     if not KEY256_MAPPING[real_idx]:
#         KEY256_MAPPING[real_idx] = [i]
#     else:
#         KEY256_MAPPING[real_idx].append(i)
#
# KEY256_MAPPING 可使用以上代码生成
with open(Path(__file__).parent / 'binaries/Key256MappingData', 'rb') as f:
    KEY256_MAPPING: Final[list[list[int]]] = pickle.load(f)
