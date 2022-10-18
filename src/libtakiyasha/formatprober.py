# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from enum import Enum

try:
    import io
except ImportError:
    import _pyio as io
from typing import IO

from .typedefs import *
from .typeutils import tobytes, verify_fileobj

__all__ = ['CommonAudioHeadersInRegexPattern']


class BitPaddedInt(int):
    def __new__(cls, value, bits: int = 7, bigendian: bool = True):
        mask = (1 << bits) - 1
        numeric_value = 0
        shift = 0

        if isinstance(value, int):
            if value < 0:
                raise ValueError
            while value:
                numeric_value += (value & mask) << shift
                value >>= 8
                shift += bits
        elif isinstance(value, bytes):
            if bigendian:
                value = reversed(value)
            for byte in bytearray(value):
                numeric_value += (byte & mask) << shift
                shift += bits
        else:
            raise TypeError

        self = int.__new__(BitPaddedInt, numeric_value)

        return self


class CommonAudioHeadersInRegexPattern(Enum):
    """常见音频格式的文件头，为经过 ``re.compile()``
    编译后的正则表达式对象，方便进行匹配。"""
    AAC: re.Pattern = re.compile(b'^\xff\xf1')
    AC3: re.Pattern = re.compile(b'\x0b\x77\xa1\x7a|\x0b\x77\x91\x64|\x0b\x77\x0b\xa0')
    APE: re.Pattern = re.compile(b'^MAC ')
    DFF: re.Pattern = re.compile(b'^FRM8')
    DTS: re.Pattern = re.compile(b'^\x7f\xfe\x80\x01')
    FLAC: re.Pattern = re.compile(b'^fLaC')
    M4A: re.Pattern = re.compile(b'^.{4}ftyp')
    MP3: re.Pattern = re.compile(b'^\xff[\xf2\xf3\xfb]')
    OGG: re.Pattern = re.compile(b'^OggS')
    TTA: re.Pattern = re.compile(b'^TTA[1-9]?')
    WAV: re.Pattern = re.compile(b'^RIFF')
    WMA: re.Pattern = re.compile(b'^0&\xb2u\x8ef\xcf\x11\xa6\xd9\x00\xaa\x00b\xcel')

    def __bytes__(self) -> bytes:
        return bytes(self.value.pattern)

    def __str__(self) -> str:
        return str(self.name)

    @classmethod
    def probe(cls,
              fileobj_or_data: IO[bytes] | BytesLike
              ) -> CommonAudioHeadersInRegexPattern | None:
        """通过匹配文件头部，探测文件对象或数据 fileobj 的格式。

        如果匹配到结果，返回匹配到的模式对应的枚举对象；否则返回 ``None``。
        """
        try:
            fileobj = io.BytesIO(tobytes(fileobj_or_data))
        except TypeError:
            fileobj = verify_fileobj(fileobj_or_data,
                                     'binary',
                                     verify_readable=True,
                                     verify_seekable=True,
                                     verify_writable=False
                                     )

        fileobj_oldpos = fileobj.seek(0, 1)

        # 排除文件开头的 ID3 标签区块
        fileobj.seek(0, 0)
        header = fileobj.read(16)
        if header.startswith(b'ID3'):
            size = int(10 + BitPaddedInt(header[6:10]))
            fileobj.seek(size, 0)
            header = fileobj.read(32)

        fileobj.seek(fileobj_oldpos, 0)

        for item in cls:
            pattern: re.Pattern = item.value  # type: ignore
            if pattern.search(header):
                return item
