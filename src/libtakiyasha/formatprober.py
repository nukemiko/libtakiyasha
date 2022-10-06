# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from enum import Enum
from typing import IO

from .utils import verify_fileobj


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
    def probe(cls, fileobj: IO[bytes]) -> CommonAudioHeadersInRegexPattern | None:
        fileobj = verify_fileobj(fileobj, verify_binary_mode=True, verify_read=True, verify_seek=True)

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
