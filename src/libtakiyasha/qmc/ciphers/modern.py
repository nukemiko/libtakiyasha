from __future__ import annotations

import os
from typing import Generator

from ...common import Cipher, KeylessCipher
from ...utils import bytesxor

QMCv1_KEYSTREAM_1ST_SEGMENT = b''
QMCv1_KEYSTREAM_REMAINING_SEGMENT = b''

__all__ = ['DynamicMap', 'ModifiedRC4', 'StaticMap']


def load_segment_file() -> tuple[bytes, bytes]:
    global QMCv1_KEYSTREAM_1ST_SEGMENT, QMCv1_KEYSTREAM_REMAINING_SEGMENT
    if not (QMCv1_KEYSTREAM_1ST_SEGMENT and QMCv1_KEYSTREAM_REMAINING_SEGMENT):
        with open(os.path.join(os.path.dirname(__file__), 'binaries/QMCv1-keystream-segment'), 'rb') as seg_file:
            QMCv1_KEYSTREAM_1ST_SEGMENT = seg_file.read(32768)
            QMCv1_KEYSTREAM_REMAINING_SEGMENT = seg_file.read(32767)

    return QMCv1_KEYSTREAM_1ST_SEGMENT, QMCv1_KEYSTREAM_REMAINING_SEGMENT

class StaticMap(KeylessCipher):
    @staticmethod
    def cipher_name() -> str:
        return 'Static Mapping'

    def __init__(self):
        self._start_seg, self._remain_seg = load_segment_file()

    def decrypt(self, cipherdata: bytes, start_offset: int = 0) -> bytes:
        data_len = len(cipherdata)
        start_offset = self._check_params(start_offset)

        if 0 <= start_offset <= 32768:
            if start_offset + data_len <= 32768:
                target_stream = self._start_seg[start_offset:start_offset + data_len]
            else:  # start_offset + data_len > 32768
                data_in_remain_segs = data_len - (32768 - start_offset)
                target_stream = self._start_seg[start_offset:] + self._remain_seg * (data_in_remain_segs // 32767) + self._remain_seg[:data_in_remain_segs % 32767]
        else:
            start_offset = (start_offset - 32768) % 32767
            if start_offset + data_len <= 32767:
                target_stream = self._remain_seg[start_offset:start_offset + data_len]
            else:  # start_offset + data_len > 32767
                remaining_data_len = data_len - (32767 - start_offset)
                target_stream = self._remain_seg[start_offset:] + self._remain_seg * (remaining_data_len // 32767) + self._remain_seg[:remaining_data_len % 32767]

        return bytesxor(cipherdata, target_stream)

class DynamicMap(Cipher):
    @staticmethod
    def cipher_name() -> str:
        return 'Dynamic Mapping'

    def yield_mask(self, data_offset: int, data_len: int):
        key: bytes = self._key
        key_len = len(key)

        for i in range(data_offset, data_offset + data_len):
            if i > 0x7fff:
                i %= 0x7fff
            idx = (i ** 2 + 71214) % key_len

            value = key[idx]
            rotate = ((idx & 7) + 4) % 8

            yield ((value << rotate) % 256) | ((value >> rotate) % 256)

    def decrypt(self, cipherdata: bytes, start_offset: int = 0) -> bytes:
        keystream = bytes(self.yield_mask(start_offset, len(cipherdata)))
        return bytesxor(cipherdata, keystream)


class ModifiedRC4(Cipher):
    @staticmethod
    def cipher_name() -> str:
        return 'Modified RC4'

    @staticmethod
    def first_segsize() -> int:
        return 128

    @staticmethod
    def remain_segsize() -> int:
        return 5120

    @staticmethod
    def get_hash_base(key: bytes) -> int:
        hash_base = 1
        key_len = len(key)

        for i in range(key_len):
            v: int = key[i]
            if v == 0:
                continue
            next_hash: int = (hash_base * v) & 0xffffffff
            if next_hash == 0 or next_hash <= hash_base:
                break
            hash_base = next_hash
        return hash_base

    def __init__(self, key: bytes):
        super().__init__(key)
        key_len = len(key)
        self._key_len = key_len

        box: bytearray = bytearray(i % 256 for i in range(key_len))

        j: int = 0
        for i in range(key_len):
            j = (j + box[i] + key[i % key_len]) % key_len
            box[i], box[j] = box[j], box[i]
        self._box: bytearray = box

        self._hash_base = self.get_hash_base(key)

    def get_seg_skip(self, v: int) -> int:
        key: bytes = self._key
        key_len: int = self._key_len
        hash_: int = self._hash_base

        seed: int = key[v % key_len]
        idx: int = int(hash_ / ((v + 1) * seed) * 100)

        return idx % key_len

    def gen_first_seg(self,
                      data_offset: int,
                      data_len: int
                      ) -> Generator[int, None, None]:
        key = self._key

        for i in range(data_offset, data_offset + data_len):
            yield key[self.get_seg_skip(i)]

    def gen_remain_seg(self,
                       data_offset: int,
                       data_len: int
                       ) -> Generator[int, None, None]:
        key_len = self._key_len
        box = self._box.copy()
        j, k = 0, 0

        skip_len = (data_offset % self.remain_segsize()) + self.get_seg_skip(data_offset // self.remain_segsize())
        for i in range(-skip_len, data_len):
            j = (j + 1) % key_len
            k = (box[j] + k) % key_len
            box[j], box[k] = box[k], box[j]
            if i >= 0:
                yield box[(box[j] + box[k]) % key_len]

    def decrypt(self, cipherdata: bytes, start_offset: int = 0) -> bytes:
        first_segsize = self.first_segsize()
        remain_segsize = self.remain_segsize()
        gen_remain_seg = self.gen_remain_seg

        pending = len(cipherdata)
        done = 0
        offset = int(start_offset)
        keystream_buffer = bytearray(pending)

        def mark(p: int) -> None:
            nonlocal pending, done, offset

            pending -= p
            done += p
            offset += p

        if 0 <= offset < first_segsize:
            blksize = pending
            if blksize > first_segsize - offset:
                blksize = first_segsize - offset
            keystream_buffer[:blksize] = self.gen_first_seg(offset, blksize)
            mark(blksize)
            if pending <= 0:
                return bytesxor(cipherdata, keystream_buffer)

        if offset % remain_segsize != 0:
            blksize = pending
            if blksize > remain_segsize - (offset % remain_segsize):
                blksize = remain_segsize - (offset % remain_segsize)
            keystream_buffer[done:done + blksize] = gen_remain_seg(offset, blksize)
            mark(blksize)
            if pending <= 0:
                return bytesxor(cipherdata, keystream_buffer)

        while pending > remain_segsize:
            keystream_buffer[done:done + remain_segsize] = gen_remain_seg(offset, remain_segsize)
            mark(remain_segsize)

        if pending > 0:
            keystream_buffer[done:] = gen_remain_seg(offset, len(keystream_buffer[done:]))

        return bytesxor(cipherdata, keystream_buffer)
