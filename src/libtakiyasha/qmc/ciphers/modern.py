from __future__ import annotations

import os
import warnings
from typing import Generator

from ...common import Cipher, KeylessCipher
from ...utils import bytesxor

QMCv1_KEYSTREAM_1ST_SEGMENT = b''
QMCv1_KEYSTREAM_REMAINING_SEGMENT = b''

__all__ = ['DynamicMask', 'HardenedRC4', 'StaticMask']


def load_segment_file() -> tuple[bytes, bytes]:
    global QMCv1_KEYSTREAM_1ST_SEGMENT, QMCv1_KEYSTREAM_REMAINING_SEGMENT
    if not (QMCv1_KEYSTREAM_1ST_SEGMENT and QMCv1_KEYSTREAM_REMAINING_SEGMENT):
        with open(os.path.join(os.path.dirname(__file__), 'binaries/QMCv1-keystream-segment'), 'rb') as seg_file:
            QMCv1_KEYSTREAM_1ST_SEGMENT = seg_file.read(32768)
            QMCv1_KEYSTREAM_REMAINING_SEGMENT = seg_file.read(32767)

    return QMCv1_KEYSTREAM_1ST_SEGMENT, QMCv1_KEYSTREAM_REMAINING_SEGMENT


class StaticMask(KeylessCipher):
    @staticmethod
    def cipher_name() -> str:
        return 'QMCv1 Static Mask'

    @staticmethod
    def masks() -> bytes:
        return bytes(
            [
                0x77, 0x48, 0x32, 0x73, 0xde, 0xf2, 0xc0, 0xc8,
                0x95, 0xec, 0x30, 0xb2, 0x51, 0xc3, 0xe1, 0xa0,
                0x9e, 0xe6, 0x9d, 0xcf, 0xfa, 0x7f, 0x14, 0xd1,
                0xce, 0xb8, 0xdc, 0xc3, 0x4a, 0x67, 0x93, 0xd6,
                0x28, 0xc2, 0x91, 0x70, 0xca, 0x8d, 0xa2, 0xa4,
                0xf0, 0x08, 0x61, 0x90, 0x7e, 0x6f, 0xa2, 0xe0,
                0xeb, 0xae, 0x3e, 0xb6, 0x67, 0xc7, 0x92, 0xf4,
                0x91, 0xb5, 0xf6, 0x6c, 0x5e, 0x84, 0x40, 0xf7,
                0xf3, 0x1b, 0x02, 0x7f, 0xd5, 0xab, 0x41, 0x89,
                0x28, 0xf4, 0x25, 0xcc, 0x52, 0x11, 0xad, 0x43,
                0x68, 0xa6, 0x41, 0x8b, 0x84, 0xb5, 0xff, 0x2c,
                0x92, 0x4a, 0x26, 0xd8, 0x47, 0x6a, 0x7c, 0x95,
                0x61, 0xcc, 0xe6, 0xcb, 0xbb, 0x3f, 0x47, 0x58,
                0x89, 0x75, 0xc3, 0x75, 0xa1, 0xd9, 0xaf, 0xcc,
                0x08, 0x73, 0x17, 0xdc, 0xaa, 0x9a, 0xa2, 0x16,
                0x41, 0xd8, 0xa2, 0x06, 0xc6, 0x8b, 0xfc, 0x66,
                0x34, 0x9f, 0xcf, 0x18, 0x23, 0xa0, 0x0a, 0x74,
                0xe7, 0x2b, 0x27, 0x70, 0x92, 0xe9, 0xaf, 0x37,
                0xe6, 0x8c, 0xa7, 0xbc, 0x62, 0x65, 0x9c, 0xc2,
                0x08, 0xc9, 0x88, 0xb3, 0xf3, 0x43, 0xac, 0x74,
                0x2c, 0x0f, 0xd4, 0xaf, 0xa1, 0xc3, 0x01, 0x64,
                0x95, 0x4e, 0x48, 0x9f, 0xf4, 0x35, 0x78, 0x95,
                0x7a, 0x39, 0xd6, 0x6a, 0xa0, 0x6d, 0x40, 0xe8,
                0x4f, 0xa8, 0xef, 0x11, 0x1d, 0xf3, 0x1b, 0x3f,
                0x3f, 0x07, 0xdd, 0x6f, 0x5b, 0x19, 0x30, 0x19,
                0xfb, 0xef, 0x0e, 0x37, 0xf0, 0x0e, 0xcd, 0x16,
                0x49, 0xfe, 0x53, 0x47, 0x13, 0x1a, 0xbd, 0xa4,
                0xf1, 0x40, 0x19, 0x60, 0x0e, 0xed, 0x68, 0x09,
                0x06, 0x5f, 0x4d, 0xcf, 0x3d, 0x1a, 0xfe, 0x20,
                0x77, 0xe4, 0xd9, 0xda, 0xf9, 0xa4, 0x2b, 0x76,
                0x1c, 0x71, 0xdb, 0x00, 0xbc, 0xfd, 0x0c, 0x6c,
                0xa5, 0x47, 0xf7, 0xf6, 0x00, 0x79, 0x4a, 0x11,
            ]
        )

    def gen_keystream(self, data_len: int, start_offset: int) -> Generator[int, None, None]:
        masks = self.masks()

        for i in range(start_offset, start_offset + data_len):
            if i > 0x7fff:
                i %= 0x7fff
            idx = (i ** 2 + 27) & 0xff
            yield masks[idx]

    def __init__(self, older_solution=False):
        self._use_older_solution = False

        if older_solution:  # 如果用户要求使用旧有解密方案
            self._start_seg, self._remain_seg = b'', b''
            self._use_older_solution = True
        else:
            try:
                self._start_seg, self._remain_seg = load_segment_file()
            except OSError:  # 如果密钥流文件 libtakiyasha/qmc/ciphers/binaries/QMCv1-keystream-segment 不存在
                warnings.warn(
                    RuntimeWarning('Cannot load QMCv1 keystream segment from data file. '
                                   'Use algorithm (more slower) to instead.'
                                   )
                )
                self._start_seg, self._remain_seg = b'', b''
                self._use_older_solution = True

    def decrypt(self, cipherdata: bytes, start_offset: int = 0) -> bytes:
        data_len = len(cipherdata)
        start_offset = self._check_params(start_offset)

        if self._use_older_solution:
            target_stream = bytes(self.gen_keystream(data_len, start_offset))
        else:
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


class DynamicMask(Cipher):
    @staticmethod
    def cipher_name() -> str:
        return 'QMCv2 Dynamic Mask'

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


class HardenedRC4(Cipher):
    @staticmethod
    def cipher_name() -> str:
        return 'QMCv2 Hardened RC4'

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
