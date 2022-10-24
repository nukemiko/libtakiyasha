# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Generator

from .. import StreamCipherSkel
from ..miscutils import bytestrxor
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import CachedClassInstanceProperty, tobytearray, tobytes, toint_nofloat

__all__ = [
    'KGMEncryptionAlgorithm',
    'KGMEncryptionAlgorithmWithCachedMask',
    'VPREnceyptionAlgorithm',
    'VPREncryptionAlgorithmWithCachedMask'
]


def xor_lower_helf_byte(b: int) -> int:
    return b ^ ((b & 0xf) << 4)


class KGMEncryptionAlgorithm(StreamCipherSkel):
    @CachedClassInstanceProperty
    def tablesize(self) -> int:
        return 16 * 17

    @property
    def table1(self) -> bytes:
        return self._table1

    @property
    def table2(self) -> bytes:
        return self._table2

    @property
    def tablev2(self) -> bytes:
        return self._tablev2

    @property
    def file_key(self):
        return self._file_key

    def __init__(self,
                 file_key: BytesLike,
                 table1: BytesLike,
                 table2: BytesLike,
                 tablev2: BytesLike, /
                 ) -> None:
        self._table1 = tobytes(table1)
        self._table2 = tobytes(table2)
        self._tablev2 = tobytes(tablev2)
        self._file_key = tobytes(file_key)

        if len(self._table1) != self.tablesize:
            raise ValueError(
                f"invalid length of 'table1': should be {self.tablesize}, not {len(self._table1)}"
            )
        if len(self._table2) != self.tablesize:
            raise ValueError(
                f"invalid length of 'table2': should be {self.tablesize}, not {len(self._table2)}"
            )
        if len(self._tablev2) != self.tablesize:
            raise ValueError(
                f"invalid length of 'tablev2': should be {self.tablesize}, not {len(self._tablev2)}"
            )

    @classmethod
    def generate_mask(cls,
                      offset: IntegerLike,
                      length: IntegerLike, /,
                      table1: BytesLike,
                      table2: BytesLike,
                      tablev2: BytesLike
                      ) -> Generator[int, None, None]:
        tablesize: int = cls.tablesize

        offset = toint_nofloat(offset)
        length = toint_nofloat(length)
        if offset < 0:
            raise ValueError("first argument 'offset' must be a non-negative integer")
        if length < 0:
            raise ValueError("second argument 'length' must be a non-negative integer")
        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)
        if len(table1) != tablesize:
            raise ValueError(
                f"invalid length of 'table1': should be {tablesize}, not {len(table1)}"
            )
        if len(table2) != tablesize:
            raise ValueError(
                f"invalid length of 'table2': should be {tablesize}, not {len(table2)}"
            )
        if len(tablev2) != tablesize:
            raise ValueError(
                f"invalid length of 'tablev2': should be {tablesize}, not {len(tablev2)}"
            )

        for idx in range(offset, offset + length):
            idx_urs4 = idx >> 4
            value = 0
            while idx_urs4 >= 17:
                value ^= table1[idx_urs4 % tablesize]
                idx_urs4 >>= 4
                value ^= table2[idx_urs4 % tablesize]
                idx_urs4 >>= 4
            yield value ^ tablev2[idx % tablesize]

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        file_key = self._file_key

        offset = toint_nofloat(offset)
        if offset < 0:
            raise ValueError("second argument 'offset' must be a non-negative integer")
        cipherdata = tobytearray(cipherdata)
        plaindata = bytearray(len(cipherdata))

        mask_byte_iterator = self.generate_mask(offset,
                                                len(cipherdata),
                                                self._table1,
                                                self._table2,
                                                self._tablev2
                                                )
        for idx, data_byte_peer in enumerate(zip(cipherdata, mask_byte_iterator)):
            cipherdata_byte, mask_byte = data_byte_peer
            plaindata[idx] = xor_lower_helf_byte(
                cipherdata_byte ^ mask_byte ^ file_key[(idx + offset) % 17]
            )

        return bytes(plaindata)


class KGMEncryptionAlgorithmWithCachedMask(StreamCipherSkel):
    @property
    def file_key(self) -> bytes:
        return self._file_key

    def __init__(self,
                 file_key: BytesLike,
                 mask_data: BytesLike
                 ) -> None:
        self._file_key = tobytes(file_key)
        self._mask_data = tobytes(mask_data)

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        file_key = self._file_key
        mask_data = self._mask_data

        offset = toint_nofloat(offset)
        if offset < 0:
            raise ValueError("second argument 'offset' must be a non-negative integer")
        cipherdata = tobytearray(cipherdata)
        plaindata = bytearray(len(cipherdata))

        for idx, data_byte_peer in enumerate(zip(cipherdata, mask_data)):
            cipherdata_byte, mask_byte = data_byte_peer
            plaindata[idx] = xor_lower_helf_byte(
                cipherdata_byte ^ mask_byte ^ file_key[(idx + offset) % 17]
            )

        return bytes(plaindata)


class VPREnceyptionAlgorithm(KGMEncryptionAlgorithm):
    @property
    def vpr_key(self):
        return self._vpr_key

    def __init__(self,
                 vpr_key: BytesLike,
                 file_key: BytesLike,
                 table1: BytesLike,
                 table2: BytesLike,
                 tablev2: BytesLike, /
                 ):
        self._vpr_key = tobytes(vpr_key)
        super().__init__(file_key, table1, table2, tablev2)

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        vpr_key = self._vpr_key

        staged = super().decrypt(cipherdata, offset)

        return bytestrxor(staged, bytes(vpr_key[(_ + offset) % 17] for _ in range(len(cipherdata))))


class VPREncryptionAlgorithmWithCachedMask(KGMEncryptionAlgorithmWithCachedMask):
    @property
    def vpr_key(self):
        return self._vpr_key

    def __init__(self, vpr_key: BytesLike, file_key: BytesLike, mask_data: BytesLike):
        self._vpr_key = tobytes(vpr_key)
        super().__init__(file_key, mask_data)

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        vpr_key = self._vpr_key

        staged = super().decrypt(cipherdata, offset)

        return bytestrxor(staged, bytes(vpr_key[(_ + offset) % 17] for _ in range(len(cipherdata))))
