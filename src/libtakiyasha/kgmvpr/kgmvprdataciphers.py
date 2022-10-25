# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Generator, TypedDict

from .kgmvprmaskutils import make_maskstream, xor_half_lower_byte
from ..common import StreamCipherSkel
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import CachedClassInstanceProperty, tobytes, toint_nofloat

__all__ = ['KGMorVPRTables', 'KGMorVPREncryptAlgorithm']


class KGMorVPRTables(TypedDict):
    table1: bytes
    table2: bytes
    tablev2: bytes


class KGMorVPREncryptAlgorithm(StreamCipherSkel):
    @CachedClassInstanceProperty
    def keysize(self) -> int:
        return 17

    @CachedClassInstanceProperty
    def tablesize(self) -> int:
        return 17 * 16

    @property
    def master_key(self) -> bytes:
        return self._master_key

    @property
    def vpr_key(self) -> bytes | None:
        return self._vpr_key

    @property
    def tables(self) -> KGMorVPRTables:
        return {
            'table1' : self._table1,
            'table2' : self._table2,
            'tablev2': self._tablev2
        }

    def __init__(self,
                 table1: BytesLike,
                 table2: BytesLike,
                 tablev2: BytesLike,
                 master_key: BytesLike, /,
                 vpr_key: BytesLike = None,
                 ) -> None:
        self._table1 = tobytes(table1)
        self._table2 = tobytes(table2)
        self._tablev2 = tobytes(tablev2)

        for valname, val in [('table1', self._table1),
                             ('table2', self._table2),
                             ('tablev2', self._tablev2)]:
            if len(val) != self.tablesize:
                raise ValueError(
                    f"invalid length of argument '{valname}': should be {self.tablesize}, not {len(val)}"
                )

        self._master_key = tobytes(master_key)
        if len(self._master_key) != self.keysize:
            raise ValueError(
                f"invalid length of argument 'master_key': "
                f"should be {self.keysize}, not {len(self._master_key)}"
            )
        if vpr_key is None:
            self._vpr_key = None
        else:
            self._vpr_key = tobytes(vpr_key)
            if len(self._vpr_key) != self.keysize:
                raise ValueError(
                    f"invalid length of argument 'vpr_key': "
                    f"should be {self.keysize}, not {len(self._vpr_key)}"
                )

    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        master_key = self._master_key
        vpr_key: bytes | None = self._vpr_key
        keysize = self.keysize

        offset = toint_nofloat(offset)
        if offset < 0:
            ValueError("second argument 'offset' must be a non-negative integer")
        plaindata = tobytes(plaindata)
        cipherdata_buf = bytearray(len(plaindata))

        maskstream_iterator = make_maskstream(
            offset, len(plaindata), self._table1, self._table2, self._tablev2
        )
        for idx, peered_byte in enumerate(zip(plaindata, maskstream_iterator)):
            pdb, msb = peered_byte
            if vpr_key is not None:
                pdb ^= vpr_key[(idx + offset) % keysize]
            cdb = xor_half_lower_byte(pdb) ^ msb ^ master_key[(idx + offset) % keysize]
            cipherdata_buf[idx] = cdb

        return tobytes(cipherdata_buf)

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        master_key = self._master_key
        vpr_key: bytes | None = self._vpr_key
        keysize = self.keysize

        offset = toint_nofloat(offset)
        if offset < 0:
            ValueError("second argument 'offset' must be a non-negative integer")
        cipherdata = tobytes(cipherdata)
        plaindata_buf = bytearray(len(cipherdata))

        maskstream_iterator = make_maskstream(
            offset, len(cipherdata), self._table1, self._table2, self._tablev2
        )
        for idx, peered_byte in enumerate(zip(cipherdata, maskstream_iterator)):
            cdb, msb = peered_byte
            pdb = xor_half_lower_byte(cdb ^ msb ^ master_key[(idx + offset) % keysize])
            if vpr_key is not None:
                pdb ^= vpr_key[(idx + offset) % keysize]
            plaindata_buf[idx] = pdb

        return tobytes(plaindata_buf)
