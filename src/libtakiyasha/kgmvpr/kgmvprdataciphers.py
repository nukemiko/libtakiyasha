# -*- coding: utf-8 -*-
from __future__ import annotations

from hashlib import md5
from typing import Generator, Literal

from ..prototypes import KeyStreamBasedStreamCipherSkel
from ..typedefs import BytesLike, IntegerLike
from ..typeutils import CachedClassInstanceProperty, tobytes, toint

__all__ = ['KGMCryptoLegacy']


def kugou_md5sum(data: bytes, /) -> bytes:
    md5sum = md5(data)
    md5digest = md5sum.digest()
    ret = bytearray(md5sum.digest_size)
    for i in range(0, md5sum.digest_size, 2):
        ret[i] = md5digest[14 - i]
        ret[i + 1] = md5digest[14 + 1 - i]

    return bytes(ret)


class KGMCryptoLegacy(KeyStreamBasedStreamCipherSkel):
    @CachedClassInstanceProperty
    def keysize(self) -> int:
        return 17

    @CachedClassInstanceProperty
    def tablesize(self) -> int:
        return 17 * 16

    def __init__(self,
                 table1: BytesLike,
                 table2: BytesLike,
                 tablev2: BytesLike,
                 core_key_test_data: BytesLike, /,
                 vpr_key: BytesLike = None,
                 ) -> None:
        self._table1 = tobytes(table1)
        self._table2 = tobytes(table2)
        self._tablev2 = tobytes(tablev2)

        for idx, valname_val in enumerate([('table1', self._table1),
                                           ('table2', self._table2),
                                           ('tablev2', self._tablev2)],
                                          start=1
                                          ):
            valname, val = valname_val
            if len(val) != self.tablesize:
                raise ValueError(
                    f"invalid length of position {idx} argument '{valname}': "
                    f"should be {self.tablesize}, not {len(val)}"
                )

        self._core_key_test_data = tobytes(core_key_test_data)
        if len(self._core_key_test_data) != self.keysize:
            raise ValueError(
                f"invalid length of fourth argument 'core_key_test_data': "
                f"should be {self.keysize}, not {len(self._core_key_test_data)}"
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

    def getkey(self, keyname: str = 'master') -> bytes | None:
        if keyname == 'master':
            return self._core_key_test_data
        elif keyname == 'table1':
            return self._table1
        elif keyname == 'table2':
            return self._table2
        elif keyname == 'tablev2':
            return self._tablev2
        elif keyname == 'vprkey':
            return self._vpr_key

    def prexor_encrypt(self, data: BytesLike, offset: IntegerLike, /) -> Generator[int, None, None]:
        offset = toint(offset)
        vpr_key = self._vpr_key
        keysize = self.keysize
        for idx, byte in enumerate(data, start=offset):
            if vpr_key is not None:
                byte ^= vpr_key[idx % keysize]
            yield byte ^ ((byte % 16) << 4)

    @staticmethod
    def prexor_decrypt(data: BytesLike, offset: IntegerLike, /) -> Generator[int, None, None]:
        offset = toint(offset)
        for idx, byte in enumerate(data, start=offset):
            yield byte ^ ((byte % 16) << 4)

    def postxor_decrypt(self, data: BytesLike, offset: IntegerLike, /) -> Generator[int, None, None]:
        offset = toint(offset)
        vpr_key = self._vpr_key
        keysize = self.keysize
        for idx, byte in enumerate(data, start=offset):
            if vpr_key is None:
                yield byte
            else:
                yield byte ^ vpr_key[idx % keysize]

    def genmask(self,
                nbytes: IntegerLike,
                offset: IntegerLike, /
                ) -> Generator[int, None, None]:
        nbytes = toint(nbytes)
        offset = toint(offset)
        if offset < 0:
            raise ValueError("second argument 'offset' must be a non-negative integer")
        if nbytes < 0:
            raise ValueError("first argument 'nbytes' must be a non-negative integer")

        tablesize: int = self.tablesize
        table1 = self._table1
        table2 = self._table2
        tablev2 = self._tablev2
        for idx in range(offset, offset + nbytes):
            idx_urs4 = idx >> 4
            value = 0
            while idx_urs4 >= 17:
                value ^= table1[idx_urs4 % tablesize]
                idx_urs4 >>= 4
                value ^= table2[idx_urs4 % tablesize]
                idx_urs4 >>= 4
            yield value ^ tablev2[idx % tablesize]

    def keystream(self,
                  operation: Literal['encrypt', 'decrypt'],
                  nbytes: IntegerLike,
                  offset: IntegerLike, /
                  ) -> Generator[int, None, None]:
        ck_test_data = self._core_key_test_data
        keysize: int = self.keysize

        mask_strm = self.genmask(nbytes, offset)
        if operation == 'encrypt':
            for idx, msb in enumerate(mask_strm, start=offset):
                yield msb ^ ck_test_data[idx % keysize]
        elif operation == 'decrypt':
            for idx, msb in enumerate(mask_strm, start=offset):
                msb ^= ck_test_data[idx % keysize]
                yield msb ^ ((msb % 16) << 4)
        elif isinstance(operation, str):
            raise ValueError(
                f"first argument 'operation' must be 'encrypt' or 'decrypt', not {operation}"
            )
        else:
            raise TypeError(
                f"first argument 'operation' must be str, not {type(operation).__name__}"
            )
