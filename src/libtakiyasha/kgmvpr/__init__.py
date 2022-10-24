# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import IO

from .kgmvprdataciphers import (KGMEncryptionAlgorithm,
                                KGMEncryptionAlgorithmWithCachedMask,
                                VPREnceyptionAlgorithm,
                                VPREncryptionAlgorithmWithCachedMask
                                )
from ..common import CryptLayerWrappedIOSkel
from ..typedefs import BytesLike, FilePath
from ..typeutils import is_filepath, tobytes, verify_fileobj

__all__ = ['KGM', 'VPR']


class KGM(CryptLayerWrappedIOSkel):
    @property
    def cipher(self) -> KGMEncryptionAlgorithm | KGMEncryptionAlgorithmWithCachedMask:
        return self._cipher

    @property
    def master_key(self) -> bytes:
        return self.cipher.file_key

    @classmethod
    def _from_file_operation(cls,
                             fileobj: IO[bytes],
                             table1: bytes,
                             table2: bytes,
                             tablev2: bytes
                             ):
        header = fileobj.read(60)
        file_key = header[28:44] + b'\x00'
        header_len = int.from_bytes(header[16:20], 'little')

        fileobj.seek(header_len, 0)

        initial_bytes = fileobj.read()

        ret = cls(KGMEncryptionAlgorithm(file_key, table1, table2, tablev2), initial_bytes)
        ret._file_key = file_key

        return ret

    @classmethod
    def from_file(cls,
                  kgm_filething: FilePath | IO[bytes], /,
                  table1: BytesLike,
                  table2: BytesLike,
                  tablev2: BytesLike
                  ) -> KGM:
        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)

        if is_filepath(kgm_filething):
            with open(kgm_filething, mode='rb') as kgm_fileobj:
                instance = cls._from_file_operation(kgm_fileobj, table1, table2, tablev2)
        else:
            kgm_fileobj = verify_fileobj(kgm_filething, 'binary',
                                         verify_readable=True,
                                         verify_seekable=True
                                         )
            instance = cls._from_file_operation(kgm_fileobj, table1, table2, tablev2)

        instance._name = getattr(kgm_fileobj, 'name', None)

        return instance

    def to_file(self, kgm_filething: FilePath | IO[bytes], /, **kwargs) -> None:
        raise NotImplementedError

    def new(self) -> KGM:
        raise NotImplementedError


class VPR(CryptLayerWrappedIOSkel):
    @property
    def cipher(self) -> VPREnceyptionAlgorithm | VPREnceyptionAlgorithm:
        return self._cipher

    @property
    def master_key(self) -> bytes:
        return self.cipher.file_key

    @property
    def vpr_key(self) -> bytes:
        return self.cipher.vpr_key

    @classmethod
    def _from_file_operation(cls,
                             fileobj: IO[bytes],
                             vpr_key: bytes,
                             table1: bytes,
                             table2: bytes,
                             tablev2: bytes
                             ):
        header = fileobj.read(60)
        file_key = header[28:44] + b'\x00'
        header_len = int.from_bytes(header[16:20], 'little')

        fileobj.seek(header_len, 0)

        initial_bytes = fileobj.read()

        ret = cls(VPREnceyptionAlgorithm(vpr_key, file_key, table1, table2, tablev2), initial_bytes)
        ret._file_key = file_key

        return ret

    @classmethod
    def from_file(cls,
                  vpr_filething: FilePath | IO[bytes], /,
                  vpr_key: BytesLike,
                  table1: BytesLike,
                  table2: BytesLike,
                  tablev2: BytesLike
                  ) -> VPR:
        vpr_key = tobytes(vpr_key)
        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)

        if is_filepath(vpr_filething):
            with open(vpr_filething, mode='rb') as vpr_fileobj:
                instance = cls._from_file_operation(vpr_fileobj, vpr_key, table1, table2, tablev2)
        else:
            vpr_fileobj = verify_fileobj(vpr_filething, 'binary',
                                         verify_readable=True,
                                         verify_seekable=True
                                         )
            instance = cls._from_file_operation(vpr_fileobj, vpr_key, table1, table2, tablev2)

        instance._name = getattr(vpr_fileobj, 'name', None)

        return instance

    def to_file(self, vpr_filething: FilePath | IO[bytes], /, **kwargs) -> None:
        raise NotImplementedError

    def new(self) -> VPR:
        raise NotImplementedError
