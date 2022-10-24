# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import IO

from .kgmvprdataciphers import KGMEncryptionAlgorithm, KGMEncryptionAlgorithmWithCachedMask
from ..common import CryptLayerWrappedIOSkel
from ..typedefs import BytesLike, FilePath
from ..typeutils import is_filepath, verify_fileobj


class KGM(CryptLayerWrappedIOSkel):
    @property
    def cipher(self) -> KGMEncryptionAlgorithm | KGMEncryptionAlgorithmWithCachedMask:
        return self._cipher

    @property
    def master_key(self) -> bytes | None:
        return getattr(self, '_file_key', None)

    def __init__(self,
                 cipher: KGMEncryptionAlgorithm | KGMEncryptionAlgorithmWithCachedMask, /,
                 initial_bytes: BytesLike = b''
                 ) -> None:
        super().__init__(cipher, initial_bytes)

    @classmethod
    def from_file(cls,
                  kgm_filething: FilePath | IO[bytes], /,
                  table1: BytesLike,
                  table2: BytesLike,
                  tablev2: BytesLike,
                  ) -> KGM:
        def operation(fileobj: IO[bytes]):
            header = fileobj.read(60)
            file_key = header[28:44] + b'\x00'
            header_len = int.from_bytes(header[16:20], 'little')

            fileobj.seek(header_len, 0)

            initial_bytes = fileobj.read()

            ret = cls(KGMEncryptionAlgorithm(file_key, table1, table2, tablev2), initial_bytes)
            ret._file_key = file_key

            return ret

        if is_filepath(kgm_filething):
            with open(kgm_filething, mode='rb') as kgm_fileobj:
                instance = operation(kgm_fileobj)
        else:
            kgm_fileobj = verify_fileobj(kgm_filething, 'binary',
                                         verify_readable=True,
                                         verify_seekable=True
                                         )
            instance = operation(kgm_fileobj)

        instance._name = getattr(kgm_fileobj, 'name', None)

        return instance

    def to_file(self, kgm_filething: FilePath | IO[bytes], /, **kwargs) -> None:
        raise NotImplementedError

    def new(self) -> KGM:
        raise NotImplementedError
