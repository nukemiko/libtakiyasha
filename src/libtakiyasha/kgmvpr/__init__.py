# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import IO, Literal

from .kgmvprdataciphers import KGMorVPREncryptAlgorithm
from ..common import CryptLayerWrappedIOSkel
from ..exceptions import CrypterCreatingError
from ..typedefs import BytesLike, FilePath
from ..typeutils import is_filepath, verify_fileobj

__all__ = ['KGMorVPR']


class KGMorVPR(CryptLayerWrappedIOSkel):
    @property
    def cipher(self) -> KGMorVPREncryptAlgorithm:
        return self._cipher

    @property
    def master_key(self) -> bytes:
        return self.cipher.master_key

    @property
    def vpr_key(self) -> bytes | None:
        return self._cipher.vpr_key

    @property
    def subtype(self):
        return 'KGM' if self.vpr_key is None else 'VPR'

    def __init__(self, cipher: KGMorVPREncryptAlgorithm, /, initial_bytes: BytesLike = b'') -> None:
        super().__init__(cipher, initial_bytes)

    @classmethod
    def new(cls) -> KGMorVPR:
        raise NotImplementedError('coming soon')

    @classmethod
    def from_file(cls,
                  kgm_vpr_filething: FilePath | IO[bytes], /,
                  table1: BytesLike,
                  table2: BytesLike,
                  tablev2: BytesLike,
                  vpr_key: BytesLike = None,
                  ) -> KGMorVPR:
        def operation(fileobj: IO[bytes]) -> KGMorVPR:
            fileobj_endpos = fileobj.seek(0, 2)
            fileobj.seek(0, 0)
            magicheader = fileobj.read(16)
            if magicheader == b'\x05\x28\xbc\x96\xe9\xe4\x5a\x43\x91\xaa\xbd\xd0\x7a\xf5\x36\x31':
                subtype: Literal['KGM', 'VPR'] = 'VPR'
                if vpr_key is None:
                    raise ValueError(
                        f"{repr(kgm_vpr_filething)} is a VPR file, but argument 'vpr_key' is missing"
                    )
            elif magicheader == b'\x7c\xd5\x32\xeb\x86\x02\x7f\x4b\xa8\xaf\xa6\x8e\x0f\xff\x99\x14':
                subtype: Literal['KGM', 'VPR'] = 'KGM'
            else:
                raise ValueError(f"{repr(kgm_vpr_filething)} is not a KGM or VPR file")
            header_len = int.from_bytes(fileobj.read(4), 'little')
            if header_len > fileobj_endpos:
                raise CrypterCreatingError(
                    f"{repr(kgm_vpr_filething)} is not a valid {subtype} file: "
                    f"header length ({header_len}) is greater than file size ({fileobj_endpos})"
                )
            fileobj.seek(28, 0)
            master_key = fileobj.read(16) + b'\x00'
            fileobj.seek(header_len, 0)

            initial_bytes = fileobj.read()

            cipher = KGMorVPREncryptAlgorithm(table1, table2, tablev2, master_key, vpr_key)
            return cls(cipher, initial_bytes)

        if is_filepath(kgm_vpr_filething):
            with open(kgm_vpr_filething, mode='rb') as kgm_vpr_fileobj:
                instance = operation(kgm_vpr_fileobj)
        else:
            kgm_vpr_fileobj = verify_fileobj(kgm_vpr_filething, 'binary',
                                             verify_readable=True,
                                             verify_seekable=True
                                             )
            instance = operation(kgm_vpr_fileobj)

        instance._name = getattr(kgm_vpr_fileobj, 'name', None)

        return instance

    def to_file(self, kgm_vpr_filething: FilePath | IO[bytes], /, **kwargs) -> None:
        raise NotImplementedError('coming soon')
