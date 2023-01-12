# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import IO, NamedTuple

from .kgmvprdataciphers import KGMCryptoLegacy
from ..exceptions import CrypterCreatingError, CrypterSavingError
from ..prototypes import EncryptedBytesIOSkel
from ..typedefs import BytesLike, FilePath, KeyStreamBasedStreamCipherProto, StreamCipherProto
from ..typeutils import isfilepath, tobytes, verify_fileobj


class KGMorVPRFileInfo(NamedTuple):
    cipher_data_offset: int
    cipher_data_len: int
    encryption_version: int
    core_key_slot: int
    core_key_test_data: bytes
    master_key: bytes | None
    is_vpr: bool


def probe(filething: FilePath | IO[bytes], /) -> tuple[Path | IO[bytes], KGMorVPRFileInfo | None]:
    def operation(fd: IO[bytes]) -> KGMorVPRFileInfo | None:
        total_size = fd.seek(0, 2)
        if total_size < 60:
            return
        fd.seek(0, 0)

        header = fd.read(16)
        if header == b'\x05\x28\xbc\x96\xe9\xe4\x5a\x43\x91\xaa\xbd\xd0\x7a\xf5\x36\x31':
            is_vpr = True
        elif header == b'\x7c\xd5\x32\xeb\x86\x02\x7f\x4b\xa8\xaf\xa6\x8e\x0f\xff\x99\x14':
            is_vpr = False
        else:
            return

        cipher_data_offset = int.from_bytes(fd.read(4), 'little')
        encryption_version = int.from_bytes(fd.read(4), 'little')
        core_key_slot = int.from_bytes(fd.read(4), 'little')
        core_key_test_data = fd.read(16)
        master_key = fd.read(16)

        return KGMorVPRFileInfo(
            cipher_data_offset=cipher_data_offset,
            cipher_data_len=total_size - cipher_data_offset,
            encryption_version=encryption_version,
            core_key_slot=core_key_slot,
            core_key_test_data=core_key_test_data,
            master_key=master_key,
            is_vpr=is_vpr
        )

    if isfilepath(filething):
        with open(filething, mode='rb') as fileobj:
            return Path(filething), operation(fileobj)
    else:
        fileobj = verify_fileobj(filething, 'binary',
                                 verify_readable=True,
                                 verify_seekable=True
                                 )
        fileobj_origpos = fileobj.tell()
        prs = operation(fileobj)
        fileobj.seek(fileobj_origpos, 0)

        return fileobj, prs


class KGMorVPR(EncryptedBytesIOSkel):
    @property
    def acceptable_ciphers(self):
        return [KGMCryptoLegacy]

    def __init__(self,
                 cipher: StreamCipherProto | KeyStreamBasedStreamCipherProto, /,
                 initial_bytes: BytesLike = b''
                 ):
        super().__init__(cipher, initial_bytes)

        self._source_file_header_data: bytes | None = None

    @classmethod
    def from_file(cls,
                  kgm_vpr_filething: FilePath | IO[bytes], /,
                  table1: BytesLike,
                  table2: BytesLike,
                  tablev2: BytesLike,
                  vpr_key: BytesLike = None
                  ):
        return cls.open(kgm_vpr_filething,
                        table1=table1,
                        table2=table2,
                        tablev2=tablev2,
                        vpr_key=vpr_key
                        )

    @classmethod
    def open(cls,
             filething_or_info: tuple[Path | IO[bytes]] | FilePath | IO[bytes], /,
             table1: BytesLike,
             table2: BytesLike,
             tablev2: BytesLike,
             vpr_key: BytesLike = None
             ):
        # if table1 is not None:
        #     table1 = tobytes(table1)
        # if table2 is not None:
        #     table2 = tobytes(table2)
        # if tablev2 is not None:
        #     tablev2 = tobytes(tablev2)
        # if vpr_key is not None:
        #     vpr_key = tobytes(vpr_key)
        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)
        if vpr_key is not None:
            vpr_key = tobytes(vpr_key)

        def operation(fd: IO[bytes]) -> cls:
            if fileinfo.encryption_version != 3:
                raise CrypterCreatingError(
                    f'unsupported KGM encryption version {fileinfo.encryption_version} '
                    f'(only version 3 is supported)'
                )
            if fileinfo.is_vpr and vpr_key is None:
                raise TypeError(
                    "argument 'vpr_key' is required for encrypt and decrypt VPR file"
                )
            cipher = KGMCryptoLegacy(table1,
                                     table2,
                                     tablev2,
                                     fileinfo.core_key_test_data + b'\x00',
                                     vpr_key
                                     )

            fd.seek(fileinfo.cipher_data_offset, 0)

            inst = cls(cipher, fd.read(fileinfo.cipher_data_len))
            fd.seek(0, 0)
            inst._source_file_header_data = fd.read(fileinfo.cipher_data_offset)
            return inst

        if isinstance(filething_or_info, tuple):
            filething_or_info: tuple[Path | IO[bytes], KGMorVPRFileInfo | None]
            if len(filething_or_info) != 2:
                raise TypeError(
                    "first argument 'filething_or_info' must be a file path, a file object, "
                    "or a tuple of probe() returns"
                )
            filething, fileinfo = filething_or_info
        else:
            filething, fileinfo = probe(filething_or_info)

        if fileinfo is None:
            raise CrypterCreatingError(
                f"{repr(filething)} is not a KGM or VPR file"
            )
        elif not isinstance(fileinfo, KGMorVPRFileInfo):
            raise TypeError(
                f"second element of the tuple must be KGMorVPRFileInfo or None, not {type(fileinfo).__name__}"
            )

        if isfilepath(filething):
            with open(filething, mode='rb') as fileobj:
                instance = operation(fileobj)
                instance._name = Path(filething)
        else:
            fileobj = verify_fileobj(filething, 'binary',
                                     verify_readable=True,
                                     verify_seekable=True
                                     )
            fileobj_sourcefile = getattr(fileobj, 'name', None)
            instance = operation(fileobj)

            if fileobj_sourcefile is not None:
                instance._name = Path(fileobj_sourcefile)

        return instance

    def to_file(self, kgm_vpr_filething: FilePath | IO[bytes] = None) -> None:
        return self.save(kgm_vpr_filething)

    def save(self,
             filething: FilePath | IO[bytes] = None
             ) -> None:
        def operation(fd: IO[bytes]) -> None:
            if self._source_file_header_data is None:
                raise CrypterSavingError(
                    f"cannot save current {type(self).__name__} object to file '{str(filething)}', "
                    f"because it's not open from KGM or VPR file"
                )
            fd.seek(0, 0)
            fd.write(self._source_file_header_data)
            while blk := self.read(self.DEFAULT_BUFFER_SIZE, nocryptlayer=True):
                fd.write(blk)

        if filething is None:
            if self.source is None:
                raise TypeError(
                    "attribute 'self.source' and argument 'filething' are empty, "
                    "don't know which file to save to"
                )
            filething = self.source

        if isfilepath(filething):
            with open(filething, mode='wb') as fileobj:
                return operation(fileobj)
        else:
            fileobj = verify_fileobj(filething, 'binary',
                                     verify_seekable=True,
                                     verify_writable=True
                                     )
            return operation(fileobj)
