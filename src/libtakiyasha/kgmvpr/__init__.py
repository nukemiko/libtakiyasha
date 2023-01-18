# -*- coding: utf-8 -*-
from __future__ import annotations

import warnings
from pathlib import Path
from typing import IO, NamedTuple

from .kgmvprdataciphers import KGMCryptoLegacy
from ..exceptions import CrypterCreatingError
from ..keyutils import make_salt
from ..prototypes import EncryptedBytesIOSkel
from ..typedefs import BytesLike, FilePath, KeyStreamBasedStreamCipherProto, StreamCipherProto
from ..typeutils import isfilepath, tobytes, verify_fileobj

warnings.filterwarnings(action='default', category=DeprecationWarning, module=__name__)

__all__ = ['KGMorVPR', 'probe_kgmvpr', 'KGMorVPRFileInfo']


class KGMorVPRFileInfo(NamedTuple):
    cipher_data_offset: int
    cipher_data_len: int
    encryption_version: int
    core_key_slot: int
    core_key_test_data: bytes
    master_key: bytes | None
    is_vpr: bool


def probe_kgmvpr(filething: FilePath | IO[bytes], /) -> tuple[Path | IO[bytes], KGMorVPRFileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 KGM 或 VPR 文件。

    返回一个 2 个元素长度的元组：第一个元素为 ``filething``；如果
    ``filething`` 是 KGM 或 VPR 文件，那么第二个元素为一个 ``KGMorVPRFileInfo`` 对象；否则为 ``None``。

    如果 ``filething`` 是 VPR 文件，那么 ``KGMorVPRFileInfo``
    对象的 ``is_vpr`` 属性为 ``True``；否则为 ``False``。

    本方法的返回值可以用于 ``KGMorVPR.open()`` 的第一个位置参数。

    Args:
        filething: 源文件的路径或文件对象
    Returns:
        一个 2 个元素长度的元组：第一个元素为 filething；如果
        filething 是 KGM 或 VPR 文件，那么第二个元素为一个 KGMorVPRFileInfo 对象；否则为 None。
    """

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
    """基于 BytesIO 的 KGM/VPR 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 KGMorVPR 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``KGMorVPR.new()`` 和 ``KGMorVPR.open()`` 新建或打开已有 KGM/VPR 文件，
    使用已有 KGMorVPR 对象的 ``save()`` 方法将其保存到文件。
    """

    @property
    def acceptable_ciphers(self):
        return [KGMCryptoLegacy]

    def __init__(self,
                 cipher: StreamCipherProto | KeyStreamBasedStreamCipherProto, /,
                 initial_bytes: BytesLike = b''
                 ) -> None:
        """基于 BytesIO 的 KGM/VPR 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 KGMorVPR 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``KGMorVPR.new()`` 和 ``KGMorVPR.open()`` 新建或打开已有 KGM/VPR 文件，
        使用已有 KGMorVPR 对象的 ``save()`` 方法将其保存到文件。

        Args:
            cipher: 要使用的 cipher，必须是一个 libtakiyasha.kgmvpr.kgmvprdataciphers.KGMCryptoLegacy 对象
            initial_bytes: 内置缓冲区的初始数据
        """
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
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``KGMorVPR.open()`` 代替。）

        打开一个 KGMorVPR 文件或文件对象 ``kgm_vpr_filething``。

        第一个位置参数 ``kgm_vpr_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``kgm_vpr_filething``
        也可以是一个文件对象，但必须可读、可跳转（``kgm_vpr_filething.seekable() == True``）。

        参数 ``table1``、``table2``、``tablev2`` 都是必选参数，
        因为它们会参与到内置透明加密层的创建过程中，并且在加密/解密过程中发挥关键作用。
        这三个参数的都必须是类字节对象，且转换为 ``bytes`` 后，长度为 272 字节。

        本方法会寻找文件内嵌主密钥的位置和加密方式，进而判断所用加密算法的类型。

        如果探测到 ``VPR`` 文件，那么参数 ``vpr_key`` 是必选的：必须是类字节对象，且转换为 ``bytes``
        后的长度为 17 字节。
        """
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {cls.__name__}.open() instead.'
            )
        )
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
        """打开一个 KGMorVPR 文件，并返回一个 ``KGMorVPR`` 对象。

        第一个位置参数 ``filething_or_info`` 需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        ``filething_or_info`` 也可以接受 ``probe_kgmvpr()`` 函数的返回值：
        一个包含两个元素的元组，第一个元素是源文件的路径或文件对象，第二个元素是源文件的信息。

        第二、三、四个参数 ``table1``、``table2`` 和 ``tablev2``
        是必需的，都必须是 272 字节长度的字节串。

        如果探测到 VPR 文件，那么第五个参数 ``vpr_key``
        是必需的。如果提供，则必须是 17 字节长度的字节串。其他情况下，此参数会被忽略。

        Args:
            filething_or_info: 源文件的路径或文件对象，或者 probe_kgmvpr() 的返回值
            table1: 解码表 1
            table2: 解码表 2
            tablev2: 解码表 3
            vpr_key: 针对 VPR 文件额外所需的密钥
        """
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
                    "or a tuple of probe_kgmvpr() returns"
                )
            filething, fileinfo = filething_or_info
        else:
            filething, fileinfo = probe_kgmvpr(filething_or_info)

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
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``KGMorVPR.save()`` 代替。）

        将当前 KGMorVPR 对象的内容保存到文件 ``kgm_vpr_filething``。

        第一个位置参数 ``kgm_vpr_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``kgm_vpr_filething``
        也可以是一个文件对象，但必须可写。

        本方法会首先尝试写入 ``kgm_vpr_filething`` 指向的文件。
        如果未提供 ``kgm_vpr_filething``，则会尝试写入 ``self.name``
        指向的文件。如果两者都为空或未提供，则会触发 ``CrypterSavingError``。

        目前无法生成 KGM/VPR 文件的标头数据，因此本方法不能用于保存通过 ``KGMorVPR.new()``
        创建的 ``KGMorVPR`` 对象。尝试这样做会触发 ``NotImplementedError``。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )

        return self.save(kgm_vpr_filething)

    def save(self,
             filething: FilePath | IO[bytes] = None
             ) -> None:
        """（实验性功能）将当前对象保存为一个新 KGM 或 VPR 文件。

        第一个参数 ``filething`` 是可选的，如果提供此参数，需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。
        如果未提供此参数，那么将会尝试使用当前对象的 ``source`` 属性；如果后者也不可用，则引发
        ``TypeError``。

        目前无法生成 KGM/VPR 文件的标头数据，因此本方法不能用于保存通过 ``KGMorVPR.new()``
        创建的 ``KGMorVPR`` 对象。尝试这样做会触发 ``NotImplementedError``。

        Args:
            filething: 目标文件的路径或文件对象
        """

        def operation(fd: IO[bytes]) -> None:
            if self._source_file_header_data is None:
                raise NotImplementedError(
                    f"cannot save current {type(self).__name__} object to file '{str(filething)}', "
                    f"generate KGM/VPR file header is not supported"
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

    @classmethod
    def new(cls,
            table1: BytesLike,
            table2: BytesLike,
            tablev2: BytesLike,
            vpr_key: BytesLike = None
            ):
        """返回一个空 KGMorVPR 对象。

        第一、二、三个参数 ``table1``、``table2`` 和 ``tablev2``
        是必需的，都必须是 272 字节长度的字节串。

        如果提供了第五个参数 ``vpr_key``，那么将会使用针对 VPR 的加密方法；这种情况下
        ``vpr_key`` 必须是 17 字节长度的字节串。

        注意：通过本方法创建的 ``KGMorVPR`` 对象不可通过 ``save()``
        方法保存到文件。尝试这样做会触发 ``NotImplementedError``。
        """
        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)
        if vpr_key is not None:
            vpr_key = tobytes(vpr_key)

        core_key_test_data = make_salt(16) + b'\x00'

        cipher = KGMCryptoLegacy(table1, table2, tablev2, core_key_test_data, vpr_key)

        return cls(cipher)
