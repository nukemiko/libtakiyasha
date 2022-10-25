# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import IO, Literal

from .kgmvprdataciphers import KGMorVPREncryptAlgorithm
from ..common import CryptLayerWrappedIOSkel
from ..exceptions import CrypterCreatingError
from ..keyutils import make_salt
from ..typedefs import BytesLike, FilePath
from ..typeutils import is_filepath, tobytes, verify_fileobj

__all__ = ['KGMorVPR']


class KGMorVPR(CryptLayerWrappedIOSkel):
    """基于 BytesIO 的 KGM/VPR 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 KGMorVPR 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``KGMorVPR.new()`` 和 ``KGMorVPR.from_file()`` 新建或打开已有 KGM 或 VPR 文件。

    已有 KGMorVPR 对象的 ``self.to_file()`` 方法可用于将对象内数据保存到文件，但目前尚未实现。
    尝试调用此方法会触发 ``NotImplementedError``。
    """

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
        """基于 BytesIO 的 KGM/VPR 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 KGMorVPR 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``KGMorVPR.new()`` 和 ``KGMorVPR.from_file()`` 新建或打开已有 KGM 或 VPR 文件。

        已有 KGMorVPR 对象的 ``self.to_file()`` 方法可用于将对象内数据保存到文件，但目前尚未实现。
        尝试调用此方法会触发 ``NotImplementedError``。
        """
        super().__init__(cipher, initial_bytes)
        if not isinstance(cipher, KGMorVPREncryptAlgorithm):
            raise TypeError('unsupported Cipher: '
                            f'supports {KGMorVPREncryptAlgorithm.__module__}.{KGMorVPREncryptAlgorithm.__name__}, '
                            f'not {type(cipher).__name__}'
                            )

    @classmethod
    def new(cls, subtype: Literal['kgm', 'vpr'], /,
            table1: BytesLike,
            table2: BytesLike,
            tablev2: BytesLike,
            vpr_key: BytesLike = None
            ) -> KGMorVPR:
        """创建并返回一个全新的空 KGMorVPR 对象。

        第一个位置参数 ``subtype`` 决定此 KGMorVPR 对象的透明加密层使用哪种加密算法，
        仅支持 ``'kgm'`` 和 ``'vpr'``。

        参数 ``table1``、``table2``、``tablev2`` 都是必选参数，
        因为它们会参与到内置透明加密层的创建过程中，并且在加密/解密过程中发挥关键作用。
        这三个参数的都必须是类字节对象，且转换为 ``bytes`` 后，长度为 272 字节。

        如果你选择 ``subtype='vpr'``，那么参数 ``vpr_key`` 是必选的：必须是类字节对象，且转换为 ``bytes``
        后的长度为 17 字节。
        """
        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)
        if vpr_key is not None:
            vpr_key = tobytes(vpr_key)
        if subtype == 'vpr':
            if vpr_key is None:
                raise ValueError("argument 'vpr_key' is required for VPR subtype")
            else:
                vpr_key = tobytes(vpr_key)
        elif subtype != 'kgm':
            if isinstance(subtype, str):
                raise ValueError(f"argument 'subtype' must be 'kgm' or 'vpr', not {subtype}")
            else:
                raise TypeError(f"argument 'subtype' must be str, not {type(subtype).__name__}")

        master_key = make_salt(16) + b'\x00'

        return cls(KGMorVPREncryptAlgorithm(table1, table2, tablev2, master_key, vpr_key))

    @classmethod
    def from_file(cls,
                  kgm_vpr_filething: FilePath | IO[bytes], /,
                  table1: BytesLike,
                  table2: BytesLike,
                  tablev2: BytesLike,
                  vpr_key: BytesLike = None
                  ) -> KGMorVPR:
        """打开一个 KGMorVPR 文件或文件对象 ``kgm_vpr_filething``。

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

        def operation(fileobj: IO[bytes]) -> KGMorVPR:
            fileobj_endpos = fileobj.seek(0, 2)
            fileobj.seek(0, 0)
            magicheader = fileobj.read(16)
            if magicheader == b'\x05\x28\xbc\x96\xe9\xe4\x5a\x43\x91\xaa\xbd\xd0\x7a\xf5\x36\x31':
                subtype: Literal['kgm', 'vpr'] = 'vpr'
                if vpr_key is None:
                    raise ValueError(
                        f"{repr(kgm_vpr_filething)} is a VPR file, but argument 'vpr_key' is missing"
                    )
            elif magicheader == b'\x7c\xd5\x32\xeb\x86\x02\x7f\x4b\xa8\xaf\xa6\x8e\x0f\xff\x99\x14':
                subtype: Literal['kgm', 'vpr'] = 'kgm'
            else:
                raise ValueError(f"{repr(kgm_vpr_filething)} is not a KGM or VPR file")
            header_len = int.from_bytes(fileobj.read(4), 'little')
            if header_len > fileobj_endpos:
                raise CrypterCreatingError(
                    f"{repr(kgm_vpr_filething)} is not a valid {subtype.upper()} file: "
                    f"header length ({header_len}) is greater than file size ({fileobj_endpos})"
                )
            fileobj.seek(28, 0)
            master_key = fileobj.read(16) + b'\x00'
            fileobj.seek(header_len, 0)

            initial_bytes = fileobj.read()

            cipher = KGMorVPREncryptAlgorithm(table1, table2, tablev2, master_key, vpr_key)
            return cls(cipher, initial_bytes)

        table1 = tobytes(table1)
        table2 = tobytes(table2)
        tablev2 = tobytes(tablev2)
        if vpr_key is not None:
            vpr_key = tobytes(vpr_key)

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
        """警告：尚未完全探明 KGM/VPR 文件的结构，因此本方法尚未实现，尝试调用会触发
        ``NotImplementedError``。预计的参数和行为如下：

        将当前 KGMorVPR 对象的内容保存到文件 ``kgm_vpr_filething``。

        第一个位置参数 ``kgm_vpr_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``kgm_vpr_filething``
        也可以是一个文件对象，但必须可写。

        本方法会首先尝试写入 ``kgm_vpr_filething`` 指向的文件。
        如果未提供 ``kgm_vpr_filething``，则会尝试写入 ``self.name``
        指向的文件。如果两者都为空或未提供，则会触发 ``CrypterSavingError``。
        """
        raise NotImplementedError('coming soon')
