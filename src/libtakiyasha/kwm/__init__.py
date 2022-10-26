# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import IO

from .kwmdataciphers import Mask32
from ..common import CryptLayerWrappedIOSkel
from ..keyutils import make_salt
from ..typedefs import BytesLike, FilePath
from ..typeutils import is_filepath, tobytes, verify_fileobj


class KWM(CryptLayerWrappedIOSkel):
    """基于 BytesIO 的 KWM 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 KWM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``KWM.new()`` 和 ``KWM.from_file()`` 新建或打开已有 KWM 文件。

    已有 KWM 对象的 ``self.to_file()`` 方法可用于将对象内数据保存到文件，但目前尚未实现。
    尝试调用此方法会触发 ``NotImplementedError``。
    """

    @property
    def cipher(self) -> Mask32:
        return self._cipher

    @property
    def core_key(self) -> bytes:
        return self.cipher.core_key

    @property
    def master_key(self) -> bytes:
        return self.cipher.master_key

    def __init__(self, cipher: Mask32, /, initial_bytes: BytesLike = b'') -> None:
        """基于 BytesIO 的 KWM 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 KWM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``KWM.new()`` 和 ``KWM.from_file()`` 新建或打开已有 KWM 文件。

        已有 KWM 对象的 ``self.to_file()`` 方法可用于将对象内数据保存到文件，但目前尚未实现。
        尝试调用此方法会触发 ``NotImplementedError``。
        """
        super().__init__(cipher, initial_bytes)
        if not isinstance(cipher, Mask32):
            raise TypeError('unsupported Cipher: '
                            f'supports {Mask32.__module__}.{Mask32.__name__}, '
                            f'not {type(cipher).__name__}'
                            )

    @classmethod
    def new(cls, core_key: BytesLike) -> KWM:
        """创建并返回一个全新的空 KWM 对象。

        第一个参数 ``core_key`` 是必需的，它被用于还原和解密主密钥。
        """
        core_key = tobytes(core_key)

        master_key = make_salt(8)
        cipher = Mask32(core_key, master_key)

        return cls(cipher)

    @classmethod
    def from_file(cls,
                  kwm_filething: FilePath | IO[bytes], /,
                  core_key: BytesLike
                  ):
        """打开一个 KWM 文件或文件对象 ``kwm_filething``。

        第一个位置参数 ``kwm_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``kwm_filething``
        也可以是一个文件对象，但必须可读、可跳转（``kwm_filething.seekable() == True``）。

        第二个参数 ``core_key`` 是必需的，它被用于还原和解密主密钥。
        """

        def operation(fileobj: IO[bytes]) -> cls:
            if not fileobj.read(24).startswith(b'yeelion-kuwo-tme'):
                raise ValueError(f"{repr(kwm_filething)} is not a KWM file")

            master_key = fileobj.read(8)
            cipher = Mask32(core_key, master_key)

            fileobj.seek(1024, 0)
            initial_bytes = fileobj.read()

            return cls(cipher, initial_bytes)

        core_key = tobytes(core_key)

        if is_filepath(kwm_filething):
            with open(kwm_filething, mode='rb') as kwm_fileobj:
                instance = operation(kwm_fileobj)
        else:
            kwm_fileobj = verify_fileobj(kwm_filething, 'binary',
                                         verify_readable=True,
                                         verify_seekable=True
                                         )

        instance._name = getattr(kwm_fileobj, 'name', None)

        return instance

    def to_file(self, kwm_filething: FilePath | IO[bytes]) -> None:
        """警告：尚未完全探明 KWM 文件的结构，因此本方法尚未实现，尝试调用会触发
        ``NotImplementedError``。预计的参数和行为如下：

        将当前 KWM 对象的内容保存到文件 ``kwm_filething``。

        第一个位置参数 ``kwm_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``kwm_filething``
        也可以是一个文件对象，但必须可写。

        本方法会首先尝试写入 ``kwm_filething`` 指向的文件。
        如果未提供 ``kwm_filething``，则会尝试写入 ``self.name``
        指向的文件。如果两者都为空或未提供，则会触发 ``CrypterSavingError``。
        """
        raise NotImplementedError('coming soon')
