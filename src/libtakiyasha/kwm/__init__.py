# -*- coding: utf-8 -*-
from __future__ import annotations

import warnings
from math import log10
from pathlib import Path
from typing import IO, NamedTuple

from .kwmdataciphers import Mask32, Mask32FromRecipe
from ..exceptions import CrypterCreatingError, CrypterSavingError
from ..keyutils import make_salt
from ..prototypes import EncryptedBytesIOSkel
from ..typedefs import BytesLike, FilePath, IntegerLike, KeyStreamBasedStreamCipherProto, StreamCipherProto
from ..typeutils import isfilepath, tobytes, toint, verify_fileobj

warnings.filterwarnings(action='default', category=DeprecationWarning, module=__name__)

DIGIT_CHARS = b'0123456789'
ASCII_LETTER_CHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

__all__ = ['KWM', 'probe_kwm', 'KWMFileInfo']


class KWMFileInfo(NamedTuple):
    mask_recipe: bytes
    cipher_data_offset: int
    cipher_data_len: int
    bitrate: int | None
    suffix: str


def probe_kwm(filething: FilePath | IO[bytes], /) -> tuple[Path | IO[bytes], KWMFileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 KWM 文件。

    返回一个 2 个元素长度的元组：第一个元素为 ``filething``；如果
    ``filething`` 是 KWM 文件，那么第二个元素为一个 ``KWMFileInfo`` 对象；否则为 ``None``。

    本方法的返回值可以用于 ``KWM.open()`` 的第一个位置参数。

    Args:
        filething: 源文件的路径或文件对象
    Returns:
        一个 2 个元素长度的元组：第一个元素为 filething；如果
        filething 是 KWM 文件，那么第二个元素为一个 KWMFileInfo 对象；否则为 None。
    """

    def operation(fd: IO[bytes]) -> KWMFileInfo | None:
        fd.seek(0, 0)

        header_data = fd.read(1024)
        cipher_data_offset = fd.tell()
        cipher_data_len = fd.seek(0, 2) - cipher_data_offset

        if not header_data.startswith(b'yeelion-kuwo'):
            return

        mask_recipe = header_data[24:32]

        bitrate = None
        bitrate_suffix_serialized = header_data[48:56].rstrip(b'\x00')
        bitrate_serialized_len = 0
        for byte in bitrate_suffix_serialized:
            if byte in DIGIT_CHARS:
                bitrate_serialized_len += 1
        if bitrate_serialized_len > 0:
            bitrate = int(bitrate_suffix_serialized[:bitrate_serialized_len]) * 1000

        suffix = None
        suffix_serialized = bitrate_suffix_serialized[bitrate_serialized_len:]
        suffix_serialized_len = 0
        for byte in suffix_serialized:
            if byte in ASCII_LETTER_CHARS:
                suffix_serialized_len += 1
        if suffix_serialized_len > 0:
            suffix = suffix_serialized[:suffix_serialized_len].decode('ascii')

        return KWMFileInfo(
            mask_recipe=mask_recipe,
            cipher_data_offset=cipher_data_offset,
            cipher_data_len=cipher_data_len,
            bitrate=bitrate,
            suffix=suffix
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


class KWM(EncryptedBytesIOSkel):
    """基于 BytesIO 的 KWM 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 KWM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``KWM.new()`` 和 ``KWM.open()`` 新建或打开已有 KWM 文件，
    使用已有 KWM 对象的 ``save()`` 方法将其保存到文件。
    """

    @property
    def acceptable_ciphers(self):
        return [Mask32FromRecipe]

    def __init__(self,
                 cipher: StreamCipherProto | KeyStreamBasedStreamCipherProto, /,
                 initial_bytes: BytesLike = b''
                 ) -> None:
        """基于 BytesIO 的 KWM 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 KWM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``KWM.new()`` 和 ``KWM.open()`` 新建或打开已有 KWM 文件，
        使用已有 KWM 对象的 ``save()`` 方法将其保存到文件。

        Args:
            cipher: 要使用的 cipher，必须是一个 libtakiyasha.kwm.kwmdataciphers.Mask32/Mask32FromRecipe 对象
            initial_bytes: 内置缓冲区的初始数据
        """
        super().__init__(cipher, initial_bytes=initial_bytes)

        self._bitrate: int | None = None
        self._suffix: str | None = None

    @property
    def bitrate(self) -> int | None:
        """音频的比特率。如果要用作显示用途，需要除以 1000。

        不可设置为负数；如果不为 ``None``，其字面量长度与后缀 ``self.suffix`` 的长度不可超过 8。
        """
        return self._bitrate

    @bitrate.setter
    def bitrate(self, value: IntegerLike) -> None:
        """音频的比特率。如果要用作显示用途，需要除以 1000。

        不可设置为负数；如果不为 ``None``，其字面量长度与后缀 ``self.suffix`` 的长度不可超过 8。
        """
        if value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'bitrate'. "
                f"Use `del self.bitrate` instead"
            )
        br = toint(value)
        if br < 0:
            raise ValueError(f"attribute 'bitrate' must be a non-netagive integer, not {value}")
        if self._suffix is None:
            max_bitrate_len = 8
        else:
            max_bitrate_len = 8 - len(self._suffix)
        bitrate_len = int(log10(br // 1000)) + 1
        if bitrate_len > max_bitrate_len:
            raise ValueError(f"attribute 'bitrate' must be less than {max_bitrate_len}, not {bitrate_len}")

        self._bitrate = br

    @bitrate.deleter
    def bitrate(self) -> None:
        """音频的比特率。本属性储存的是乘以 1000 后的结果。

        不可设置为负数；如果不为 ``None``，其整除 1000 后的字面量长度与后缀
        ``self.suffix`` 的长度之和不可大于 8。
        """
        self._bitrate = None

    @property
    def suffix(self) -> int | None:
        """加密数据对应的文件应当使用的后缀。由于不够精确，不建议使用。

        如果不为 None，其长度与比特率 ``self.bitrate`` 整除 1000 后的字面量长度之和不可大于 8。
        """
        return self._suffix

    @suffix.setter
    def suffix(self, value: str) -> None:
        """加密数据对应的文件应当使用的后缀。由于不够精确，不建议使用。

        如果不为 None，其长度与比特率 ``self.bitrate`` 整除 1000 后的字面量长度之和不可大于 8。
        """
        if value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'suffix'. "
                f"Use `del self.suffix` instead"
            )
        if not isinstance(value, str):
            raise TypeError(f"attribute 'suffix' must be str, not {type(value).__name__}")
        value = str(value)
        if self._bitrate is None:
            max_suffix_len = 8
        else:
            max_suffix_len = 8 - (int(log10(self._bitrate // 1000)) + 1)
        if len(value) > max_suffix_len:
            raise ValueError(
                f"attribute 'bitrate' must be less than {max_suffix_len}, not {len(value)}"
            )
        for char in (ord(_) for _ in value):
            if char not in ASCII_LETTER_CHARS:
                raise ValueError(
                    f"attribute 'suffix' can only contains digits and ascii letters, but '{chr(char)}' found"
                )
        self._suffix = value

    @suffix.deleter
    def suffix(self) -> None:
        """加密数据对应的文件应当使用的后缀。由于不够精确，不建议使用。

        如果不为 None，其长度与比特率 ``self.bitrate`` 整除 1000 后的字面量长度之和不可大于 8。
        """
        self._suffix = None

    @classmethod
    def from_file(cls,
                  kwm_filething: FilePath | IO[bytes], /,
                  core_key: BytesLike
                  ):
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``KWM.open()`` 代替。）

        打开一个 KWM 文件或文件对象 ``kwm_filething``。

        第一个位置参数 ``kwm_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``kwm_filething``
        也可以是一个文件对象，但必须可读、可跳转（``kwm_filething.seekable() == True``）。

        第二个参数 ``core_key`` 是必需的，它被用于还原和解密主密钥。
        """
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {cls.__name__}.open() instead.'
            )
        )

        return cls.open(kwm_filething, core_key=core_key)

    @classmethod
    def open(cls,
             filething_or_info: tuple[Path | IO[bytes], KWMFileInfo | None] | FilePath | IO[bytes], /,
             core_key: BytesLike = None,
             master_key: BytesLike = None
             ):
        """打开一个 KWM 文件，并返回一个 ``KWM`` 对象。

        第一个位置参数 ``filething_or_info`` 需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        ``filething_or_info`` 也可以接受 ``probe_kwm()`` 函数的返回值：
        一个包含两个元素的元组，第一个元素是源文件的路径或文件对象，第二个元素是源文件的信息。

        第二个参数 ``core_key`` 一般情况下是必需的，用于解密文件内嵌的主密钥。
        例外：如果你提供了第三个参数 ``mask``，那么它是可选的。

        第三个参数 ``mask`` 可选，如果提供，将会被作为主密钥使用，
        而文件内置的主密钥会被忽略，``core_key`` 也不再是必需参数。

        Args:
            filething_or_info: 源文件的路径或文件对象，或者 probe_kwm() 的返回值
            core_key: 核心密钥，用于生成文件内加密数据的主密钥
            master_key: 如果提供，将会被作为主密钥使用，而文件内置的主密钥会被忽略
        """
        if core_key is not None:
            core_key = tobytes(core_key)
        if master_key is not None:
            master_key = tobytes(master_key)

        def operation(fd: IO[bytes]) -> cls:
            fd.seek(1024, 0)
            initial_bytes = fd.read()

            if master_key is not None:
                cipher = Mask32(master_key)
            elif core_key is None:
                raise TypeError(
                    "argument 'core_key' is required to "
                    "generate the master key"
                )
            else:
                cipher = Mask32FromRecipe(fileinfo.mask_recipe, core_key)

            inst = cls(cipher, initial_bytes)
            inst._bitrate = fileinfo.bitrate
            inst._suffix = fileinfo.suffix

            return inst

        if isinstance(filething_or_info, tuple):
            filething_or_info: tuple[Path | IO[bytes], KWMFileInfo | None]
            if len(filething_or_info) != 2:
                raise TypeError(
                    "first argument 'filething_or_info' must be a file path, a file object, "
                    "or a tuple of probe_kwm() returns"
                )
            filething, fileinfo = filething_or_info
        else:
            filething, fileinfo = probe_kwm(filething_or_info)

        if fileinfo is None:
            raise CrypterCreatingError(
                f"{repr(filething)} is not a KWM file"
            )
        elif not isinstance(fileinfo, KWMFileInfo):
            raise TypeError(
                f"second element of the tuple must be KWMFileInfo or None, not {type(fileinfo).__name__}"
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

    def to_file(self, kwm_filething: FilePath | IO[bytes] = None) -> None:
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``KWM.save()`` 代替。）"""
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )

        return self.save(kwm_filething)

    def save(self,
             filething: FilePath | IO[bytes] = None,
             newer_magic_header: bool = False
             ) -> None:
        """（实验性功能）将当前对象保存为一个新 KWM 文件。

        第一个参数 ``filething`` 是可选的，如果提供此参数，需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。
        如果未提供此参数，那么将会尝试使用当前对象的 ``source`` 属性；如果后者也不可用，则引发
        ``TypeError``。

        第二个参数 ``newer_magic_header`` 可选，如果为 ``True``，那么保存的文件会使用新版 KWM\
        文件的文件头 ``b'yeelion-kuwo'``；否则使用 ``b'yeelion-kuwo-tme'``。

        Args:
            filething: 目标文件的路径或文件对象
            newer_magic_header: 是否使用新版 KWM 文件使用的文件头
        """

        def operation(fd: IO[bytes]) -> None:
            recipe = self.cipher.getkey('original')
            if not recipe:
                raise CrypterSavingError('cannot store a non-standard recipe into a KWM file')

            fd.seek(0, 0)
            if newer_magic_header:
                fd.write(b'yeelion-kuwo')
            else:
                fd.write(b'yeelion-kuwo-tme')
            fd.seek(24, 0)
            fd.write(recipe)
            fd.seek(48, 0)
            if self._bitrate is not None:
                fd.write(str(self._bitrate // 1000).encode('ascii'))
            if self._suffix is not None:
                fd.write(self._suffix.encode('ascii'))
            fd.seek(1024, 0)
            fd.write(self.getvalue(nocryptlayer=True))

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
    def new(cls, core_key: BytesLike):
        """返回一个空 KWM 对象。"""
        core_key = tobytes(core_key)

        recipe = make_salt(8)
        cipher = Mask32FromRecipe(recipe, core_key)

        return cls(cipher)
