# -*- coding: utf-8 -*-
from __future__ import annotations

import warnings
from base64 import b64decode, b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, IO, Literal, NamedTuple

from .qmcdataciphers import HardenedRC4, Mask128
from .qmckeyciphers import QMCv2KeyEncryptV1, QMCv2KeyEncryptV2
from ..exceptions import CrypterCreatingError
from ..keyutils import make_random_ascii_string, make_salt
from ..prototypes import EncryptedBytesIOSkel
from ..typedefs import BytesLike, FilePath
from ..typeutils import isfilepath, tobytes, verify_fileobj
from ..warns import CrypterSavingWarning

warnings.filterwarnings(action='default', category=CrypterSavingWarning, module=__name__)
warnings.filterwarnings(action='default', category=DeprecationWarning, module=__name__)

__all__ = [
    'probe_qmcv2',
    'QMCv1',
    'QMCv2',
    'QMCv2QTag',
    'QMCv2STag'
]


@dataclass
class QMCv2QTag:
    """解析、存储和重建 QMCv2 文件末尾的 QTag 数据。不包括主密钥。"""
    song_id: int = 0
    unknown: int = 2

    @classmethod
    def load(cls, qtag_serialized: BytesLike, /):
        qtag_serialized = tobytes(qtag_serialized)
        qtag_serialized_splitted = qtag_serialized.split(b',')
        if len(qtag_serialized_splitted) != 3:
            raise ValueError('invalid QMCv2 QTag data: the counts of splitted segments '
                             f'should be equal to 3, not {len(qtag_serialized_splitted)}'
                             )
        master_key_encrypted_b64encoded = qtag_serialized_splitted[0]
        song_id: int = int(qtag_serialized_splitted[1])
        unknown: int = int(qtag_serialized_splitted[2])

        return master_key_encrypted_b64encoded, cls(song_id=song_id, unknown=unknown)

    def dump(self, master_key_encrypted_b64encoded: BytesLike, /) -> bytes:
        return b','.join(
            [
                tobytes(master_key_encrypted_b64encoded),
                str(self.song_id).encode('ascii'),
                str(self.unknown).encode('ascii')
            ]
        )


@dataclass
class QMCv2STag:
    """解析、存储和重建 QMCv2 文件末尾的 STag 数据。"""
    song_id: int = 0
    unknown: int = 2
    song_mid: str = '0' * 14

    @classmethod
    def load(cls, stag_serialized: BytesLike, /):
        stag_serialized = tobytes(stag_serialized)
        stag_serialized_splitted = stag_serialized.split(b',')
        if len(stag_serialized_splitted) != 3:
            raise ValueError('invalid QMCv2 STag data: the counts of splitted segments '
                             f'should be equal to 3, not {len(stag_serialized_splitted)}'
                             )
        song_id: int = int(stag_serialized_splitted[0])
        unknown: int = int(stag_serialized_splitted[1])
        song_mid: str = str(stag_serialized_splitted[2], encoding='ascii')

        return cls(song_id=song_id, unknown=unknown, song_mid=song_mid)

    def dump(self) -> bytes:
        return b','.join(
            [
                str(self.song_id).encode('ascii'),
                str(self.unknown).encode('ascii'),
                str(self.song_mid).encode('ascii')
            ]
        )


class QMCv2FileInfo(NamedTuple):
    """用于存储 QMCv2 文件的信息。"""
    cipher_ctor: Callable[[...], HardenedRC4] | Callable[[...], Mask128] | None
    cipher_data_len: int
    master_key_encrypted: bytes | None
    master_key_encryption_ver: int | None
    extra_info: QMCv2QTag | QMCv2STag | None


def _guess_cipher_ctor(master_key: BytesLike, /,
                       is_encrypted: bool = True
                       ) -> Callable[[...], HardenedRC4] | Callable[[...], Mask128] | None:
    if is_encrypted:
        expected_keylen_mask128 = (272, 392)
        expected_keylen_hardened_rc4 = (528, 736)
    else:
        expected_keylen_mask128 = (256, 256)
        expected_keylen_hardened_rc4 = (512, 512)

    master_key = tobytes(master_key)
    if len(master_key) in expected_keylen_mask128:
        return Mask128.from_qmcv2_key256
    elif len(master_key) in expected_keylen_hardened_rc4:
        return HardenedRC4
    elif len(master_key) == 128 and not is_encrypted:
        return Mask128


def probe_qmcv2(filething: FilePath | IO[bytes], /) -> tuple[Path | IO[bytes], QMCv2FileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 QMCv2 文件。

    返回一个 2 个元素长度的元组：第一个元素为 ``filething``；如果
    ``filething`` 是 QMCv2 文件，那么第二个元素为一个 ``QMCv2FileInfo`` 对象；否则为 ``None``。

    本方法的返回值可以用于 ``QMCv2.open()`` 的第一个位置参数。

    本方法不适用于 QMCv1 文件的探测。

    Args:
        filething: 源文件的路径或文件对象
    Returns:
        一个 2 个元素长度的元组：第一个元素为 filething；如果
        filething 是 QMCv2 文件，那么第二个元素为一个 QMCv2FileInfo 对象；否则为 None。
    """

    def operation(fd: IO[bytes]) -> QMCv2FileInfo | None:
        total_size = fd.seek(-4, 2) + 4
        tail_data = fd.read(4)

        if tail_data == b'STag':
            fd.seek(-8, 2)
            tag_serialized_len = int.from_bytes(fd.read(4), 'big')
            if tag_serialized_len > (total_size - 8):
                return
            cipher_data_len = fd.seek(-(tag_serialized_len + 8), 2)
            extra_info = QMCv2STag.load(fd.read(tag_serialized_len))

            cipher_ctor = None
            master_key_encrypted = None
            master_key_encryption_ver = None
        elif tail_data == b'QTag':
            fd.seek(-8, 2)
            tag_serialized_len = int.from_bytes(fd.read(4), 'big')
            if tag_serialized_len > (total_size - 8):
                return
            cipher_data_len = fd.seek(-(tag_serialized_len + 8), 2)
            master_key_encrypted_b64encoded, extra_info = QMCv2QTag.load(fd.read(tag_serialized_len))
            master_key_encrypted = b64decode(master_key_encrypted_b64encoded)

            cipher_ctor = _guess_cipher_ctor(master_key_encrypted)
            master_key_encryption_ver = 1
        else:
            extra_info = None
            master_key_encrypted_b64encoded_len = int.from_bytes(tail_data, 'little')
            if master_key_encrypted_b64encoded_len > total_size - 4:
                return
            cipher_data_len = fd.seek(-(master_key_encrypted_b64encoded_len + 4), 2)
            master_key_encrypted_b64encoded = fd.read(master_key_encrypted_b64encoded_len)
            try:
                master_key_encrypted_b64encoded.decode('ascii')
            except UnicodeDecodeError:
                return
            master_key_encrypted_b64decoded = b64decode(master_key_encrypted_b64encoded)
            if master_key_encrypted_b64decoded.startswith(b'QQMusic EncV2,Key:'):
                master_key_encrypted = master_key_encrypted_b64decoded[18:]
                master_key_encryption_ver = 2
            else:
                master_key_encrypted = master_key_encrypted_b64decoded
                master_key_encryption_ver = 1
            cipher_ctor = _guess_cipher_ctor(master_key_encrypted)

        return QMCv2FileInfo(cipher_ctor=cipher_ctor,
                             cipher_data_len=cipher_data_len,
                             master_key_encrypted=master_key_encrypted,
                             master_key_encryption_ver=master_key_encryption_ver,
                             extra_info=extra_info
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


class QMCv1(EncryptedBytesIOSkel):
    """基于 BytesIO 的 QMCv1 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 QMCv1 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``QMCv1.new()`` 和 ``QMCv1.open()`` 新建或打开已有 QMCv1 文件，
    使用已有 QMCv1 对象的 ``save()`` 方法将其保存到文件。
    """

    @property
    def acceptable_ciphers(self):
        return [Mask128]

    @classmethod
    def from_file(cls,
                  filething: FilePath | IO[bytes], /,
                  mask: BytesLike
                  ):
        """本方法已被废弃，并且可能会在未来版本中被移除。请尽快使用 ``QMCv1.open()`` 代替。"""
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated and no longer used. '
                f'Use {cls.__name__}.open() instead.'
            )
        )
        return cls.open(filething, mask=mask)

    @classmethod
    def open(cls,
             filething: FilePath | IO[bytes], /,
             mask: BytesLike
             ):
        """打开一个 QMCv1 文件，并返回一个 ``QMCv1`` 对象。

        第一个位置参数 ``filething`` 需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        第二个参数 ``mask`` 是必需的，用于主密钥。其长度必须为 44、128 或 256 位。

        Args:
            filething: 源文件的路径或文件对象
            mask: 文件的主密钥，其长度必须为 44、128 或 256 位
        Raises:
            ValueError: mask 的长度不符合上述要求
        """
        mask = tobytes(mask)

        def operation(fd: IO[bytes]) -> cls:
            if len(mask) == 44:
                cipher = Mask128.from_qmcv1_mask44(mask)
            elif len(mask) == 128:
                cipher = Mask128(mask)
            elif len(mask) == 256:
                cipher = Mask128.from_qmcv1_mask256(mask)
            else:
                raise ValueError(
                    f"the length of argument 'mask' must be 44, 128, or 256, not {len(mask)}"
                )

            fd.seek(0, 0)
            return cls(cipher, fd.read())

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

    def to_file(self, filething: FilePath | IO[bytes] = None, /) -> None:
        """本方法已被废弃，并且可能会在未来版本中被移除。请尽快使用 ``QMCv1.save()`` 代替。"""
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated and no longer used. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )
        return self.save(filething)

    def save(self, filething: FilePath | IO[bytes] = None, /) -> None:
        """将当前对象保存为一个新 QMCv1 文件。

        第一个参数 ``filething`` 是可选的，如果提供此参数，需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        Args:
            filething: 目标文件的路径或文件对象

        Raises:
            TypeError: 当前对象的属性 source 和参数 filething 都为空，无法保存文件
        """

        def operation(fd: IO[bytes]):
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
    def new(cls, mask: BytesLike = None):
        """返回一个空 QMCv1 对象。

        第一个参数 ``mask`` 是可选的，如果提供，将被用作主密钥。
        """
        if mask is None:
            mask = make_salt(128)
        else:
            mask = tobytes(mask)
        return cls(Mask128(mask))


class QMCv2(EncryptedBytesIOSkel):
    """基于 BytesIO 的 QMCv2 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 QMCv2 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``QMCv2.new()`` 和 ``QMCv2.open()`` 新建或打开已有 QMCv2 文件，
    使用已有 QMCv2 对象的 ``save()`` 方法将其保存到文件。
    """

    @property
    def acceptable_ciphers(self):
        return [HardenedRC4, Mask128]

    def __init__(self, cipher: HardenedRC4 | Mask128, /, initial_bytes: BytesLike = b'') -> None:
        """基于 BytesIO 的 QMCv2 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 QMCv2 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``QMCv2.new()`` 和 ``QMCv2.open()`` 新建或打开已有 QMCv2 文件，
        使用已有 QMCv2 对象的 ``save()`` 方法将其保存到文件。
        """
        super().__init__(cipher, initial_bytes)

        self._extra_info: QMCv2QTag | QMCv2STag | None = None

    @property
    def extra_info(self) -> QMCv2QTag | QMCv2STag | None:
        return self._extra_info

    @extra_info.setter
    def extra_info(self, value: QMCv2QTag | QMCv2STag | None) -> None:
        if value is None or isinstance(value, (QMCv2QTag, QMCv2STag)):
            self._extra_info = value
        raise TypeError(
            f"attribute 'extra_info' must be QMCv2QTag, QMCv2STag, or None, not {repr(value)}"
        )

    @property
    def master_key(self) -> bytes | None:
        if isinstance(self.cipher, Mask128):
            ret = self.cipher.getkey('original')
            if ret:
                return ret

        return super().master_key

    @classmethod
    def from_file(cls,
                  filething_or_info: tuple[Path | IO[bytes], QMCv2FileInfo | None] | FilePath | IO[bytes], /,
                  core_key: BytesLike = None,
                  garble_key1: BytesLike = None,
                  garble_key2: BytesLike = None,
                  master_key: BytesLike = None
                  ):
        """本方法已被废弃，并且可能会在未来版本中被移除。请尽快使用 ``QMCv2.open()`` 代替。"""
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated and no longer used. '
                f'Use {cls.__name__}.open() instead.'
            )
        )
        return cls.open(filething_or_info,
                        core_key=core_key,
                        garble_key1=garble_key1,
                        garble_key2=garble_key2,
                        master_key=master_key
                        )

    @classmethod
    def open(cls,
             filething_or_info: tuple[Path | IO[bytes], QMCv2FileInfo | None] | FilePath | IO[bytes], /,
             core_key: BytesLike = None,
             garble_key1: BytesLike = None,
             garble_key2: BytesLike = None,
             master_key: BytesLike = None,
             encrypt_method: Literal['map', 'mask', 'rc4'] = None
             ):
        """打开一个 QMCv2 文件，并返回一个 ``QMCv2`` 对象。

        第一个位置参数 ``filething_or_info`` 需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        ``filething_or_info`` 也可以接受 ``probe_qmcv2()`` 函数的返回值：
        一个包含两个元素的元组，第一个元素是源文件的路径或文件对象，第二个元素是源文件的信息。

        第二个参数 ``core_key`` 一般情况下是必需的，用于解密文件内嵌的主密钥。
        例外：如果你提供了第五个参数 ``master_key``，那么它是可选的。

        第三、第四个参数 ``garble_key1`` 和 ``garble_key2``，仅在探测到文件内嵌的主密钥使用了
        V2 加密时是必需的。在其他情况下，它们的值会被忽略。

        第五个参数 ``master_key`` 可选，如果提供，将会被作为主密钥使用，
        而文件内置的主密钥会被忽略，``core_key``、``garble_key1`` 和 ``garble_key2``
        也不再是必需参数。
        例外：如果探测到文件未嵌入任何形式的密钥，那么此参数是必需的。

        第六个参数 ``encrypt_method`` 用于指定文件数据使用的加密方式，支持以下值：

        - ``'map'`` 或 ``'mask'`` - 掩码表（Mask128）
        - ``'rc4'`` - 强化版 RC4（HardenedRC4）
        - ``None`` - 不指定，由 ``probe_qmcv2()`` 自行探测

        此参数的设置会覆盖 ``probe_qmcv2()`` 的探测结果。

        Args:
            filething_or_info: 源文件的路径或文件对象，或者 probe_qmcv2() 的返回值
            core_key: 核心密钥，用于解密文件内嵌的主密钥
            garble_key1: 混淆密钥 1，用于解密使用 V2 加密的主密钥
            garble_key2: 混淆密钥 2，用于解密使用 V2 加密的主密钥
            master_key: 如果提供，将会被作为主密钥使用，而文件内置的主密钥会被忽略
            encrypt_method: 用于指定文件数据使用的加密方式，支持 'map'、'mask'、'rc4' 或 None
        Raises:
            TypeError: 参数 core_key 和 master_key 都未提供，或者缺少 garble_key1 或 garble_key2 用于解密 V2 加密的主密钥
            ValueError: encrypt_method 的值不符合上述条件
            CrypterCreatingError: probe_qmcv2() 返回的文件信息中，master_key_encryption_ver 的值是当前不支持的
        """
        if core_key is not None:
            core_key = tobytes(core_key)
        if garble_key1 is not None:
            garble_key1 = tobytes(garble_key1)
        if garble_key2 is not None:
            garble_key2 = tobytes(garble_key2)
        if master_key is not None:
            master_key = tobytes(master_key)
        if encrypt_method is not None:
            if encrypt_method not in ('map', 'mask', 'rc4'):
                if isinstance(encrypt_method, str):
                    raise ValueError(
                        f"argument 'encrypt_method' must be 'map', 'mask', or 'rc4', "
                        f"not {repr(encrypt_method)}"
                    )
                else:
                    raise TypeError(
                        f"argument 'encrypt_method' must be str, "
                        f"not {type(encrypt_method).__name__}"
                    )

        def operation(fd: IO[bytes]) -> cls:
            cipher_data_len = fileinfo.cipher_data_len
            extra_info = fileinfo.extra_info
            master_key_encrypted = fileinfo.master_key_encrypted
            master_key_encryption_ver = fileinfo.master_key_encryption_ver
            cipher_ctor = fileinfo.cipher_ctor

            if master_key is None:
                if isinstance(extra_info, QMCv2STag):
                    raise TypeError(
                        "argument 'master_key' is required to "
                        "QMCv2 file ends with STag"
                    )
                if core_key is None:
                    raise TypeError(
                        "argument 'core_key' is required to "
                        "decrypt the protected master key"
                    )
                if master_key_encryption_ver == 1:
                    target_master_key = QMCv2KeyEncryptV1(core_key).decrypt(
                        master_key_encrypted
                    )
                elif master_key_encryption_ver == 2:
                    if garble_key1 is None and garble_key2 is None:
                        raise TypeError(
                            "argument 'garble_key1' and 'garble_key2' is required to "
                            "decrypt the QMCv2 Key Encryption V2 protected master key"
                        )
                    elif garble_key1 is None:
                        raise TypeError(
                            "argument 'garble_key1' is required to "
                            "decrypt the QMCv2 Key Encryption V2 protected master key"
                        )
                    elif garble_key2 is None:
                        raise TypeError(
                            "argument 'garble_key2' is required to "
                            "decrypt the QMCv2 Key Encryption V2 protected master key"
                        )
                    target_master_key = QMCv2KeyEncryptV2(
                        core_key, garble_key1, garble_key2
                    ).decrypt(master_key_encrypted)
                else:
                    raise CrypterCreatingError(
                        f"unsupported master key encryption version {master_key_encryption_ver}"
                    )
            else:
                target_master_key = master_key
                cipher_ctor = _guess_cipher_ctor(target_master_key, is_encrypted=False)

            if encrypt_method in ('map', 'mask'):
                cipher_ctor = Mask128
            elif encrypt_method == 'rc4':
                cipher_ctor = HardenedRC4

            if cipher_ctor is None:
                raise TypeError(
                    "don't know which cipher to use, "
                    f"please try {cls.__name__}.open() again "
                    f"with argument 'encrypt_method'"
                )

            cipher = cipher_ctor(target_master_key)
            fd.seek(0, 0)
            inst = cls(cipher, fd.read(cipher_data_len))
            inst._extra_info = extra_info

            return inst

        if isinstance(filething_or_info, tuple):
            filething_or_info: tuple[Path | IO[bytes], QMCv2FileInfo | None]
            if len(filething_or_info) != 2:
                raise TypeError(
                    "first argument 'filething_or_info' must be a file path, a file object, "
                    "or a tuple of probe_qmcv2() returns"
                )
            filething, fileinfo = filething_or_info
            if fileinfo is None:
                raise CrypterCreatingError(
                    f"{repr(filething)} is not a QMCv2 file"
                )
        else:
            filething, fileinfo = probe_qmcv2(filething_or_info)

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

    def to_file(self,
                core_key: BytesLike = None,
                filething: FilePath | IO[bytes] = None,
                garble_key1: BytesLike = None,
                garble_key2: BytesLike = None,
                with_extra_info: bool = False
                ) -> None:
        """本方法已被废弃，并且可能会在未来版本中被移除。请尽快使用 ``QMCv2.save()`` 代替。"""
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated and no longer used. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )
        return self.save(core_key=core_key,
                         filething=filething,
                         garble_key1=garble_key1,
                         garble_key2=garble_key2,
                         with_extra_info=with_extra_info
                         )

    def save(self,
             core_key: BytesLike = None,
             filething: FilePath | IO[bytes] = None,
             garble_key1: BytesLike = None,
             garble_key2: BytesLike = None,
             with_extra_info: bool = False
             ) -> None:
        """将当前对象保存为一个新 QMCv2 文件。

        第一个参数 ``core_key`` 一般是必需的，用于加密主密钥，以便嵌入到文件。
        例外：参数 ``with_extra_info=True`` 且当前对象的属性 ``extra_info``
        是一个 ``QMCv2STag`` 对象，此时它是可选的，其值会被忽略。

        第二个参数 ``filething`` 是可选的，如果提供此参数，需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。
        如果未提供此参数，那么将会尝试使用当前对象的 ``source`` 属性；如果后者也不可用，则引发
        ``TypeError``。

        第三、第四个参数 ``garble_key1`` 和 ``garble_key2``，决定对主密钥进行加密的方法；
        如果提供，则需要两个一起提供，将会对主密钥采用 V2 加密；否则，对主密钥采用 V1 加密。
        如果参数 ``with_extra_info=True`` 且当前对象的属性 ``extra_info``
        是一个 ``QMCv2STag`` 对象，它们的值会被忽略。

        第五个参数 ``with_extra_info`` 如果为 ``True``，且当前对象的属性 ``extra_info`` 是
        ``QMCv2QTag`` 或 ``QMCv2STag`` 对象，那么这些对象将会被序列化后嵌入文件。

        Args:
            core_key: 核心密钥，用于加密主密钥，以便嵌入到文件
            filething: 目标文件的路径或文件对象
            garble_key1: 混淆密钥 1，用于使用 V2 加密方式加密主密钥
            garble_key2: 混淆密钥 2，用于使用 V2 加密方式加密主密钥
            with_extra_info: 是否在文件末尾添加额外信息（self.extra_info）

        Raises:
            TypeError: 当前对象的属性 source 和参数 filething 都为空，无法保存文件；参数 core_key 和 master_key 都未提供，或者缺少 garble_key1 或 garble_key2 用于使用 V2 方式加密主密钥
        """
        if core_key is not None:
            core_key = tobytes(core_key)
        if garble_key1 is not None:
            garble_key1 = tobytes(garble_key1)
        if garble_key2 is not None:
            garble_key2 = tobytes(garble_key2)

        def operation(fd: IO[bytes]) -> None:
            fd.seek(0, 0)
            extra_info = self.extra_info

            if with_extra_info:
                if isinstance(extra_info, QMCv2STag):
                    warnings.warn(
                        CrypterSavingWarning(
                            "Extra info (self.extra_info) will be export to STag data, "
                            "which cannot save the master key. "
                            "So you should save the master key in other way. "
                            "Use 'self.master_key' to get it."
                        )
                    )
                    tag_serialized = extra_info.dump()
                    fd.write(self.getvalue(nocryptlayer=True))
                    fd.write(tag_serialized)
                    fd.write(len(tag_serialized).to_bytes(4, 'big'))
                    fd.write(b'STag')

                    return

            master_key = self.master_key
            if core_key is None:
                raise TypeError(
                    "argument 'core_key' is required to encrypt the master key "
                    "before embed to file"
                )
            if with_extra_info:
                if isinstance(extra_info, QMCv2QTag):
                    master_key_encrypted = QMCv2KeyEncryptV1(core_key).encrypt(master_key)
                    master_key_encrypted_b64encoded = b64encode(master_key_encrypted)
                    tag_serialized = extra_info.dump(master_key_encrypted_b64encoded)
                    fd.write(self.getvalue(nocryptlayer=True))
                    fd.write(tag_serialized)
                    fd.write(len(tag_serialized).to_bytes(4, 'big'))
                    fd.write(b'QTag')

                    return

            if garble_key1 is None and garble_key2 is None:  # QMCv2 KeyencV1
                master_key_encrypted = QMCv2KeyEncryptV1(core_key).encrypt(master_key)
                master_key_encrypted_b64encoded = b64encode(master_key_encrypted)
            else:  # QMCv2 KeyEncV2
                if garble_key1 is None:
                    raise TypeError(
                        "argument 'garble_key1' is required to encrypt the master key "
                        "with QMCv2 Key Encryption V2 before embed to file"
                    )
                if garble_key2 is None:
                    raise TypeError(
                        "argument 'garble_key2' is required to encrypt the master key "
                        "with QMCv2 Key Encryption V2 before embed to file"
                    )
                master_key_encrypted = QMCv2KeyEncryptV2(
                    core_key, garble_key1, garble_key2
                ).encrypt(master_key)
                master_key_encrypted_b64encoded = b64encode(
                    b'QQMusic EncV2,Key:' + master_key_encrypted
                )
            fd.write(self.getvalue(nocryptlayer=True))
            fd.write(master_key_encrypted_b64encoded)
            fd.write(len(master_key_encrypted_b64encoded).to_bytes(4, 'little'))

            return

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
    def new(cls, encrypt_method: Literal['map', 'mask', 'rc4'], /):
        """返回一个空 QMCv2 对象。

        第一个位置参数 ``encrypt_method`` 是必需的，用于指示使用的加密方式，支持以下值：

        - ``'map'`` 或 ``'mask'`` - 掩码表（Mask128）
        - ``'rc4'`` - 强化版 RC4（HardenedRC4）

        Raises:
            ValueError: encrypt_method 的值不符合上述条件
        """
        if encrypt_method in ('map', 'mask'):
            cipher = Mask128.from_qmcv2_key256(make_random_ascii_string(256).encode('ascii'))
        elif encrypt_method == 'rc4':
            cipher = HardenedRC4(make_random_ascii_string(512).encode('ascii'))
        elif isinstance(encrypt_method, str):
            raise ValueError(
                f"argument 'encrypt_method' must be 'map', 'mask', or 'rc4', "
                f"not {repr(encrypt_method)}"
            )
        else:
            raise TypeError(
                f"argument 'encrypt_method' must be str, "
                f"not {type(encrypt_method).__name__}"
            )

        return cls(cipher)
