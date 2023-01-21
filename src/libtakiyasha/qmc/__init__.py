# -*- coding: utf-8 -*-
from __future__ import annotations

import re
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
from ..typedefs import BytesLike, FilePath, IntegerLike
from ..typeutils import isfilepath, tobytes, verify_fileobj
from ..warns import CrypterSavingWarning

warnings.filterwarnings(action='default', category=CrypterSavingWarning, module=__name__)
warnings.filterwarnings(action='default', category=DeprecationWarning, module=__name__)

__all__ = [
    'probe_qmc',
    'probe_qmcv1',
    'probe_qmcv2',
    'QMCv1',
    'QMCv2',
    'QMCv2QTag',
    'QMCv2STag',
    'QMCv1FileInfo',
    'QMCv2FileInfo'
]

QMCV1_SUFFIX_PATTERN = re.compile('\\.qmc[a-zA-Z0-9]{1,4}$', flags=re.IGNORECASE)


@dataclass
class QMCv2QTag:
    """解析、存储和生成 QMCv2 文件末尾的 QTag 数据（不包括主密钥）。

    可以按照操作数据类（``dataclass``）实例的方式操作本类的实例。
    """
    song_id: int = 0
    """此歌曲在 QQ 音乐的 ID。"""
    unknown: int = 2
    """含义未知，在已知所有样本中都为 2。"""

    @classmethod
    def load(cls, qtag_serialized: BytesLike, /):
        """解析一段 QTag 数据，返回加密后的主密钥和一个 QMCv2QTag 对象。"""
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
        """根据当前 QMCv2QTag 对象生成并返回一段 QTag 数据，需要已加密的主密钥。"""
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
    """此歌曲在 QQ 音乐的 ID。"""
    unknown: int = 2
    """含义未知，在已知所有样本中都为 2。"""
    song_mid: str = '0' * 14
    """此歌曲在 QQ 音乐的媒体 ID（MId）。"""

    @classmethod
    def load(cls, stag_serialized: BytesLike, /):
        """解析一段 STag 数据，返回一个 QMCv2STag 对象。"""
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
        """根据当前 QMCv2STag 对象生成并返回一段 STag 数据。

        可以按照操作数据类（``dataclass``）实例的方式操作本类的实例。
        """
        return b','.join(
            [
                str(self.song_id).encode('ascii'),
                str(self.unknown).encode('ascii'),
                str(self.song_mid).encode('ascii')
            ]
        )


class QMCv1FileInfo(NamedTuple):
    """用于存储 QMCv1 文件的信息。"""
    cipher_data_offset: int
    cipher_data_len: int


class QMCv2FileInfo(NamedTuple):
    """用于存储 QMCv2 文件的信息。"""
    cipher_ctor: Callable[[...], HardenedRC4] | Callable[[...], Mask128] | None
    cipher_data_offset: int
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


def probe_qmcv1(filething: FilePath | IO[bytes], /, is_qmcv1: bool = False) -> tuple[Path | IO[bytes], QMCv1FileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 QMCv1 文件。

    返回一个 2 个元素长度的元组：

    - 第一个元素为 ``filething``；
    - 如果 ``filething`` 是 QMCv1 文件，那么第二个元素为一个 ``QMCv1FileInfo`` 对象；
    - 否则为 ``None``。

    目前难以通过文件结构识别 QMCv1 文件，因此本方法通过文件扩展名判断是否为 QMCv1 文件。
    只要文件扩展名匹配下列正则表达式模式（不区分大小写），本方法就会将此文件视为一个 QMCv1 文件：

    ``^\\.qmc[a-zA-Z0-9]{1,4}$``

    对于不匹配以上正则表达式的文件扩展名（或者无法获取到文件扩展名），如果参数
    ``is_qmcv1=True``，本方法会跳过探测过程，认为此文件是一个 QMCv1 文件，并直接返回结果。

    本方法的返回值可以用于 ``QMCv1.open()`` 的第一个位置参数。

    本方法不适用于 QMCv2 文件的探测。

    Args:
        filething: 源文件的路径或文件对象
        is_qmcv1: 跳过探测过程，认为源文件是一个 QMCv1 文件
    Returns:
        一个 2 个元素长度的元组：第一个元素为 filething；如果
        filething 是 QMCv1 文件，那么第二个元素为一个 QMCv1FileInfo 对象；否则为 None。
    """

    def operation(fd: IO[bytes]) -> QMCv1FileInfo | None:
        filename = getattr(fd, 'name', None)
        if filename is None and not is_qmcv1:
            return
        filepath = Path(filename)
        if QMCV1_SUFFIX_PATTERN.search(filepath.suffix) or is_qmcv1:
            return QMCv1FileInfo(
                cipher_data_offset=0,
                cipher_data_len=fd.seek(0, 2)
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


def probe_qmcv2(filething: FilePath | IO[bytes], /) -> tuple[Path | IO[bytes], QMCv2FileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 QMCv2 文件。

    返回一个 2 个元素长度的元组：

    - 第一个元素为 ``filething``；
    - 如果 ``filething`` 是 QMCv2 文件，那么第二个元素为一个 ``QMCv2FileInfo`` 对象；
    - 否则为 ``None``。

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
                             cipher_data_offset=0,
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


def probe_qmc(
        filething: FilePath | IO[bytes], /
) -> tuple[Path | IO[bytes], QMCv1FileInfo | None] | tuple[Path | IO[bytes], QMCv2FileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 QMCv1 或 QMCv2 文件。

    返回一个 2 个元素长度的元组：

    - 第一个元素为 ``filething``；
    - 如果 ``filething`` 是 QMCv1 文件，那么第二个元素为一个 ``QMCv1FileInfo`` 对象；
    - 如果 ``filething`` 是 QMCv2 文件，那么第二个元素为一个 ``QMCv2FileInfo`` 对象；
    - 如果都不是，则为 ``None``。

    本方法的返回值可以用于 ``QMCv1.open()`` 和 ``QMCv2.open()`` 的第一个位置参数。

    Args:
        filething: 源文件的路径或文件对象
    Returns:
        一个 2 个元素长度的元组：第一个元素为 filething；如果
        filething 是 QMCv1 文件，那么第二个元素为一个 QMCv1FileInfo 对象；如果
        filething 是 QMCv2 文件，那么第二个元素为一个 QMCv2FileInfo 对象；否则为 None。
    """
    fthing, fileinfo = probe_qmcv2(filething)
    if fileinfo:
        return fthing, fileinfo
    return probe_qmcv1(filething)


class QMCv1(EncryptedBytesIOSkel):
    """基于 BytesIO 的 QMCv1 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 QMCv1 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``QMCv1.new()`` 和 ``QMCv1.open()`` 新建或打开已有 QMCv1 文件，
    使用已有 QMCv1 对象的 ``save()`` 方法将其保存到文件。

    使用示例：

    - 新建一个 QMCv1 对象以便编辑：
    >>> qmcv1file = QMCv1.new()  # 添加 mask 参数以便自定义密钥，否则使用随机生成的密钥
    >>> qmcv1file
    <libtakiyasha.qmc.QMCv1 at 0x7ff6820d9e90, cipher <libtakiyasha.qmc.qmcdataciphers.Mask128 object at 0x7ff682178c10>>
    >>>

    - 获取使用的主密钥：
    >>> qmcv1file.master_key  # 此处的密钥是随机生成的
    b'}t4\\x87-\\xcd\\x88\\x93Ro\\x12g1Q\\xc4O\\xb3...'
    >>>

    - 访问内部的 Cipher 对象：
    >>> qmcv1file.cipher
    <libtakiyasha.qmc.qmcdataciphers.Mask128 object at 0x7ff682178c10>
    >>>

    - 打开一个外部 QMCv1 文件：
    >>> qmcv1file = QMCv1.open('/path/to/qmcv1file.qmcflac', mask=b'YourQMCv1Mask...')
    >>> qmcv1file
    <libtakiyasha.qmc.QMCv1 at 0x7ff6820d9e90, cipher <libtakiyasha.qmc.qmcdataciphers.Mask128 object at 0x7ff682178c10>, source '/path/to/qmcv1file.qmcflac'>
    >>>

    - 读取和写入，注意写入操作产生的修改需要调用 ``save()`` 方法显式保存：
    >>> qmcv1file.read(16)
    b'fLaC\\x00\\x00\\x00"\\x12\\x00\\x12\\x00\\x00\\x07)\\x00'
    >>> qmcv1file.seek(0, 2)
    36137109
    >>> qmcv1file.write(b'\\x00Writing something')
    18
    >>>

    - 保存上述操作产生的更改
    >>> # 如果该 QMCv1 对象不是从文件打开的，还需要 filething 参数
    >>> qmcv1file.save()
    >>>
    """

    @property
    def acceptable_ciphers(self):
        return [Mask128]

    @classmethod
    def from_file(cls,
                  qmcv1_filething: FilePath | IO[bytes], /,
                  master_key: BytesLike
                  ):
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``QMCv1.open()`` 代替。）

        打开一个 QMCv1 文件或文件对象 ``qmcv1_filething``。

        第一个位置参数 ``qmcv1_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``qmcv1_filething``
        也可以是一个文件对象，但必须可读。

        第二个位置参数 ``master_key`` 用于解密音频数据，长度仅限 44、128 或 256 位。
        如果不符合长度要求，会触发 ``ValueError``。
        """
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {cls.__name__}.open() instead.'
            )
        )
        return cls.open(qmcv1_filething, mask=master_key)

    @classmethod
    def open(cls,
             filething_or_info: tuple[Path | IO[bytes], QMCv1FileInfo | None] | FilePath | IO[bytes], /,
             mask: BytesLike
             ):
        """打开一个 QMCv1 文件，并返回一个 ``QMCv1`` 对象。

        第一个位置参数 ``filething`` 需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        第二个参数 ``mask`` 是必需的，用于主密钥。其长度必须为 44、128 或 256 位。

        Args:
            filething_or_info: 源文件的路径或文件对象
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

            fd.seek(fileinfo.cipher_data_offset, 0)
            return cls(cipher, fd.read(fileinfo.cipher_data_len))

        if isinstance(filething_or_info, tuple):
            filething_or_info: tuple[Path | IO[bytes], QMCv1FileInfo | None]
            if len(filething_or_info) != 2:
                raise TypeError(
                    "first argument 'filething_or_info' must be a file path, a file object, "
                    "or a tuple of probe_qmc(), probe_qmcv1() returns"
                )
            filething, fileinfo = filething_or_info
        else:
            filething, fileinfo = probe_qmcv1(filething_or_info)

        if fileinfo is None:
            raise CrypterCreatingError(
                f"{repr(filething)} is not a QMCv1 file"
            )
        elif not isinstance(fileinfo, QMCv1FileInfo):
            raise TypeError(
                f"second element of the tuple must be QMCv1FileInfo or None, not {type(fileinfo).__name__}"
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

    def to_file(self, qmcv1_filething: FilePath | IO[bytes] = None) -> None:
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``QMCv2.save()`` 代替。）

        将当前 QMCv1 对象的内容保存到文件 ``qmcv1_filething``。

        第一个位置参数 ``qmcv1_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``qmcv1_filething``
        也可以是一个文件对象，但必须可写。

        本方法会首先尝试写入 ``qmcv1_filething`` 指向的文件。
        如果未提供 ``qmcv1_filething``，则会尝试写入 ``self.name``
        指向的文件。如果两者都为空或未提供，则会触发 ``CrypterSavingError``。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )
        return self.save(qmcv1_filething)

    def save(self, filething: FilePath | IO[bytes] = None) -> None:
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

        使用示例：

    - 新建一个 QMCv2 对象以便编辑：
    >>> qmcv2file = QMCv2.new('mask')  # 必须选择使用的加密方式，可用值：'map'、'mask'、'rc4'
    >>> qmcv2file
    <libtakiyasha.qmc.QMCv2 at 0x7ff6820d9e90, cipher <libtakiyasha.qmc.qmcdataciphers.Mask128 object at 0x7ff682178c10>>
    >>>

    - 获取使用的主密钥：
    >>> qmcv2file.master_key  # 此处的密钥是随机生成的
    b'pdjx6epLTXuayfUKEWjxxcEWcWqybsMTTauxG7cIo5qsXH8...'
    >>>

    - 访问内部的 Cipher 对象：
    >>> qmcv2file.cipher
    <libtakiyasha.qmc.qmcdataciphers.Mask128 object at 0x7ff682178c10>
    >>>

    - 打开一个外部 QMCv2 文件：
    >>> qmcv2file = QMCv2.open('/path/to/qmcv2file-hardenedrc4.mflac0', core_key=b'YourQMCv2CoreKey')
    >>> qmcv2file
    <libtakiyasha.qmc.QMCv2 at 0x7ff672679e90, cipher <libtakiyasha.qmc.qmcdataciphers.HardenedRC4 object at 0x7ff6811ff6a0>, source '/path/to/qmcv2file-hardenedrc4.mflac0'>
    >>>
    根据文件使用的加密方式，你可能需要输入多个密钥。更多使用方法，请使用 ``help(QMCv2.open)`` 查看帮助。

    - 读取和写入，注意写入操作产生的修改需要调用 ``save()`` 方法显式保存：
    >>> qmcv2file.read(16)
    b'fLaC\\x00\\x00\\x00"\\x12\\x00\\x12\\x00\\x00\\x07)\\x00'
    >>> qmcv2file.seek(0, 2)
    36137109
    >>> qmcv2file.write(b'\\x00Writing something')
    18
    >>>

    - 保存上述操作产生的更改
    >>> # 如果该 QMCv2 对象不是从文件打开的，还需要 filething 参数
    >>> qmcv2file.save(core_key=b'YourQMCv2CoreKey')
    >>>
    根据你想要的输出文件加密方式，你可能需要输入多个密钥。更多使用方法，请使用 ``help(QMCv2.save)`` 查看帮助。

    - 访问源文件末尾的附加数据（QTag 或 STag），如果没有，则为 ``None``：
    >>> qmcv2file.extra_info
    QMCv2QTag(song_id=0, unknown=2)
    >>> qmcv2file.extra_info.song_id
    1145141919810
    >>> qmcv2file.extra_info.unknown
    2
    >>>
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

        Args:
            cipher: 要使用的 cipher，必须是一个 libtakiyasha.qmc.qmcdataciphers.Mask128/HardenedRC4 对象
            initial_bytes: 内置缓冲区的初始数据
        """
        super().__init__(cipher, initial_bytes)

        self._extra_info: QMCv2QTag | QMCv2STag | None = None

        self._core_key_deprecated: bytes | None = None
        self._garble_key1_deprecated: bytes | None = None
        self._garble_key2_deprecated: bytes | None = None

    @property
    def extra_info(self) -> QMCv2QTag | QMCv2STag | None:
        """源文件末尾的附加信息（如果有），根据类型可分为 QTag 或 STag。"""
        return self._extra_info

    @extra_info.setter
    def extra_info(self, value: QMCv2QTag | QMCv2STag) -> None:
        """源文件末尾的附加信息（如果有），根据类型可分为 QTag 或 STag。"""
        if isinstance(value, (QMCv2QTag, QMCv2STag)):
            self._extra_info = value
        elif value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'extra_info'. "
                f"Use `del self.extra_info` instead"
            )
        else:
            raise TypeError(
                f"attribute 'extra_info' must be QMCv2QTag or QMCv2STag, not {repr(value)}"
            )

    @extra_info.deleter
    def extra_info(self) -> None:
        """源文件末尾的附加信息（如果有），根据类型可分为 QTag 或 STag。"""
        self._extra_info = None

    @property
    def master_key(self) -> bytes | None:
        if isinstance(self.cipher, Mask128):
            ret = self.cipher.getkey('original')
            if ret:
                return ret

        return super().master_key

    @property
    def core_key(self) -> bytes | None:
        """（已弃用，且将会在后续版本中删除。）

        核心密钥，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.core_key or {type(self).__name__}.simple_key'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage the core key by your self.'
            )
        )
        return self._core_key_deprecated

    @core_key.setter
    def core_key(self, value: BytesLike) -> None:
        """（已弃用，且将会在后续版本中删除。）

        核心密钥，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.core_key or {type(self).__name__}.simple_key'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage the core key by your self.'
            )
        )
        if value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'core_key'. "
                f"Use `del self.core_key` instead"
            )
        self._core_key_deprecated = tobytes(value)

    @core_key.deleter
    def core_key(self) -> None:
        """（已弃用，且将会在后续版本中删除。）

        核心密钥，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.core_key or {type(self).__name__}.simple_key'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage the core key by your self.'
            )
        )
        self._core_key_deprecated = None

    simple_key = core_key

    @property
    def garble_key1(self) -> bytes | None:
        """（已弃用，且将会在后续版本中删除。）

        混淆密钥 1，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.garble_key1 or {type(self).__name__}.mix_key1'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage garble keys by your self.'
            )
        )
        return self._garble_key1_deprecated

    @garble_key1.setter
    def garble_key1(self, value: BytesLike) -> None:
        """（已弃用，且将会在后续版本中删除。）

        混淆密钥 1，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.garble_key1 or {type(self).__name__}.mix_key1'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage garble keys by your self.'
            )
        )
        if value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'garble_key1'. "
                f"Use `del self.garble_key1` instead"
            )
        self._garble_key1_deprecated = tobytes(value)

    @garble_key1.deleter
    def garble_key1(self):
        """（已弃用，且将会在后续版本中删除。）

        混淆密钥 1，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.garble_key1 or {type(self).__name__}.mix_key1'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage garble keys by your self.'
            )
        )
        self._garble_key1_deprecated = None

    mix_key1 = garble_key1

    @property
    def garble_key2(self) -> bytes | None:
        """（已弃用，且将会在后续版本中删除。）

        混淆密钥 2，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.garble_key2 or {type(self).__name__}.mix_key2'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage garble keys by your self.'
            )
        )
        return self._garble_key2_deprecated

    @garble_key2.setter
    def garble_key2(self, value: BytesLike) -> None:
        """（已弃用，且将会在后续版本中删除。）

        混淆密钥 2，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.garble_key2 or {type(self).__name__}.mix_key2'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage garble keys by your self.'
            )
        )
        if value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'garble_key2'. "
                f"Use `del self.garble_key2` instead"
            )
        self._garble_key2_deprecated = tobytes(value)

    @garble_key2.deleter
    def garble_key2(self):
        """（已弃用，且将会在后续版本中删除。）

        混淆密钥 2，用于加/解密主密钥。

        ``QMCv2.from_file()`` 会在当前对象被创建时设置此属性；而 ``QMCv2.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.garble_key2 or {type(self).__name__}.mix_key2'
                f'is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage garble keys by your self.'
            )
        )
        self._garble_key2_deprecated = None

    mix_key2 = garble_key2

    @classmethod
    def from_file(cls,
                  qmcv2_filething: FilePath | IO[bytes], /,
                  simple_key: BytesLike = None,
                  mix_key1: BytesLike = None,
                  mix_key2: BytesLike = None, *,
                  master_key: BytesLike = None,
                  ):
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``QMCv2.open()`` 代替。）

        打开一个 QMCv2 文件或文件对象 ``qmcv2_filething``。

        第一个位置参数 ``qmcv2_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``qmcv2_filething``
        也可以是一个文件对象，但必须可读、可跳转（``qmcv2_filething.seekable() == True``）。

        本方法会寻找文件内嵌主密钥的位置和加密方式，进而判断所用加密算法的类型。

        如果提供了参数 ``master_key``，那么此参数将会被视为主密钥，
        用于判断加密算法类型和解密音频数据，同时会跳过其他步骤。
        其必须是类字节对象，且转换为 ``bytes`` 的长度必须是 128、256
        或 512 位。如果不符合长度要求，会触发 ``ValueError``。否则：

        - 如果未能找到文件内嵌的主密钥，那么参数 ``master_key`` 是必需的。
        - 如果文件内嵌的主密钥，其加密版本为 V1，那么参数 ``simple_key`` 是必需的。
        - 如果文件内嵌的主密钥，其加密版本为 V2，那么除了 ``simple_key``，参数``mix_key1``、``mix_key2`` 也是必需的。

        以上特定条件中的必需参数，如果缺失，则会触发 ``ValueError``。
        """
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {cls.__name__}.open() instead.'
            )
        )
        instance = cls.open(qmcv2_filething,
                            core_key=simple_key,
                            garble_key1=mix_key1,
                            garble_key2=mix_key2,
                            master_key=master_key
                            )
        instance._core_key_deprecated = tobytes(simple_key)
        instance._garble_key1_deprecated = tobytes(mix_key1)
        instance._garble_key2_deprecated = tobytes(mix_key2)

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

        ``filething_or_info`` 也可以接受 ``probe_qmc()`` 和 ``probe_qmcv2()`` 函数的返回值：
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

        此参数的设置会覆盖 ``probe_qmc()`` 或 ``probe_qmcv2()`` 的探测结果。

        Args:
            filething_or_info: 源文件的路径或文件对象，或者 probe_qmc() 和 probe_qmcv2() 的返回值
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
                    "or a tuple of probe_qmc(), probe_qmcv2() returns"
                )
            filething, fileinfo = filething_or_info
        else:
            filething, fileinfo = probe_qmcv2(filething_or_info)

        if fileinfo is None:
            raise CrypterCreatingError(
                f"{repr(filething)} is not a QMCv2 file"
            )
        elif not isinstance(fileinfo, QMCv2FileInfo):
            raise TypeError(
                f"second element of the tuple must be QMCv2FileInfo or None, not {type(fileinfo).__name__}"
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

    def to_file(self,
                qmcv2_filething: FilePath | IO[bytes] = None, /,
                tag_type: Literal['qtag', 'stag'] = None,
                simple_key: BytesLike = None,
                master_key_enc_ver: IntegerLike = 1,
                mix_key1: BytesLike = None,
                mix_key2: BytesLike = None
                ) -> None:
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``QMCv2.save()`` 代替。）

        将当前 QMCv2 对象的内容保存到文件 ``qmcv2_filething``。

        第一个位置参数 ``qmcv2_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``qmcv2_filething``
        也可以是一个文件对象，但必须可写。

        本方法会首先尝试写入 ``qmcv2_filething`` 指向的文件。
        如果未提供 ``qmcv2_filething``，则会尝试写入 ``self.name``
        指向的文件。如果两者都为空或未提供，则会触发 ``CrypterSavingError``。

        参数 ``tag_type`` 决定在文件末尾附加的内容，仅支持以下值：
            - ``None`` - 将主密钥加密后直接附加在文件末尾。
            - ``qtag`` - 将主密钥加密后封装在 QTag 信息中，附加在文件末尾。
            - ``stag`` - 将 STag 信息附加在文件末尾。
                - 注意：选择 STag 意味着文件内不会内嵌主密钥，你需要自己记下主密钥。
                - 访问属性 ``self.master_key`` 获取主密钥。

        如果 ``tag_type`` 为其他值，会触发 ``ValueError``。

        无论 ``tag_type`` 为何值（``stag`` 除外），都需要使用 ``simple_key`` 加密主密钥。
        如果参数 ``master_key_enc_ver=2``，还需要 ``mix_key1`` 和 ``mix_key2``。
        如果未提供这些参数，则会使用当前 QMCv2 对象的同名属性代替。
        如果两者都为 ``None`` 或未提供，则会触发 ``CrypterSavingError``。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )
        with_extra_info = False
        if isinstance(self.extra_info, (QMCv2QTag, QMCv2QTag)) and tag_type:
            with_extra_info = True
        if master_key_enc_ver == 1:
            mix_key1 = None
            mix_key2 = None
        elif master_key_enc_ver == 2:
            if mix_key1 is None:
                mix_key1 = self.garble_key1
            if mix_key2 is None:
                mix_key2 = self.garble_key2
            if mix_key1 is None and mix_key2 is None:
                raise TypeError(
                    "argument 'mix_key1' and 'mix_key2' is required to "
                    "decrypt the QMCv2 Key Encryption V2 protected master key"
                )
            elif mix_key1 is None:
                raise TypeError(
                    "argument 'mix_key1' is required to "
                    "decrypt the QMCv2 Key Encryption V2 protected master key"
                )
            elif mix_key2 is None:
                raise TypeError(
                    "argument 'mix_key2' is required to "
                    "decrypt the QMCv2 Key Encryption V2 protected master key"
                )
        else:
            raise ValueError("argument 'master_key_enc_ver' must be 1 or 2, "
                             f"not {master_key_enc_ver}"
                             )
        if simple_key is None:
            simple_key = self.core_key
        return self.save(core_key=simple_key,
                         filething=qmcv2_filething,
                         garble_key1=mix_key1,
                         garble_key2=mix_key2,
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
