# -*- coding: utf-8 -*-
from __future__ import annotations

import warnings
from base64 import b64decode, b64encode
from dataclasses import dataclass
from secrets import token_bytes
from typing import IO, Literal

from .qmcdataciphers import HardenedRC4, Mask128
from .qmckeyciphers import QMCv2KeyEncryptV1, QMCv2KeyEncryptV2
from ..common import CryptLayerWrappedIOSkel
from ..exceptions import CrypterCreatingError, CrypterSavingError
from ..keyutils import make_random_ascii_string
from ..typedefs import BytesLike, FilePath, IntegerLike
from ..typeutils import is_filepath, tobytes, toint_nofloat, verify_fileobj
from ..warns import CrypterCreatingWarning, CrypterSavingWarning

__all__ = [
    'QMCv2QTag',
    'QMCv2STag',
    'QMCv1',
    'QMCv2'
]


@dataclass
class QMCv2QTag:
    """解析、存储和重建 QMCv2 文件末尾的 QTag 数据。"""
    master_key_encrypted_b64encoded: bytes
    song_id: int
    unknown_value1: bytes

    @classmethod
    def from_bytes(cls, bytestring: BytesLike) -> QMCv2QTag:
        segments = tobytes(bytestring).split(b',')
        if len(segments) != 3:
            raise ValueError('invalid QMCv2 QTag data: the counts of splitted segments '
                             f'should be equal to 3, not {len(segments)}'
                             )

        master_key_encrypted_b64encoded = segments[0]
        song_id = int(segments[1])
        unknown_value1 = segments[2]

        return cls(master_key_encrypted_b64encoded, song_id, unknown_value1)

    def to_bytes(self, with_tail: bool = False) -> bytes:
        ret = b','.join([
            self.master_key_encrypted_b64encoded,
            str(self.song_id).encode('utf-8'),
            self.unknown_value1
        ]
        )
        if with_tail:
            return ret + len(ret).to_bytes(4, 'big') + b'QTag'
        else:
            return ret

    @classmethod
    def new(cls, master_key: BytesLike, simple_key: BytesLike, song_id: IntegerLike, unknown_value1: BytesLike) -> QMCv2QTag:
        master_key_encrypted = QMCv2KeyEncryptV1(simple_key).encrypt(master_key)
        master_key_encrypted_b64encoded = b64encode(master_key_encrypted)

        return cls(master_key_encrypted_b64encoded,
                   toint_nofloat(song_id),
                   tobytes(unknown_value1)
                   )


@dataclass
class QMCv2STag:
    """解析、存储和重建 QMCv2 文件末尾的 STag 数据。"""
    song_id: int
    unknown_value1: bytes
    song_mid: str

    @classmethod
    def from_bytes(cls, bytestring: BytesLike) -> QMCv2STag:
        segments = tobytes(bytestring).split(b',')
        if len(segments) != 3:
            raise ValueError('invalid QMCv2 STag data: the counts of splitted segments '
                             f'should be equal to 3, not {len(segments)}'
                             )

        song_id = int(segments[0])
        unknown_value1 = segments[1]
        song_mid = segments[2].decode('utf-8')

        return cls(song_id, unknown_value1, song_mid)

    def to_bytes(self, with_tail: bool = False) -> bytes:
        raw_song_id = str(self.song_id).encode('utf-8')
        raw_song_mid = self.song_mid.encode('utf-8')

        ret = b','.join([raw_song_id, self.unknown_value1, raw_song_mid])
        if with_tail:
            return ret + len(ret).to_bytes(4, 'big') + b'STag'
        else:
            return ret

    @classmethod
    def new(cls, song_id: IntegerLike, unknown_value1: BytesLike, song_mid: str) -> QMCv2STag:
        return cls(toint_nofloat(song_id), tobytes(unknown_value1), str(song_mid))


class QMCv1(CryptLayerWrappedIOSkel):
    """基于 BytesIO 的 QMCv1 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 QMCv1 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``QMCv1.new()`` 和 ``QMCv1.from_file()`` 新建或打开已有 QMCv1 文件，
    使用已有 QMCv1 对象的 ``self.to_file()`` 方法将其保存到文件。
    """

    @property
    def cipher(self) -> Mask128:
        return self._cipher

    @property
    def master_key(self):
        return self.cipher.mask128

    def __init__(self, cipher: Mask128, /, initial_bytes: BytesLike = b'') -> None:
        """基于 BytesIO 的 QMCv1 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 QMCv1 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``QMCv1.new()`` 和 ``QMCv1.from_file()`` 新建或打开已有 QMCv1 文件，
        使用 ``self.to_file()`` 将已有 QMCv1 对象保存到文件。
        """
        super().__init__(cipher, initial_bytes)
        if not isinstance(cipher, Mask128):
            raise TypeError(f"'{type(self).__name__}' "
                            f"only support cipher '{Mask128.__module__}.{Mask128.__name__}', "
                            f"not '{type(self._cipher).__name__}'"
                            )

    @classmethod
    def new(cls) -> QMCv1:
        """创建并返回一个全新的空 QMCv1 对象。"""
        master_key = token_bytes(128)

        return cls(Mask128(master_key))

    @classmethod
    def from_file(cls,
                  qmcv1_filething: FilePath | IO[bytes], /,
                  master_key: BytesLike
                  ) -> QMCv1:
        """打开一个 QMCv1 文件或文件对象 ``qmcv1_filething``。

        第一个位置参数 ``qmcv1_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``qmcv1_filething``
        也可以是一个文件对象，但必须可读。

        第二个位置参数 ``master_key`` 用于解密音频数据，长度仅限 44、128 或 256 位。
        如果不符合长度要求，会触发 ``ValueError``。
        """
        master_key = tobytes(master_key)
        if len(master_key) == 44:
            cipher = Mask128.from_qmcv1_mask44(master_key)
        elif len(master_key) == 128:
            cipher = Mask128(master_key)
        elif len(master_key) == 256:
            cipher = Mask128.from_qmcv1_mask256(master_key)
        else:
            raise ValueError("the length of second argument 'master_key' "
                             f"must be 44, 128 or 256, not {len(master_key)}"
                             )

        if is_filepath(qmcv1_filething):
            with open(qmcv1_filething, mode='rb') as qmcv1_fileobj:
                instance = cls(cipher, qmcv1_fileobj.read())
        else:
            qmcv1_fileobj = verify_fileobj(qmcv1_filething, 'binary',
                                           verify_readable=True
                                           )
            instance = cls(cipher, qmcv1_fileobj.read())

        instance._name = getattr(qmcv1_fileobj, 'name', None)

        return instance

    def to_file(self, qmcv1_filething: FilePath | IO[bytes] = None, /) -> None:
        """将当前 QMCv1 对象的内容保存到文件 ``qmcv1_filething``。

        第一个位置参数 ``qmcv1_filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``qmcv1_filething``
        也可以是一个文件对象，但必须可写。

        本方法会首先尝试写入 ``qmcv1_filething`` 指向的文件。
        如果未提供 ``qmcv1_filething``，则会尝试写入 ``self.name``
        指向的文件。如果两者都为空或未提供，则会触发 ``CrypterSavingError``。
        """
        if qmcv1_filething is None:
            if self.name is None:
                raise CrypterSavingError(
                    "cannot determine the target file: "
                    "argument 'qmcv1_filething' and attribute self.name are None or unspecified"
                )
            qmcv1_filething = self.name

        if is_filepath(qmcv1_filething):
            with open(qmcv1_filething, mode='wb') as qmcv1_fileobj:
                qmcv1_fileobj.write(self.getvalue(nocryptlayer=True))
        else:
            qmcv1_fileobj = verify_fileobj(qmcv1_filething, 'binary',
                                           verify_writable=True
                                           )
            qmcv1_fileobj.write(self.getvalue(nocryptlayer=True))


class QMCv2(CryptLayerWrappedIOSkel):
    """基于 BytesIO 的 QMCv2 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 QMCv2 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``QMCv2.new()`` 和 ``QMCv2.from_file()`` 新建或打开已有 QMCv2 文件，
    使用已有 QMCv2 对象的 ``self.to_file()`` 方法将其保存到文件。
    """

    @property
    def cipher(self) -> HardenedRC4 | Mask128:
        return self._cipher

    @property
    def master_key(self) -> bytes:
        if isinstance(self.cipher, HardenedRC4):
            return self.cipher.key512
        elif isinstance(self.cipher, Mask128):
            if self.cipher.original_master_key is None:
                return self.cipher.mask128
            return self.cipher.original_master_key

    @property
    def simple_key(self) -> bytes | None:
        return self._simple_key

    @simple_key.setter
    def simple_key(self, value: BytesLike) -> None:
        self._simple_key = tobytes(value)

    @simple_key.deleter
    def simple_key(self) -> None:
        self._simple_key = None

    @property
    def mix_key1(self) -> bytes | None:
        return self._mix_key1

    @mix_key1.setter
    def mix_key1(self, value: BytesLike) -> None:
        self._mix_key1 = tobytes(value)

    @mix_key1.deleter
    def mix_key1(self) -> None:
        self._mix_key1 = None

    @property
    def mix_key2(self) -> bytes | None:
        return self._mix_key2

    @mix_key2.setter
    def mix_key2(self, value: BytesLike) -> None:
        self._mix_key2 = tobytes(value)

    @mix_key2.deleter
    def mix_key2(self) -> None:
        self._mix_key2 = None

    @property
    def song_id(self) -> int:
        return self._song_id

    @song_id.setter
    def song_id(self, value: IntegerLike) -> None:
        self._song_id = toint_nofloat(value)

    @song_id.deleter
    def song_id(self) -> None:
        self._song_id = 0

    @property
    def song_mid(self) -> str:
        return self._song_mid

    @song_mid.setter
    def song_mid(self, value: str) -> None:
        self._song_mid = str(value)

    @song_mid.deleter
    def song_mid(self) -> None:
        self._song_mid = '0' * 14

    @property
    def unknown_value1(self) -> bytes:
        return self._unknown_value1

    @unknown_value1.setter
    def unknown_value1(self, value: BytesLike) -> None:
        self._unknown_value1 = tobytes(value)

    @unknown_value1.deleter
    def unknown_value1(self) -> None:
        self._unknown_value1 = b'2'

    @property
    def qtag(self) -> QMCv2QTag | None:
        if self.simple_key is not None and len(self.master_key) in (256, 512):
            return QMCv2QTag.new(
                master_key=self.master_key,
                simple_key=self.simple_key,
                song_id=self.song_id,
                unknown_value1=self.unknown_value1
            )

    @property
    def stag(self) -> QMCv2STag:
        return QMCv2STag(
            song_id=self.song_id,
            unknown_value1=self.unknown_value1,
            song_mid=self.song_mid
        )

    def __init__(self,
                 cipher: HardenedRC4 | Mask128, /,
                 initial_bytes: BytesLike = b'',
                 simple_key: BytesLike = None,
                 mix_key1: BytesLike = None,
                 mix_key2: BytesLike = None, *,
                 song_id: IntegerLike = 0,
                 song_mid: str = '0' * 14,
                 unknown_value1: BytesLike = b'2'
                 ) -> None:
        """基于 BytesIO 的 QMCv2 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 QMCv2 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``QMCv2.new()`` 和 ``QMCv2.from_file()`` 新建或打开已有 QMCv2 文件，
        使用已有 QMCv2 对象的 ``self.to_file()`` 方法将其保存到文件。
        """
        super().__init__(cipher, initial_bytes)
        if not isinstance(cipher, (HardenedRC4, Mask128)):
            raise TypeError(f'unsupported Cipher: '
                            f'supports '
                            f'{Mask128.__module__}.{Mask128.__name__} and '
                            f'{HardenedRC4.__module__}.{HardenedRC4.__name__}, '
                            f'not {type(cipher).__name__}'
                            )

        if simple_key is None:
            self._simple_key = None
        else:
            self._simple_key = tobytes(simple_key)
        if mix_key1 is None:
            self._mix_key1 = None
        else:
            self._mix_key1 = tobytes(mix_key1)
        if mix_key2 is None:
            self._mix_key2 = None
        else:
            self._mix_key2 = tobytes(mix_key2)
        self._song_id = toint_nofloat(song_id)
        self._song_mid = str(song_mid)
        self._unknown_value1 = tobytes(unknown_value1)

    @classmethod
    def new(cls,
            cipher_type: Literal['mask', 'rc4'], /,
            simple_key: BytesLike = None,
            mix_key1: BytesLike = None,
            mix_key2: BytesLike = None, *,
            song_id: IntegerLike = 0,
            song_mid: str = '0' * 14,
            unknown_value1: BytesLike = b'2'
            ) -> QMCv2:
        """创建并返回一个全新的空 QMCv2 对象。

        第一个位置参数 ``cipher_type`` 决定此 QMCv2 对象的透明加密层使用哪种加密算法，
        仅支持 ``'mask'`` 和 ``'rc4'``。

        位置参数 ``simple_key``、``mix_key1``、``mix_key2``
        都是可选参数，但已经在这里填写的参数，在将此 QMCv2 对象保存到文件时不必再填写。

        关键字参数 ``song_id``、``song_mid``、``unknown_value1`` 也是可选参数。
        这些参数是无关紧要的。
        """
        if cipher_type == 'mask':
            cipher = Mask128.from_qmcv2_key256(make_random_ascii_string(256))
        elif cipher_type == 'rc4':
            cipher = HardenedRC4(make_random_ascii_string(512))
        elif isinstance(cipher_type, str):
            raise ValueError(f"first argument 'cipher_type' must be 'mask' or 'rc4', not {cipher_type}")
        else:
            raise TypeError(f"first argument 'cipher_type' must be str, "
                            f"not {type(cipher_type).__name__}"
                            )

        return cls(cipher,
                   simple_key=simple_key,
                   mix_key1=mix_key1,
                   mix_key2=mix_key2,
                   song_id=song_id,
                   song_mid=song_mid,
                   unknown_value1=unknown_value1
                   )

    @classmethod
    def from_file(cls,
                  qmcv2_filething: FilePath | IO[bytes], /,
                  simple_key: BytesLike = None,
                  mix_key1: BytesLike = None,
                  mix_key2: BytesLike = None, *,
                  master_key: BytesLike = None,
                  ) -> QMCv2:
        """打开一个 QMCv2 文件或文件对象 ``qmcv2_filething``。

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

        def operation(fileobj: IO[bytes]) -> QMCv2:
            fileobj_endpos = fileobj.seek(0, 2)
            fileobj.seek(-4, 2)
            tail_data = fileobj.read(4)

            song_id = 0
            song_mid = '0' * 14
            unknown_value1 = b'2'

            if tail_data == b'STag':
                if master_key is None:
                    raise ValueError("'master_key' is required for QMCv2 file with STag "
                                     "audio data encryption/decryption"
                                     )
                fileobj.seek(-8, 2)
                stag_len = int.from_bytes(fileobj.read(4), 'big')
                if stag_len + 8 > fileobj_endpos:
                    raise CrypterCreatingError(
                        f'{repr(qmcv2_filething)} is not a valid QMCv2 file: '
                        f'QMCv2 STag data length ({stag_len + 8}) '
                        f'is greater than file length ({fileobj_endpos})'
                    )
                audio_encrypted_len = fileobj.seek(-(stag_len + 8), 2)
                stag = QMCv2STag.from_bytes(fileobj.read(stag_len))
                song_id = stag.song_id
                song_mid = stag.song_mid
                unknown_value1 = stag.unknown_value1
                target_master_key = master_key
                fileobj.seek(0, 0)
                initial_bytes = fileobj.read(audio_encrypted_len)
            else:
                if simple_key is None:
                    raise ValueError("'simple_key' is required for QMCv2 file master key decryption")
                if tail_data == b'QTag':
                    fileobj.seek(-8, 2)
                    qtag_len = int.from_bytes(fileobj.read(4), 'big')
                    if qtag_len + 8 > fileobj_endpos:
                        raise CrypterCreatingError(
                            f'{repr(qmcv2_filething)} is not a valid QMCv2 file: '
                            f'QMCv2 QTag data length ({qtag_len + 8}) '
                            f'is greater than file length ({fileobj_endpos})'
                        )
                    audio_encrypted_len = fileobj.seek(-(qtag_len + 8), 2)
                    qtag = QMCv2QTag.from_bytes(fileobj.read(qtag_len))
                    master_key_encrypted_b64encoded = qtag.master_key_encrypted_b64encoded
                    song_id = qtag.song_id
                    unknown_value1 = qtag.unknown_value1
                    target_master_key = master_key
                    if target_master_key is None:
                        target_master_key = QMCv2KeyEncryptV1(simple_key).decrypt(
                            b64decode(master_key_encrypted_b64encoded)
                        )
                    fileobj.seek(0, 0)
                    initial_bytes = fileobj.read(audio_encrypted_len)
                else:
                    master_key_encrypted_b64encoded_len = int.from_bytes(tail_data, 'little')
                    if master_key_encrypted_b64encoded_len + 4 > fileobj_endpos:
                        raise CrypterCreatingError(
                            f'{repr(qmcv2_filething)} is not a valid QMCv2 file: '
                            f'QMCv2 QTag data length ({master_key_encrypted_b64encoded_len + 4}) '
                            f'is greater than file length ({fileobj_endpos})'
                        )
                    audio_encrypted_len = fileobj.seek(-(master_key_encrypted_b64encoded_len + 4), 2)
                    master_key_encrypted_b64encoded = fileobj.read(master_key_encrypted_b64encoded_len)
                    target_master_key = master_key
                    if target_master_key is None:
                        master_key_encrypted = b64decode(master_key_encrypted_b64encoded, validate=False)
                        if master_key_encrypted.startswith(b'QQMusic EncV2,Key:'):
                            missing_mix_key_msg = '{} is required for QMCv2 file ' \
                                                  'with master key encryption V2 decryption'
                            missed_mix_keys = None
                            if mix_key1 is None and mix_key2 is None:
                                missed_mix_keys = "'mix_key1' and 'mix_key2'"
                            elif mix_key1 is None:
                                missed_mix_keys = "'mix_key1'"
                            elif mix_key2 is None:
                                missed_mix_keys = "'mix_key2'"
                            if missed_mix_keys:
                                raise ValueError(missing_mix_key_msg.format(missed_mix_keys))
                            target_master_key = QMCv2KeyEncryptV2(
                                simple_key,
                                mix_key1,
                                mix_key2
                            ).decrypt(master_key_encrypted[18:])
                        else:
                            target_master_key = QMCv2KeyEncryptV1(simple_key).decrypt(master_key_encrypted)

                    fileobj.seek(0, 0)
                    initial_bytes = fileobj.read(audio_encrypted_len)

            if len(target_master_key) == 128:
                cipher = Mask128(target_master_key)
                warnings.warn(CrypterCreatingWarning(
                    'maskey length is 128, most likely obtained by other means, '
                    'such as known plaintext attack. '
                    'Unable to recover and save the original master key from this key.'
                )
                )
            elif len(target_master_key) == 256:
                cipher = Mask128.from_qmcv2_key256(target_master_key)
            elif len(target_master_key) == 512:
                cipher = HardenedRC4(target_master_key)
            else:
                raise CrypterCreatingError(
                    'invalid master key length: should be 128 (unrecommend), 256 or 512, '
                    f'not {len(target_master_key)}'
                )

            return cls(cipher,
                       initial_bytes,
                       simple_key=simple_key,
                       mix_key1=mix_key1,
                       mix_key2=mix_key2,
                       song_id=song_id,
                       song_mid=song_mid,
                       unknown_value1=unknown_value1
                       )

        if simple_key is not None:
            simple_key = tobytes(simple_key)
        if mix_key1 is not None:
            mix_key1 = tobytes(mix_key1)
        if mix_key2 is not None:
            mix_key2 = tobytes(mix_key2)
        if master_key is not None:
            master_key = tobytes(master_key)

        if is_filepath(qmcv2_filething):
            with open(qmcv2_filething, mode='rb') as qmcv2_fileobj:
                instance = operation(qmcv2_fileobj)
        else:
            qmcv2_fileobj = verify_fileobj(qmcv2_filething, 'binary',
                                           verify_readable=True,
                                           verify_seekable=True
                                           )
            instance = operation(qmcv2_fileobj)

        instance._name = getattr(qmcv2_fileobj, 'name', None)

        return instance

    def to_file(self,
                qmcv2_filething: FilePath | IO[bytes] = None, /,
                tag_type: Literal['qtag', 'stag'] = None,
                simple_key: BytesLike = None,
                master_key_enc_ver: IntegerLike = 1,
                mix_key1: BytesLike = None,
                mix_key2: BytesLike = None
                ) -> None:
        """将当前 QMCv2 对象的内容保存到文件 ``qmcv2_filething``。

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

        def operation(fileobj: IO[bytes]) -> None:
            if tag_type == 'stag':
                warnings.warn(CrypterSavingWarning(
                    'the STag embedded in the file does not contain the master key. '
                    'You need to remember the master key yourself. '
                    "Access the attribute 'self.master_key' to get the master key."
                )
                )
                fileobj.write(self.getvalue(nocryptlayer=True))
                fileobj.write(self.stag.to_bytes(with_tail=True))
            elif tag_type == 'qtag':
                if self.qtag is None:
                    raise CrypterCreatingError("unable to save the file: cannot generate QTag")
                fileobj.write(self.getvalue(nocryptlayer=True))
                fileobj.write(self.qtag.to_bytes(with_tail=True))
            elif tag_type is None:
                target_simple_key = simple_key
                if target_simple_key is None:
                    if self.simple_key is None:
                        raise CrypterSavingError(
                            "argument 'simple_key' and attribute self.simple_key is not available, "
                            'but it is required for the master key encryption'
                        )
                    target_simple_key = self.simple_key
                if len(self.master_key) == 128:
                    raise CrypterSavingError(
                        'master key is not available: '
                        'maskey length is 128, most likely obtained by other means, '
                        'such as known plaintext attack. '
                        'Unable to recover the original master key from this key.'
                    )
                master_key = self.master_key
                if master_key_enc_ver == 1:
                    master_key_encrypted = QMCv2KeyEncryptV1(target_simple_key).encrypt(master_key)
                elif master_key_enc_ver == 2:
                    missing_mix_key_msg = '{names} not available, but {appell} required for ' \
                                          'the master key encryption V2 encryption'
                    missed_mix_keys_appell = {}
                    target_mix_key1 = mix_key1
                    if target_mix_key1 is None:
                        target_mix_key1 = self.mix_key1
                    target_mix_key2 = mix_key2
                    if target_mix_key2 is None:
                        target_mix_key2 = self.mix_key2
                    if target_mix_key1 is None and target_mix_key2 is None:
                        missed_mix_keys_appell['names'] = \
                            "argument 'mix_key1' and attribute self.mix_key1, " \
                            "argument 'mix_key2' and attribute self.mix_key2 are"
                        missed_mix_keys_appell['appell'] = 'they are'
                    elif target_mix_key1 is None or target_mix_key2 is None:
                        missed_mix_keys_appell['appell'] = 'it is'
                        if target_mix_key1 is None:
                            missed_mix_keys_appell['names'] = \
                                "argument 'mix_key1' and attribute self.mix_key1 is"
                        elif target_mix_key2 is None:
                            missed_mix_keys_appell['names'] = \
                                "argument 'mix_key2' and attribute self.mix_key2 is"
                    print(missed_mix_keys_appell)
                    if missed_mix_keys_appell:
                        raise CrypterSavingError(
                            missing_mix_key_msg.format_map(missed_mix_keys_appell)
                        )
                    master_key_encrypted = b'QQMusic EncV2,Key:' + QMCv2KeyEncryptV2(
                        target_simple_key, target_mix_key1, target_mix_key2
                    ).encrypt(master_key)
                else:
                    raise ValueError("argument 'master_key_enc_ver' must be 1 or 2, "
                                     f"not {master_key_enc_ver}"
                                     )
                master_key_encrypted_b64encoded = b64encode(master_key_encrypted)
                master_key_encrypted_b64encoded_len = len(master_key_encrypted_b64encoded)
                fileobj.write(self.getvalue(nocryptlayer=True))
                fileobj.write(master_key_encrypted_b64encoded)
                fileobj.write(master_key_encrypted_b64encoded_len.to_bytes(4, 'little'))
            elif isinstance(tag_type, str):
                raise ValueError("argument 'tag_type' must be 'qtag', 'stag' or None, "
                                 f"not {tag_type}"
                                 )
            else:
                raise TypeError(f"argument 'tag_type' must be str or None, "
                                f"not {type(tag_type).__name__}"
                                )

        master_key_enc_ver = toint_nofloat(master_key_enc_ver)
        if simple_key is not None:
            simple_key = tobytes(simple_key)
        if mix_key1 is not None:
            mix_key1 = tobytes(mix_key1)
        if mix_key2 is not None:
            mix_key2 = tobytes(mix_key2)

        if is_filepath(qmcv2_filething):
            with open(qmcv2_filething, mode='wb') as qmcv2_fileobj:
                operation(qmcv2_fileobj)
        else:
            qmcv2_fileobj = verify_fileobj(qmcv2_filething, 'binary',
                                           verify_writable=True
                                           )
            operation(qmcv2_fileobj)
