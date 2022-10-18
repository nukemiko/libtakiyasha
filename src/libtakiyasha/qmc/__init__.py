# -*- coding: utf-8 -*-
from __future__ import annotations

from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from dataclasses import dataclass
from typing import IO, Literal, NamedTuple

from .dataciphers import *
from .keyciphers import *
from ..common import *
from ..exceptions import *
from ..typedefs import *
from ..typeutils import is_filepath, tobytes, toint_nofloat, verify_fileobj
from ..utils.keyutils import *


@dataclass
class QMCv2QTag:
    master_key_encrypted_b64encoded: bytes
    song_id: int
    unknown_value1: bytes

    @classmethod
    def from_bytes(cls, bytestring: BytesLike) -> QMCv2QTag:
        segments = tobytes(bytestring).split(b',')
        if len(segments) != 3:
            raise ValueError('invalid QMCv2 QTag data: the counts of splitted segments '
                             f'should be equal to 3, got {len(segments)}'
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
    song_id: int
    unknown_value1: bytes
    song_mid: str

    @classmethod
    def from_bytes(cls, bytestring: BytesLike) -> QMCv2STag:
        segments = tobytes(bytestring).split(b',')
        if len(segments) != 3:
            raise ValueError('invalid QMCv2 STag data: the counts of splitted segments '
                             f'should be equal to 3, got {len(segments)}'
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


class QMCv1(BytesIOWithTransparentCryptLayer):
    """QMCv1 格式文件的读取和创建支持。"""

    @property
    def cipher(self) -> Mask128:
        return self._cipher

    @classmethod
    def new(cls) -> QMCv1:
        """返回一个全新的空 QMCv1 对象。"""
        master_key = make_salt(128)

        return cls(Mask128(master_key))

    @staticmethod
    def _make_cipher_by_mask_len(mask: bytes) -> Mask128:
        mask_len = len(mask)
        if mask_len == 44:
            return Mask128.from_qmcv1_mask44(mask)
        elif mask_len == 128:
            return Mask128(mask)
        elif mask_len == 256:
            return Mask128.from_qmcv1_mask256(mask)
        else:
            raise ValueError(f'invalid mask length: should be 44, 128 or 256, got {mask_len}')

    @classmethod
    def from_file(cls,
                  filething: FilePath | IO[bytes], /,
                  mask: BytesLike,
                  ) -> QMCv1:
        """打开一个 QMCv1 文件或文件对象 ``filething``。

        第一个位置参数 ``filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``filething``
        也可以是一个文件对象，但必须可读。

        第二个位置参数 ``mask`` 用于解密音频数据，长度仅限 44、128 或 256 位。
        如果不符合长度要求，会触发 ``ValueError``。
        """
        mask = tobytes(mask)
        cipher = cls._make_cipher_by_mask_len(mask)

        if is_filepath(filething):
            with open(filething, mode='rb') as fileobj:
                initial_data = fileobj.read()
                filename: str = fileobj.name
        else:
            fileobj = verify_fileobj(filething,
                                     'binary',
                                     verify_readable=True
                                     )
            initial_data = fileobj.read()
            filename: str | None = getattr(fileobj, 'name', None)

        instance = cls(cipher, initial_data)
        instance._name = filename

        return instance

    def to_file(self, filething: FilePath | IO[bytes] = None, /) -> None:
        """将当前 QMCv1 对象的内容保存到文件 ``filething``。

        第一个位置参数 ``filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``filething``
        也可以是一个文件对象，但必须可读。

        如果 ``filething`` 留空，将会使用 ``self.name``
        作为目标文件的路径。如果也无法从 ``self.name``
        获取到目标文件路径，则会触发 ``CrypterSavingError``。
        """
        if filething is None:
            if self.name is None:
                raise CrypterSavingError("cannot get path of target file: "
                                         "attribute 'self.name' and argument 'filething' "
                                         "are missing"
                                         )
            else:
                filething = self.name

        if is_filepath(filething):
            with open(filething, mode='wb') as fileobj:
                fileobj.write(self.getvalue(nocryptlayer=True))
        else:
            fileobj = verify_fileobj(filething,
                                     'binary',
                                     verify_writable=True
                                     )
            fileobj.write(self.getvalue(nocryptlayer=True))

    def __init__(self, cipher: Mask128, /, initial_data: BytesLike = b'') -> None:
        super().__init__(cipher, initial_data)
        if not isinstance(cipher, Mask128):
            raise TypeError(f"unsupported Cipher: supports {Mask128.__name__}, "
                            f"got {type(cipher).__name__}"
                            )
        self._name = None

    @property
    def master_key(self) -> bytes:
        return self.cipher.mask128


class QMCv2(BytesIOWithTransparentCryptLayer):
    """QMCv2 格式文件的读写和创建支持。"""

    @property
    def cipher(self) -> Mask128 | HardenedRC4:
        return self._cipher

    @classmethod
    def new(cls, subtype: Literal['mask', 'rc4'], /) -> QMCv2:
        """返回一个全新的空 QMCv2 对象。

        第一个位置参数 ``subtype`` 用于决定使用哪一个音频加密算法，仅支持
        ``mask`` 和 ``rc4``；使用其他值会触发 ``ValueError`` 或 ``TypeError``。
        """
        if str(subtype) == 'mask':
            master_key = make_random_ascii_string(256)
            cipher_maker = Mask128.from_qmcv2_key256
        elif str(subtype) == 'rc4':
            master_key = make_random_ascii_string(512)
            cipher_maker = HardenedRC4
        elif isinstance(subtype, str):
            raise ValueError("positional argument 'subtype' must be 'mask' or 'rc4', "
                             f"not '{subtype}'"
                             )
        else:
            raise TypeError(f"positional argument 'subtype' must be str, not {type(subtype).__name__}")

        return cls(cipher_maker(master_key))

    @classmethod
    def from_file(cls,
                  filething: FilePath | IO[bytes], /,
                  simple_key: BytesLike = None,
                  mix_key1: BytesLike = None,
                  mix_key2: BytesLike = None, *,
                  master_key: BytesLike = None,
                  ) -> QMCv2:
        """打开一个 QMCv2 文件或文件对象 ``filething``。

        第一个位置参数 ``filething`` 可以是文件路径（``str``、``bytes``
        或任何拥有方法 ``__fspath__()`` 的对象）。``filething``
        也可以是一个文件对象，但必须可读。

        本方法会查找文件中内嵌的已加密主密钥，并判断主密钥的加密方式。

        第二个参数 ``simple_key`` 用于解密在文件中找到的主密钥。
        如果主密钥加密方式为 V1，此参数是必选的；
        如果主密钥加密方式为 V2，则第三、第四个位置参数
        ``mix_key1`` 和 ``mix_key2`` 也是必选的。

        关键字参数 ``master_key`` 是可选的。一旦提供，则将其视为用户提供的主密钥，
        其他参数（``simple_key``、``mix_key1`` 和 ``mix_key2``）都会被忽略。
        例外：在未能找到内嵌的已加密主密钥时，此参数是必选的。
        """
        if master_key is not None:
            master_key = tobytes(master_key)
        if simple_key is not None:
            simple_key = tobytes(simple_key)
        if mix_key1 is not None:
            mix_key1 = tobytes(mix_key1)
        if mix_key2 is not None:
            mix_key2 = tobytes(mix_key2)

        if is_filepath(filething):
            with open(filething, mode='rb') as fileobj:
                instance = _extract_qmcv2_file(fileobj, simple_key, mix_key1, mix_key2, master_key)
        else:
            fileobj = verify_fileobj(filething,
                                     'binary',
                                     verify_readable=True,
                                     verify_seekable=True
                                     )
            instance = _extract_qmcv2_file(fileobj, simple_key, mix_key1, mix_key2, master_key)

        instance._name = getattr(fileobj, 'name', None)

        return instance

    def to_file(self,
                filething: FilePath | IO[bytes] = None, /,
                tag_type: Literal['qtag', 'stag'] = None,
                simple_key: BytesLike = None,
                master_key_enc_ver: IntegerLike = 1,
                mix_key1: BytesLike = None,
                mix_key2: BytesLike = None
                ) -> None:
        """将当前 QMCv2 对象保存到文件 ``filething``。
        此过程会向 ``filething`` 写入 QMCv2 文件结构。

        第一个位置参数 ``filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``filething`` 也可以是文件对象，该对象必须可写和可跳转
        （``filething.seekable() == True``）。

        如果提供了 ``filething``，本方法将会把数据写入 ``filething``
        指向的文件。否则，本方法以写入模式打开一个指向 ``self.name``
        的文件对象，将数据写入此文件对象。如果两者都为空或未提供，则会触发
        ``ValueError``。

        第二个参数 ``tag_type`` 决定文件末尾附加的内容，支持以下值：

        - ``None`` - 只附加加密后的主密钥；``master_key_enc_ver`` 可以为 1 或 2
        - ``qtag`` - 附加 QTag；``master_key_enc_ver`` 只能为 1，否则会触发 ``CrypterSavingError``
        - ``stag`` - 附加 STag；因为 STag 不含密钥，除了 ``filething`` 之外，所有参数都会被忽略

        第三个参数 ``simple_key`` 是可选的。
        如果提供此参数，本方法会使用它来加密主密钥；否则，使用
        ``self.simple_key`` 代替。如果两者都为 ``None`` 或未提供，触发 ``ValueError``。

        第四个参数 ``master_key_enc_ver`` 是可选的，决定主密钥加密的方式；
        仅支持 1 和 2 两个值，默认为 1。

        第五、第六个参数 ``mix_key1`` 和 ``mix_key2``，在第三个参数
        ``master_key_enc_ver=2`` 时，如果提供这些参数，本方法会在使用 ``simple_key``
        加密主密钥后，使用它们再次加密；任何一个未提供，则使用对象自身存储的同名属性
        ``self.mix_key1`` 或 ``self.mix_key2`` 代替。
        如果任何一个相关参数和属性都为 ``None`` 或未提供，触发 ``ValueError``。
        """
        if tag_type != 'stag':
            if simple_key is None:
                if self.simple_key is None:
                    raise ValueError("cannot get simple key for master key encryption: "
                                     "argument 'simple_key' and attribute 'self.simple_key' "
                                     "are missing"
                                     )
                simple_key = self.simple_key
            else:
                simple_key = tobytes(simple_key)

        master_key_enc_ver = toint_nofloat(master_key_enc_ver)
        if tag_type == 'qtag':
            if master_key_enc_ver != 1:
                raise CrypterSavingError('QTag is only compatible with master key encryption V1, '
                                         f'got V{master_key_enc_ver}'
                                         )
            payload = QMCv2QTag.new(
                master_key=self.master_key,
                simple_key=simple_key,
                song_id=self.song_id,
                unknown_value1=self.qmcv2tag_unknown_value1
            ).to_bytes(with_tail=True)
        elif tag_type == 'stag':
            payload = self.stag.to_bytes(with_tail=True)
        elif tag_type is None:
            if master_key_enc_ver == 1:
                master_key_encrypted_b64encoded = b64encode(
                    QMCv2KeyEncryptV1(simple_key).encrypt(self.master_key)
                )
            elif master_key_enc_ver == 2:
                missing_mix_keys = []
                if mix_key1 is None:
                    if self.mix_key1 is None:
                        missing_mix_keys.append('mix_key1')
                    mix_key1 = self.mix_key1
                else:
                    mix_key1 = tobytes(mix_key1)
                if mix_key2 is None:
                    if self.mix_key2 is None:
                        missing_mix_keys.append('mix_key2')
                    mix_key2 = self.mix_key2
                else:
                    mix_key2 = tobytes(mix_key2)
                if missing_mix_keys:
                    missing_mix_keys_msg = ', '.join([f"'{_}'" for _ in missing_mix_keys])
                    raise ValueError("unable to continue the master key encryption: "
                                     f"argument {missing_mix_keys_msg} and attribute {missing_mix_keys_msg} "
                                     f"are missing"
                                     )
                master_key_encrypted_b64encoded = b64encode(
                    b'QQMusic EncV2,Key:' + QMCv2KeyEncryptV2(simple_key,
                                                              mix_key1,
                                                              mix_key2
                                                              ).encrypt(self.master_key)
                )
            else:
                raise ValueError('unsupported QMCv2 master key encryption version: '
                                 f'supports V1 and V2, got V{master_key_enc_ver}'
                                 )
            payload = master_key_encrypted_b64encoded + len(
                master_key_encrypted_b64encoded
            ).to_bytes(4, 'little')
        elif isinstance(tag_type, str):
            raise ValueError(f"argument 'tag_type' must be 'qtag', 'stag' or None, not {tag_type}")
        else:
            raise TypeError(f"argument 'tag_type' must be str or None, not {type(tag_type).__name__}")

        if is_filepath(filething):
            with open(filething, mode='wb') as fileobj:
                fileobj.write(self.getvalue(nocryptlayer=True))
                fileobj.write(payload)
        else:
            fileobj = verify_fileobj(filething,
                                     'binary',
                                     verify_writable=True
                                     )
            fileobj.write(self.getvalue(nocryptlayer=True))
            fileobj.write(payload)

    def __init__(self,
                 cipher: Mask128, /,
                 initial_data: BytesLike = b'',
                 simple_key: BytesLike = None, *,
                 mix_key1: BytesLike = None,
                 mix_key2: BytesLike = None,
                 qmcv2tag: QMCv2QTag | QMCv2STag = None
                 ) -> None:
        super().__init__(cipher, initial_data)
        if not isinstance(cipher, (Mask128, HardenedRC4)):
            raise TypeError(f'unsupported Cipher: '
                            f'supports {Mask128.__name__} and {HardenedRC4.__name__}, '
                            f'got {type(cipher).__name__}'
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
        if isinstance(qmcv2tag, QMCv2QTag):
            self._song_id = qmcv2tag.song_id
            self._unknown_value1 = qmcv2tag.unknown_value1
            self._song_mid = '0' * 14
        elif isinstance(qmcv2tag, QMCv2STag):
            self._song_id = qmcv2tag.song_id
            self._song_mid = qmcv2tag.song_mid
            self._unknown_value1 = qmcv2tag.unknown_value1
        elif qmcv2tag is None:
            self._song_id, self._song_mid, self._unknown_value1 = 0, '0' * 14, b'2'
        else:
            raise TypeError("argument 'qmcv2tag' must be QMCv2QTag, QMCv2STag or None, "
                            f"not {type(qmcv2tag).__name__}"
                            )
        self._name = None

    @property
    def master_key(self) -> bytes:
        if isinstance(self.cipher, Mask128):
            return self.cipher.original_mask_or_key
        elif isinstance(self.cipher, HardenedRC4):
            return self.cipher.key512
        else:
            raise TypeError(f"unsupported Cipher: "
                            f"supports {Mask128.__name__} and {HardenedRC4.__name__}, "
                            f"got {type(self.cipher).__name__}"
                            )

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
    def qmcv2tag_unknown_value1(self) -> bytes:
        return self._unknown_value1

    @qmcv2tag_unknown_value1.setter
    def qmcv2tag_unknown_value1(self, value: BytesLike) -> None:
        self._unknown_value1 = tobytes(value)

    @qmcv2tag_unknown_value1.deleter
    def qmcv2tag_unknown_value1(self) -> None:
        self._unknown_value1 = b''

    @property
    def qtag(self) -> QMCv2QTag:
        if self.simple_key is None:
            raise AttributeError("attribute 'simple_key' is not set")
        else:
            simple_key = self.simple_key
        master_key = self.master_key
        song_id = self.song_id
        unknown_value1 = self.qmcv2tag_unknown_value1

        return QMCv2QTag.new(master_key, simple_key, song_id, unknown_value1)

    @property
    def stag(self) -> QMCv2STag:
        song_id = self.song_id
        unknown_value1 = self.qmcv2tag_unknown_value1
        song_mid = self.song_mid
        return QMCv2STag.new(song_id, unknown_value1, song_mid)


class QMCv2FileProbeResult(NamedTuple):
    audio_encrypted_len: int
    master_key_encrypted: bytes | None
    master_key_encrypt_ver: int | None
    qmcv2tag: QMCv2QTag | QMCv2STag | None


def _probe_qmcv2_file(fileobj: IO[bytes]) -> tuple[int, QMCv2FileProbeResult]:
    fileobj_endpos = fileobj.seek(0, 2)
    fileobj.seek(-4, 2)
    tail_4bytes = fileobj.read(4)
    if tail_4bytes == b'QTag':
        fileobj.seek(-8, 2)
        tag_bytestring_len = int.from_bytes(fileobj.read(4), 'big')
        if tag_bytestring_len > fileobj_endpos:
            raise CrypterCreatingError(f'{repr(fileobj)} is not a valid QMCv2 file: '
                                       f'QTag length ({tag_bytestring_len}) '
                                       f'is greater than file length ({fileobj_endpos})'
                                       )
        audio_encrypted_len = fileobj.seek(-(tag_bytestring_len + 8), 2)
        qmcv2tag = QMCv2QTag.from_bytes(fileobj.read(tag_bytestring_len))
        master_key_encrypted = b64decode(qmcv2tag.master_key_encrypted_b64encoded, validate=True)
        master_key_encrypt_ver = 1
    elif tail_4bytes == b'STag':
        fileobj.seek(-8, 2)
        tag_bytestring_len = int.from_bytes(fileobj.read(4), 'big')
        if tag_bytestring_len > fileobj_endpos:
            raise CrypterCreatingError(f'{repr(fileobj)} is not a valid QMCv2 file: '
                                       f'STag length ({tag_bytestring_len}) '
                                       f'is greater than file length ({fileobj_endpos})'
                                       )
        audio_encrypted_len = fileobj.seek(-(tag_bytestring_len + 8), 2)
        qmcv2tag = QMCv2STag.from_bytes(fileobj.read(tag_bytestring_len))
        master_key_encrypted = None
        master_key_encrypt_ver = None
    else:
        master_key_encrypted_b64encoded_len = int.from_bytes(tail_4bytes, 'little')
        if master_key_encrypted_b64encoded_len > fileobj_endpos:
            raise CrypterCreatingError(f'{repr(fileobj)} is not a valid QMCv2 file: '
                                       f'master key length ({master_key_encrypted_b64encoded_len}) '
                                       f'is greater than file length ({fileobj_endpos})'
                                       )
        audio_encrypted_len = fileobj.seek(-(master_key_encrypted_b64encoded_len + 4), 2)
        master_key_encrypted_b64encoded = fileobj.read(master_key_encrypted_b64encoded_len)
        try:
            master_key_encrypted = b64decode(master_key_encrypted_b64encoded, validate=True)
        except BinasciiError:
            suspect_master_key_encrypted = b64decode(master_key_encrypted_b64encoded, validate=False)
            if suspect_master_key_encrypted.startswith(b'QQMusic EncV2,Key:'):
                master_key_encrypted = suspect_master_key_encrypted[18:]
                master_key_encrypt_ver = 2
            else:
                raise CrypterCreatingError(f'{repr(fileobj)} is not a valid QMCv2 file: '
                                           f'QMCv2 without STag should not missing master key'
                                           )
        else:
            master_key_encrypt_ver = 1
        qmcv2tag = None

    return fileobj.tell(), QMCv2FileProbeResult(audio_encrypted_len,
                                                master_key_encrypted,
                                                master_key_encrypt_ver,
                                                qmcv2tag
                                                )


def _make_cipher(probe_result: QMCv2FileProbeResult | bytes,
                 simple_key: bytes = None,
                 mix_key1: bytes = None,
                 mix_key2: bytes = None,
                 master_key: bytes = None
                 ) -> Mask128 | HardenedRC4:
    if master_key is None:
        master_key_encrypted = probe_result.master_key_encrypted
        if isinstance(probe_result.qmcv2tag, QMCv2STag):
            raise ValueError('master key is required for QMCv2 with STag')
        else:
            if simple_key is None:
                raise ValueError("argument 'simple_key' is required "
                                 "to decrypt QMCv2 master key encryption V1 or V2"
                                 )
            if probe_result.master_key_encrypt_ver == 1:
                master_key = QMCv2KeyEncryptV1(simple_key).decrypt(master_key_encrypted)
            elif probe_result.master_key_encrypt_ver == 2:
                if mix_key1 is None or mix_key2 is None:
                    raise ValueError("argument 'mix_key1' and 'mix_key2' is required "
                                     "to decrypt QMCv2 master key encryption V2"
                                     )
                master_key = QMCv2KeyEncryptV2(simple_key, mix_key1, mix_key2).decrypt(master_key_encrypted)
            else:
                raise CrypterCreatingError(f'unsupported master key encryption version: '
                                           f'supports 1 and 2, got {probe_result.master_key_encrypt_ver}'
                                           )

    if len(master_key) < 300:
        cipher = Mask128.from_qmcv2_key256(master_key)
    else:
        cipher = HardenedRC4(master_key)

    return cipher


def _extract_qmcv2_file(fileobj: IO[bytes],
                        simple_key: bytes = None,
                        mix_key1: bytes = None,
                        mix_key2: bytes = None,
                        master_key: bytes = None
                        ) -> QMCv2:
    offset, probe_result = _probe_qmcv2_file(fileobj)
    cipher = _make_cipher(probe_result, simple_key, mix_key1, mix_key2, master_key)

    fileobj.seek(0, 0)
    initial_data = fileobj.read(probe_result.audio_encrypted_len)
    qmcv2tag = probe_result.qmcv2tag

    return QMCv2(cipher, initial_data, simple_key, mix_key1=mix_key1, mix_key2=mix_key2, qmcv2tag=qmcv2tag)
