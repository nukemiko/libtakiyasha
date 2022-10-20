# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field as dcfield
from secrets import token_bytes
from typing import Any, IO, Iterable, Mapping

from .common import BytesIOWithTransparentCryptLayer, CryptLayerWrappedIOSkel
from .exceptions import CrypterCreatingError, CrypterSavingError
from .keyutils import make_random_ascii_string, make_random_number_string
from .miscutils import bytestrxor
from .stdciphers import RC4, RC4WithNewSkel, StreamedAESWithModeECB
from .typedefs import BytesLike, FilePath
from .typeutils import is_filepath, tobytes, verify_fileobj

__all__ = ['NcmMusicIdentityTag', 'NCM']

_TAG_KEY = b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'


@dataclass
class NcmMusicIdentityTag:
    format: str = ''
    musicId: str = ''
    musicName: str = ''
    artist: list[list[str | int]] = dcfield(default_factory=list)
    album: str = ''
    albumId: int = 0
    albumPicDocId: int = 0
    albumPic: str = ''
    mvId: int = 0
    flag: int = 0
    bitrate: int = 0
    duration: int = 0
    alias: list[str] = dcfield(default_factory=list)
    transNames: list[str] = dcfield(default_factory=list)

    def to_dict(self) -> dict[str, str | int | list]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, mapping: Mapping) -> NcmMusicIdentityTag:
        return cls(**mapping)

    def to_mutagen_style_dict(self, ncm_163tag: str | BytesLike = None) -> dict[str, Any]:
        if ncm_163tag is None:
            comment: str | None = ncm_163tag
        elif isinstance(ncm_163tag, str):
            comment: str | None = str(ncm_163tag)
        else:
            comment: str | None = tobytes(ncm_163tag).decode()
        if not isinstance(self.format, str):
            raise TypeError(f"'self.format' must be str, not {type(self.format)}")
        elif self.format.lower() in ('flac', 'ogg'):
            ret = {
                'title' : [self.musicName],
                'artist': [artistinfo[0] for artistinfo in self.artist],
                'album' : [self.album],
            }
            if comment is not None:
                ret['comment'] = [comment]
        elif self.format.lower() == 'mp3':
            ret = {
                'TIT2': [self.musicName],
                'TPE1': [artistinfo[0] for artistinfo in self.artist],
                'TALB': [self.album]
            }
            if comment is not None:
                ret['TXXX::comment'] = [comment]
        else:
            raise ValueError(f"unsupported tag format '{self.format}'")

        return ret


@dataclass
class CloudMusicIdentifier:
    """网易云音乐 163key 的解析、储存和构建。"""
    format: str = ''
    musicId: str = ''
    musicName: str = ''
    artist: list[list[str | int]] = dcfield(default_factory=list)
    album: str = ''
    albumId: int = 0
    albumPicDocId: int = 0
    albumPic: str = ''
    mvId: int = 0
    flag: int = 0
    bitrate: int = 0
    duration: int = 0
    alias: list[str] = dcfield(default_factory=list)
    transNames: list[str] = dcfield(default_factory=list)

    @classmethod
    def from_ncm_163key(cls,
                        ncm_163key_maybe_xored: BytesLike, /,
                        is_xored: bool = False
                        ) -> CloudMusicIdentifier:
        """解析 163key，返回一个储存解析结果的 ``CloudMusicIdentifier`` 对象。

        第一个位置参数 ``ncm_163key_maybe_xored`` 是需要解析的 163key 字节串。

        如果 ``is_xored=True``，那么本方法会在解析之前，将 ``ncm_163key_maybe_xored``
        的每一个字节都与 ``0x63`` 进行 XOR。一般情况下不需要提供此参数。
        """
        ncm_163key_maybe_xored = tobytes(ncm_163key_maybe_xored)

        if is_xored:
            ncm_163key = bytestrxor(b'c' * len(ncm_163key_maybe_xored),
                                    ncm_163key_maybe_xored
                                    )
        else:
            ncm_163key = ncm_163key_maybe_xored

        ncm_tag_bytestr_encrypted_encoded = ncm_163key[22:]  # 去除开头的 b"163 key(Don't modify):"
        ncm_tag_bytestr_encrypted = b64decode(ncm_tag_bytestr_encrypted_encoded, validate=True)
        ncm_tag_bytestr = StreamedAESWithModeECB(_TAG_KEY).decrypt(ncm_tag_bytestr_encrypted)[6:]  # 去除字节串开头的 b'music:'

        return cls(**json.loads(ncm_tag_bytestr))

    def to_ncm_163key(self, with_xor: bool = False) -> bytes:
        """根据当前对象储存的解析结果，重建并返回一个 163key。

        如果 ``with_xor=True``，那么本方法在返回结果之间，
        将结果字节串的每一个字节都与 ``0x63`` 进行 XOR。一般情况下不需要提供此参数。
        """
        ncm_tag_bytestr = json.dumps(asdict(self), ensure_ascii=False).encode('utf-8')
        ncm_tag_bytestr_encrypted = StreamedAESWithModeECB(_TAG_KEY).encrypt(b'music:' + ncm_tag_bytestr)
        target = b"163 key(Don't modify):" + b64encode(ncm_tag_bytestr_encrypted)

        if with_xor:
            return bytestrxor(b'c' * len(target), target)
        else:
            return target

    def to_mutagen_style_dict(self) -> dict[str, Any]:
        """根据当前对象储存的解析结果，构建并返回一个 Mutagen VorbisComment/ID3 风格的字典。

        此方法需要当前对象的 ``format`` 属性来决定构建何种风格的字典，
        并且只支持 ``'flac'`` (VorbisComment) 和 ``'mp3'`` (ID3)。

        本方法不支持嵌入封面图像，你需要通过其他手段做到。

        配合 Mutagen 使用（以 FLAC 为例）：

        >>> ncm_tag = CloudMusicIdentifier(format='flac')
        >>> mutagen_flac = mutagen.flac.FLAC('target.flac')  # type: ignore
        >>> mutagen_flac.clear()  # 可选，此步骤将会清空 mutagen_flac 已有的数据
        >>> mutagen_flac.update(ncm_tag.to_mutagen_style_dict())
        >>>
        """
        comment = self.to_ncm_163key(with_xor=False)
        if not isinstance(self.format, str):
            raise TypeError(f"'self.format' must be str, not {type(self.format)}")
        elif self.format.lower() == 'flac':
            ret = {
                'title' : [self.musicName],
                'artist': [artistinfo[0] for artistinfo in self.artist],
                'album' : [self.album],
            }
            if comment is not None:
                ret['comment'] = [comment]
        elif self.format.lower() == 'mp3':
            ret = {
                'TIT2': [self.musicName],
                'TPE1': [artistinfo[0] for artistinfo in self.artist],
                'TALB': [self.album]
            }
            if comment is not None:
                ret['TXXX::comment'] = [comment]
        else:
            raise ValueError(f"unsupported tag format '{self.format}'")

        return ret


class NCM(BytesIOWithTransparentCryptLayer):
    """NCM 格式文件的读取和创建支持。"""

    @property
    def cipher(self) -> RC4:
        return self._cipher

    @property
    def cover_data(self) -> bytes:
        """从 NCM 文件中提取的封面图像数据。"""
        return self._cover_data

    @cover_data.setter
    def cover_data(self, value: BytesLike) -> None:
        self._cover_data = tobytes(value)

    @cover_data.deleter
    def cover_data(self) -> None:
        self._cover_data = b''

    @property
    def ncm_tag(self) -> NcmMusicIdentityTag:
        """从 NCM 文件中提取的标签信息。"""
        return self._ncm_tag

    @property
    def ncm_163key(self) -> bytes:
        """音乐信息标识符，由网易云音乐客户端使用。

        本属性会与 ``self.ncm_tag`` 同步变化。
        """
        return _make_ncm_163key(self._ncm_tag)

    @property
    def core_key(self) -> bytes | None:
        """加/解密主密钥使用的核心密钥。

        在打开已有 NCM 文件时，此属性会被自动设置；也可以直接设置此属性。
        """
        return self._core_key

    @property
    def master_key(self) -> bytes:
        return self.cipher.masterkey

    @core_key.setter
    def core_key(self, value: BytesLike) -> None:
        self._core_key = tobytes(value)

    @core_key.deleter
    def core_key(self) -> None:
        self._core_key = None

    def __init__(self,
                 cipher: RC4, /,
                 initial_data: BytesLike = b'',
                 core_key: BytesLike = None, *,
                 ncm_tag: NcmMusicIdentityTag | Mapping[str, Any] | Iterable[tuple[str, Any]] = None,
                 cover_data: BytesLike = b'',
                 ) -> None:
        """NCM 格式文件的读取和创建支持。

        Args:
            cipher: 加密/解密所需的 Cipher 对象
            initial_data: 可选，包含初始已加密数据的类字节对象
        """
        if core_key is None:
            self._core_key = None
        else:
            self._core_key = tobytes(core_key)
        if ncm_tag is None:  # 未指定，自动创建
            ncm_tag = NcmMusicIdentityTag()
        elif not isinstance(ncm_tag, NcmMusicIdentityTag):  # 由 NcmMusicIdentityTag 进行转换和错误处理
            ncm_tag = NcmMusicIdentityTag.from_mapping(ncm_tag)
        self._ncm_tag: NcmMusicIdentityTag = ncm_tag
        self._cover_data: bytes = tobytes(cover_data)
        super().__init__(cipher, initial_data)
        if not isinstance(cipher, RC4):
            raise TypeError(f"unsupported Cipher '{type(cipher).__name__}' "
                            f"(supported Ciphers: '{RC4.__name__}')"
                            )
        self._name: str | None = None

    @classmethod
    def new(cls) -> NCM:
        """创建一个空的 NCM 对象。"""
        master_key = (make_random_number_string(29) + make_random_ascii_string(84)).encode('utf-8')

        return cls(RC4(master_key))

    @classmethod
    def from_file(cls,
                  filething: FilePath | IO[bytes], /,
                  core_key: BytesLike
                  ) -> NCM:
        """打开一个已有的 NCM 文件 ``filething``。

        本方法需要在文件中寻找并解密主密钥，随后使用主密钥解密音频数据。

        核心密钥 ``core_key`` 是第一个位置参数，用于解密找到的主密钥。

        第二个位置参数 ``filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``filething`` 也可以是文件对象，该对象必须可读和可跳转
        （``filething.seekable() == True``）。
        """
        if core_key is not None:
            core_key = tobytes(core_key)

        if is_filepath(filething):
            with open(filething, 'rb') as fileobj:
                instance = _extract(fileobj, core_key)
        else:
            fileobj = verify_fileobj(filething, 'binary',
                                     verify_readable=True,
                                     verify_seekable=True
                                     )
            instance = _extract(fileobj, core_key)

        instance._name = getattr(fileobj, 'name', None)

        return instance

    def to_file(self,
                filething: FilePath | IO[bytes] = None, /,
                core_key: BytesLike = None,
                ) -> None:
        """将当前 NCM 对象保存到文件 ``filething``。
        此过程会向 ``filething`` 写入 NCM 文件结构。

        第一个位置参数 ``filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``filething`` 也可以是文件对象，该对象必须可写和可跳转
        （``filething.seekable() == True``）。

        第二个位置参数 ``core_key`` 是可选的。
        如果提供此参数，本方法会将其作为核心密钥来加密主密钥；否则，使用
        ``self.core_key`` 代替。如果两者都为 ``None`` 或未提供，触发 ``ValueError``。

        如果提供了 ``filething``，本方法将会把数据写入 ``filething``
        指向的文件。否则，本方法以写入模式打开一个指向 ``self.name``
        的文件对象，将数据写入此文件对象。如果两者都为空或未提供，则会触发
        ``ValueError``。
        """
        if core_key is None:
            if self.core_key is None:
                raise ValueError("core key missing: "
                                 "argument 'core_key' and attribute 'self.core_key' are "
                                 "empty or unspecified"
                                 )
            else:
                core_key = self.core_key
        else:
            core_key = tobytes(core_key)

        cipher: RC4 = self.cipher

        if filething is None:
            if self.name is None:
                raise ValueError("attribute 'self.name' and argument 'filething' is not provided, "
                                 "unable to continue the saving"
                                 )
            else:
                filething = self.name

        if is_filepath(filething):
            with open(filething, mode='wb') as fileobj:
                _create(fileobj,
                        core_key,
                        cipher,
                        self._ncm_tag,
                        self._cover_data,
                        self.getvalue(nocryptlayer=True)
                        )
        else:
            fileobj = verify_fileobj(filething, 'binary',
                                     verify_writable=True,
                                     verify_seekable=True
                                     )
            _create(fileobj,
                    core_key,
                    cipher,
                    self._ncm_tag,
                    self._cover_data,
                    self.getvalue(nocryptlayer=True)
                    )


def _ensure_is_ncmfile(fileobj: IO[bytes], offset: int) -> int:
    fileobj.seek(offset, 0)

    header = fileobj.read(10)
    if not header.startswith(b'CTENFDAM'):
        raise CrypterCreatingError("not a vaild NCM file: "
                                   f"header should be starts with b'CTENFDAM', got {header[:8]})"
                                   )

    return fileobj.tell()


def _extract_master_key(fileobj: IO[bytes],
                        offset: int,
                        core_key: bytes
                        ) -> tuple[int, RC4]:
    fileobj.seek(offset, 0)

    master_key_encrypted_xored_len = int.from_bytes(fileobj.read(4), 'little')
    master_key_encrypted = bytestrxor(b'd' * master_key_encrypted_xored_len,
                                      fileobj.read(master_key_encrypted_xored_len)
                                      )
    master_key = StreamedAESWithModeECB(core_key).decrypt(master_key_encrypted)[17:]  # 去除开头的 b'neteasecloudmusic'

    return fileobj.tell(), RC4(master_key)


def _extract_ncm_163key(fileobj: IO[bytes], offset: int) -> tuple[int, bytes]:
    fileobj.seek(offset, 0)

    ncm_163key_xored_len = int.from_bytes(fileobj.read(4), 'little')
    ncm_163key_xored = fileobj.read(ncm_163key_xored_len)
    ncm_163key = bytestrxor(b'c' * ncm_163key_xored_len, ncm_163key_xored)

    return fileobj.tell(), ncm_163key


def _extract_ncm_tag(ncm_163key: bytes) -> NcmMusicIdentityTag:
    ncm_tag_bytestr_encrypted_encoded = ncm_163key[22:]  # 去除开头的 b"163 key(Don't modify):"
    ncm_tag_bytestr_encrypted = b64decode(ncm_tag_bytestr_encrypted_encoded, validate=True)
    ncm_tag_bytestr = StreamedAESWithModeECB(_TAG_KEY).decrypt(ncm_tag_bytestr_encrypted)[6:]  # 去除字节串开头的 b'music:'

    return NcmMusicIdentityTag.from_mapping(json.loads(ncm_tag_bytestr))


def _skip_nonsenses(fileobj: IO[bytes], offset: int) -> int:
    fileobj.seek(offset, 0)

    fileobj.seek(5, 1)

    return fileobj.tell()


def _extract_cover_data(fileobj: IO[bytes], offset: int) -> tuple[int, bytes]:
    fileobj.seek(offset, 0)

    cover_space_len = int.from_bytes(fileobj.read(4), 'little')
    cover_data_len = int.from_bytes(fileobj.read(4), 'little')
    if cover_space_len - cover_data_len < 0:
        raise CrypterCreatingError(f'file structure error: '
                                   f'cover space length ({cover_space_len}) '
                                   f'< cover data length ({cover_data_len})'
                                   )
    cover_data = fileobj.read(cover_data_len)
    fileobj.seek(cover_space_len - cover_data_len, 1)

    return fileobj.tell(), cover_data


def _extract_encrypted_audio_data(fileobj: IO[bytes], offset: int) -> bytes:
    fileobj.seek(offset, 0)

    encrypted_audio_data = fileobj.read()

    return encrypted_audio_data


def _extract(fileobj: IO[bytes], core_key: bytes) -> NCM:
    start_offset = fileobj.tell()

    offset = _ensure_is_ncmfile(fileobj, start_offset)
    offset, cipher = _extract_master_key(fileobj, offset, core_key)
    offset, ncm_163key = _extract_ncm_163key(fileobj, offset)
    ncm_tag = _extract_ncm_tag(ncm_163key)
    offset = _skip_nonsenses(fileobj, offset)
    offset, cover_data = _extract_cover_data(fileobj, offset)
    audio_data = _extract_encrypted_audio_data(fileobj, offset)

    ncm = NCM(cipher, audio_data, ncm_tag=ncm_tag, cover_data=cover_data, core_key=core_key)

    return ncm


def _write_magic_header(fileobj: IO[bytes], offset: int) -> int:
    fileobj.seek(offset, 0)

    fileobj.write(b'CTENFDAM\x00\x00')

    return fileobj.tell()


def _write_master_key_encrypted_xored(fileobj: IO[bytes],
                                      offset: int,
                                      core_key: bytes,
                                      cipher: RC4
                                      ) -> int:
    fileobj.seek(offset, 0)

    master_key_encrypted = StreamedAESWithModeECB(core_key).encrypt(b'neteasecloudmusic' + cipher.masterkey)
    master_key_encrypted_xored = bytestrxor(b'd' * len(master_key_encrypted), master_key_encrypted)
    master_key_encrypted_xored_len = len(master_key_encrypted_xored).to_bytes(4, 'little')
    fileobj.write(master_key_encrypted_xored_len)
    fileobj.write(master_key_encrypted_xored)

    return fileobj.tell()


def _make_ncm_163key(ncm_tag: NcmMusicIdentityTag) -> bytes:
    ncm_tag_bytestr = json.dumps(ncm_tag.to_dict(), ensure_ascii=False).encode('utf-8')
    ncm_tag_bytestr_encrypted = StreamedAESWithModeECB(_TAG_KEY).encrypt(b'music:' + ncm_tag_bytestr)
    return b"163 key(Don't modify):" + b64encode(ncm_tag_bytestr_encrypted)


def _write_ncm_163key(fileobj: IO[bytes], offset: int, ncm_163key: bytes) -> int:
    fileobj.seek(offset, 0)

    ncm_163key_xored = bytestrxor(b'c' * len(ncm_163key), ncm_163key)
    ncm_163key_xored_len = len(ncm_163key_xored).to_bytes(4, 'little')
    fileobj.write(ncm_163key_xored_len)
    fileobj.write(ncm_163key_xored)

    return fileobj.tell()


def _write_cover_data(fileobj: IO[bytes], offset: int, cover_data: bytes) -> int:
    fileobj.seek(offset, 0)

    cover_space_len = len(cover_data).to_bytes(4, 'little')
    cover_data_len = cover_space_len
    fileobj.write(cover_space_len)
    fileobj.write(cover_data_len)
    fileobj.write(cover_data)

    return fileobj.tell()


def _write_encrypted_audio_data(fileobj: IO[bytes], offset: int, encrypted_audio_data: bytes) -> int:
    fileobj.seek(offset, 0)

    fileobj.write(encrypted_audio_data)

    return fileobj.tell()


def _create(fileobj: IO[bytes],
            core_key: bytes,
            cipher: RC4,
            ncm_tag: NcmMusicIdentityTag,
            cover_data: bytes,
            encrypted_audio_data: bytes
            ) -> None:
    start_offset = fileobj.tell()

    offset = _write_magic_header(fileobj, start_offset)
    offset = _write_master_key_encrypted_xored(fileobj, offset, core_key, cipher)
    ncm_163key = _make_ncm_163key(ncm_tag)
    offset = _write_ncm_163key(fileobj, offset, ncm_163key)
    offset = _skip_nonsenses(fileobj, offset)
    offset = _write_cover_data(fileobj, offset, cover_data)
    _write_encrypted_audio_data(fileobj, offset, encrypted_audio_data)


class NCMWithNewSkel(CryptLayerWrappedIOSkel):
    @property
    def cipher(self) -> RC4WithNewSkel:
        return self._cipher

    @property
    def master_key(self) -> bytes:
        return self.cipher.master_key

    @property
    def core_key(self) -> bytes:
        return self._core_key

    @core_key.setter
    def core_key(self, value: BytesLike) -> None:
        self._core_key = tobytes(value)

    @core_key.deleter
    def core_key(self) -> None:
        self._core_key = None

    @property
    def ncm_tag(self) -> CloudMusicIdentifier:
        return self._ncm_tag

    @property
    def cover_data(self) -> bytes:
        return self._cover_data

    @cover_data.setter
    def cover_data(self, value: BytesLike) -> None:
        self._cover_data = tobytes(value)

    @cover_data.deleter
    def cover_data(self) -> None:
        self._cover_data = b''

    def __init__(self,
                 cipher: RC4WithNewSkel, /,
                 initial_bytes: BytesLike = b'',
                 core_key: BytesLike = None, *,
                 ncm_tag: CloudMusicIdentifier | Mapping[str, Any] | Iterable[tuple[str, Any]] = None,
                 cover_data: BytesLike = b''
                 ) -> None:
        if core_key is None:
            self._core_key = None
        else:
            self._core_key = tobytes(core_key)
        if ncm_tag is None:
            ncm_tag = CloudMusicIdentifier()
        elif not isinstance(ncm_tag, CloudMusicIdentifier):
            ncm_tag = CloudMusicIdentifier(**ncm_tag)
        self._ncm_tag: CloudMusicIdentifier = ncm_tag
        self._cover_data: bytes = tobytes(cover_data)
        super().__init__(cipher, initial_bytes)
        if not isinstance(self._cipher, RC4WithNewSkel):
            raise TypeError(f"'{type(self).__name__}' "
                            f"only support cipher '{RC4WithNewSkel.__name__}', "
                            f"got '{type(self._cipher).__name__}'"
                            )

    @classmethod
    def new(cls,
            core_key: BytesLike = None, *,
            ncm_tag: CloudMusicIdentifier | Mapping[str, Any] | Iterable[tuple[str, Any]] = None,
            cover_data: BytesLike = b''
            ) -> NCMWithNewSkel:
        """创建一个空的 NCM 对象。"""
        master_key = (make_random_number_string(29) + make_random_ascii_string(84)).encode('utf-8')

        return cls(RC4WithNewSkel(master_key),
                   core_key=core_key,
                   ncm_tag=ncm_tag,
                   cover_data=cover_data
                   )

    @classmethod
    def from_file(cls,
                  ncm_filething: FilePath | IO[bytes], /,
                  core_key: BytesLike,
                  ) -> NCMWithNewSkel:
        """打开一个已有的 NCM 文件 ``ncm_filething``。

        第一个位置参数 ``ncm_filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``ncm_filething`` 也可以是文件对象，该对象必须可读和可跳转
        （``ncm_filething.seekable() == True``）。

        本方法需要在文件中寻找并解密主密钥，随后使用主密钥解密音频数据。

        核心密钥 ``core_key`` 是第二个参数，用于解密找到的主密钥。
        """

        def operation(fileobj: IO[bytes]) -> NCMWithNewSkel:
            if not fileobj.read(10).startswith(b'CTENFDAM'):
                raise ValueError(f"{fileobj} is not a NCM file")

            master_key_encrypted_xored_len = int.from_bytes(fileobj.read(4), 'little')
            master_key_encrypted_xored = fileobj.read(master_key_encrypted_xored_len)
            master_key_encrypted = bytestrxor(b'd' * master_key_encrypted_xored_len,
                                              master_key_encrypted_xored
                                              )
            master_key = StreamedAESWithModeECB(core_key).decrypt(master_key_encrypted)[17:]  # 去除开头的 b'neteasecloudmusic'
            cipher = RC4WithNewSkel(master_key)

            ncm_163key_xored_len = int.from_bytes(fileobj.read(4), 'little')
            ncm_163key_xored = fileobj.read(ncm_163key_xored_len)
            ncm_tag = CloudMusicIdentifier.from_ncm_163key(ncm_163key_xored, is_xored=True)

            fileobj.seek(5, 1)

            cover_space_len = int.from_bytes(fileobj.read(4), 'little')
            cover_data_len = int.from_bytes(fileobj.read(4), 'little')
            if cover_space_len - cover_data_len < 0:
                raise CrypterCreatingError(f'file structure error: '
                                           f'cover space length ({cover_space_len}) '
                                           f'< cover data length ({cover_data_len})'
                                           )
            cover_data = fileobj.read(cover_data_len)
            fileobj.seek(cover_space_len - cover_data_len, 1)

            audio_encrypted = fileobj.read()

            return cls(cipher, audio_encrypted, ncm_tag=ncm_tag, cover_data=cover_data, core_key=core_key)

        if is_filepath(ncm_filething):
            with open(ncm_filething, mode='rb') as ncm_fileobj:
                instance = operation(ncm_fileobj)
        else:
            ncm_fileobj = verify_fileobj(ncm_filething, 'binary',
                                         verify_readable=True,
                                         verify_seekable=True
                                         )
            instance = operation(ncm_fileobj)

        instance._name = getattr(ncm_fileobj, 'name', None)

        return instance

    def to_file(self,
                ncm_filething: FilePath | IO[bytes] = None, /,
                core_key: BytesLike = None
                ) -> None:
        """将当前 NCM 对象保存到文件 ``filething``。
        此过程会向 ``ncm_filething`` 写入 NCM 文件结构。

        第一个位置参数 ``ncm_filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``ncm_filething`` 也可以是文件对象，该对象必须可写。

        第二个位置参数 ``core_key`` 是可选的。
        如果提供此参数，本方法会将其作为核心密钥来加密主密钥；否则，使用
        ``self.core_key`` 代替。如果两者都为 ``None`` 或未提供，触发 ``ValueError``。

        如果提供了 ``ncm_filething``，本方法将会把数据写入 ``ncm_filething``
        指向的文件。否则，本方法以写入模式打开一个指向 ``self.name``
        的文件对象，将数据写入此文件对象。如果两者都为空或未提供，则会触发
        ``ValueError``。
        """

        def operation(fileobj: IO[bytes]) -> None:
            fileobj.write(b'CTENFDAM')
            fileobj.write(token_bytes(2))

            master_key_encrypted = StreamedAESWithModeECB(core_key).encrypt(b'neteasecloudmusic' + self.cipher.master_key)
            master_key_encrypted_xored = bytestrxor(b'd' * len(master_key_encrypted), master_key_encrypted)
            master_key_encrypted_xored_len = len(master_key_encrypted_xored).to_bytes(4, 'little')
            fileobj.write(master_key_encrypted_xored_len)
            fileobj.write(master_key_encrypted_xored)

            ncm_163key_xored = self.ncm_tag.to_ncm_163key(with_xor=True)
            ncm_163key_xored_len = len(ncm_163key_xored).to_bytes(4, 'little')
            fileobj.write(ncm_163key_xored_len)
            fileobj.write(ncm_163key_xored)

            fileobj.write(token_bytes(5))

            cover_space_len = len(self.cover_data).to_bytes(4, 'little')
            cover_data_len = cover_space_len
            fileobj.write(cover_space_len)
            fileobj.write(cover_data_len)
            fileobj.write(self.cover_data)

            fileobj.write(self.getvalue(nocryptlayer=True))

        if core_key is None:
            if self.core_key is None:
                raise CrypterSavingError('core key missing: '
                                         "argument 'core_key' and attribute 'self.core_key' "
                                         "are None or unspecified"
                                         )
            core_key = self.core_key
        else:
            core_key = tobytes(core_key)

        if is_filepath(ncm_filething):
            with open(ncm_filething, mode='wb') as ncm_fileobj:
                operation(ncm_fileobj)
        else:
            ncm_fileobj = verify_fileobj(ncm_filething, 'binary',
                                         verify_writable=True
                                         )
            operation(ncm_fileobj)
