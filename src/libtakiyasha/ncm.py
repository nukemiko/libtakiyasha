# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import warnings
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field as dcfield
from functools import cached_property
from typing import Any, IO, Iterable, Mapping

from .common import *
from .exceptions import CrypterCreatingError
from .formatprober import *
from .stdciphers import RC4, StreamedAESWithModeECB
from .typedefs import *
from .utils import *
from .utils.typeutils import *
from .warns import CrypterCreatingWarning

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


class NCM(BytesIOWithTransparentCryptedLayer):
    """NCM 格式文件的读取和创建支持。"""

    @cached_property
    def name(self) -> str | None:
        return self._name

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
        """核心密钥，用于加密/解密主密钥（``self.cipher.masterkey``）。"""
        return self._core_key

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
            core_key: 可选，核心密钥，将会存储为同名属性以便 saveto_file() 方法使用
        """
        if ncm_tag is None:  # 未指定，自动创建
            ncm_tag = NcmMusicIdentityTag()
        elif not isinstance(ncm_tag, NcmMusicIdentityTag):  # 由 NcmMusicIdentityTag 进行转换和错误处理
            ncm_tag = NcmMusicIdentityTag.from_mapping(ncm_tag)
        self._ncm_tag: NcmMusicIdentityTag = ncm_tag
        self._cover_data: bytes = tobytes(cover_data)
        if core_key is None:
            self._core_key: bytes | None = None
        else:
            self._core_key: bytes | None = tobytes(core_key)
        super().__init__(cipher, initial_data)
        if not isinstance(cipher, RC4):
            raise TypeError(f"unsupported Cipher '{type(cipher).__name__}' "
                            f"(supported Ciphers: '{RC4.__name__}')"
                            )
        self._name: str | None = None

    @classmethod
    def new(cls, master_key: BytesLike, core_key: BytesLike = None) -> NCM:
        """创建一个空的 NCM 对象。主密钥 ``master_key`` 是必需的。

        核心密钥 ``core_key`` 是可选的，如果提供此参数，其将会作为返回的 NCM 实例
        ``core_key`` 属性的值。
        """
        return cls(RC4(master_key), core_key=core_key)

    @classmethod
    def from_file(cls,
                  filething: FilePath | IO[bytes],
                  core_key: BytesLike,
                  validate: bool = False
                  ) -> NCM:
        """打开一个已有的 NCM 文件 ``filething``。

        ``filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``filething`` 也可以是文件对象，该对象必须可读和可跳转
        （``filething.seekable() == True``）。

        本方法需要在文件中寻找并解密主密钥，随后使用主密钥解密音频数据。

        核心密钥 ``core_key`` 用于解密找到的主密钥。

        如果提供参数 ``validate=True``，本方法会验证解密的结果是否为常见的音频格式。
        如果验证未通过，将打印一条警告信息。
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

        if validate and not CommonAudioHeadersInRegexPattern.probe(instance):
            warnings.warn("decrypted data header does not match any common audio file headers. "
                          "Possible cases: broken data, incorrect core_key, or not a NCM file",
                          CrypterCreatingWarning
                          )

        return instance

    def saveto_file(self,
                    filething: FilePath | IO[bytes] = None,
                    core_key: BytesLike = None
                    ) -> None:
        """将当前 NCM 对象保存到文件 ``filething``。
        此过程会向 ``filething`` 写入 NCM 文件结构。

        ``filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``filething`` 也可以是文件对象，该对象必须可写和可跳转
        （``filething.seekable() == True``）。

        如果提供了 ``filething``，本方法将会把数据写入 ``filething`` 指向的文件。否则，将数据写入
        ``self.name``。如果两者都为空或未提供，则会触发 ``ValueError``。

        如果提供了 ``core_key``，本方法会将其作为核心密钥来加密主密钥。否则，
        使用当前对象的同名属性作为核心密钥。如果两者都为空或未提供，则会触发 ``ValueError``。
        """
        if core_key is None:
            if self.core_key is None:
                raise ValueError("attribute 'self.core_key' and argument 'core_key' is not provided, "
                                 "unable to continue the export"
                                 )
            else:
                core_key = self.core_key
        else:
            core_key = tobytes(core_key)

        cipher: RC4 = self.cipher

        if filething is None:
            if self.name is None:
                raise ValueError("attribute 'self.name' and argument 'filething' is not provided, "
                                 "unable to continue the export"
                                 )
            else:
                filething = self.name

        if is_filepath(filething):
            with open(filething, mode='wb') as fileobj:
                return _create(fileobj,
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
            return _create(fileobj,
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

    ncm = NCM(cipher, audio_data, core_key, ncm_tag=ncm_tag, cover_data=cover_data)
    ncm._name = getattr(fileobj, 'name', None)

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
