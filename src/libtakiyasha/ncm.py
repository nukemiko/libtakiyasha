# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import warnings
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field as dcfield
from secrets import token_bytes
from typing import Any, IO, Iterable, Mapping, TypedDict

from .common import CryptLayerWrappedIOSkel
from .exceptions import CrypterCreatingError, CrypterSavingError
from .keyutils import make_random_ascii_string, make_random_number_string
from .miscutils import bytestrxor
from .stdciphers import ARC4, StreamedAESWithModeECB
from .typedefs import BytesLike, FilePath
from .typeutils import is_filepath, tobytes, verify_fileobj
from .warns import CrypterCreatingWarning

__all__ = ['CloudMusicIdentifier', 'NCM']

_TAG_KEY = b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'

MutagenStyleDict = TypedDict(
    'MutagenStyleDict', {
        'TIT2'         : list,
        'TPE1'         : list,
        'TALB'         : list,
        'TXXX::comment': list,
        'title'        : list,
        'artist'       : list,
        'album'        : list,
        'comment'      : list
    },
    total=False
)


@dataclass
class CloudMusicIdentifier:
    """解析、储存和重建网易云音乐 163key 。"""
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
    gain: float = 0.0
    mp3DocId: str = ''
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

    def to_mutagen_style_dict(self) -> MutagenStyleDict:
        """根据当前对象储存的解析结果，构建并返回一个 Mutagen VorbisComment/ID3 风格的字典。

        此方法需要当前对象的 ``format`` 属性来决定构建何种风格的字典，
        并且只支持 ``'flac'`` (VorbisComment) 和 ``'mp3'`` (ID3)。

        本方法不支持嵌入封面图像，你需要通过其他手段做到。

        配合 Mutagen 使用（以 FLAC 为例）：

        >>> from mutagen import flac  # type: ignore
        >>> ncm_tag = CloudMusicIdentifier(format='flac')
        >>> mutagen_flac = mutagen.flac.FLAC('target.flac')  # type: ignore
        >>> mutagen_flac.clear()  # 可选，此步骤将会清空 mutagen_flac 已有的数据
        >>> mutagen_flac.update(ncm_tag.to_mutagen_style_dict())
        >>> mutagen_flac.save()
        >>>

        配合 Mutagen 使用（以 MP3 为例，稍微麻烦一些）：

        >>> from mutagen import id3, mp3  # type: ignore
        >>> ncm_tag = CloudMusicIdentifier(format='mp3')
        >>> mutagen_mp3 = mutagen.mp3.MP3('target.mp3')  # type: ignore
        >>> mutagen_mp3.clear()  # 可选，此步骤将会清空 mutagen_mp3 已有的数据
        >>> for key, value in ncm_tag.to_mutagen_style_dict().items():
        ...     id3frame_cls = getattr(id3, key[:4])
        ...     id3frame = mutagen_mp3.get(key)
        ...     if id3frame is None:
        ...         mutagen_mp3[key] = id3frame_cls(text=value, desc='comment')
        ...     elif id3frame.text:
        ...         id3frame.text = value
        ...         mutagen_mp3[key] = id3frame
        ...
        >>> mutagen_mp3.save()
        >>>
        """
        comment = self.to_ncm_163key(with_xor=False).decode('utf-8')
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


class NCM(CryptLayerWrappedIOSkel):
    """基于 BytesIO 的 NCM 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 NCM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``NCM.new()`` 和 ``NCM.from_file()`` 新建或打开已有 NCM 文件，
    使用已有 NCM 对象的 ``self.to_file()`` 方法将其保存到文件。
    """

    @property
    def cipher(self) -> ARC4:
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
                 cipher: ARC4, /,
                 initial_bytes: BytesLike = b'',
                 core_key: BytesLike = None, *,
                 ncm_tag: CloudMusicIdentifier | Mapping[str, Any] | Iterable[tuple[str, Any]] = None,
                 cover_data: BytesLike = b''
                 ) -> None:
        """基于 BytesIO 的 NCM 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 NCM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``NCM.new()`` 和 ``NCM.from_file()`` 新建或打开已有 NCM 文件，
        使用已有 NCM 对象的 ``self.to_file()`` 方法将其保存到文件。
        """
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
        if not isinstance(self._cipher, ARC4):
            raise TypeError(f"'{type(self).__name__}' "
                            f"only support cipher '{ARC4.__module__}.{ARC4.__name__}', "
                            f"got '{type(self._cipher).__name__}'"
                            )

    @classmethod
    def new(cls,
            core_key: BytesLike = None, *,
            ncm_tag: CloudMusicIdentifier | Mapping[str, Any] | Iterable[tuple[str, Any]] = None,
            cover_data: BytesLike = b''
            ) -> NCM:
        """创建一个空的 NCM 对象。"""
        master_key = (make_random_number_string(29) + make_random_ascii_string(84)).encode('utf-8')

        return cls(ARC4(master_key),
                   core_key=core_key,
                   ncm_tag=ncm_tag,
                   cover_data=cover_data
                   )

    @classmethod
    def from_file(cls,
                  ncm_filething: FilePath | IO[bytes], /,
                  core_key: BytesLike,
                  ) -> NCM:
        """打开一个已有的 NCM 文件 ``ncm_filething``。

        第一个位置参数 ``ncm_filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``ncm_filething`` 也可以是文件对象，该对象必须可读和可跳转
        （``ncm_filething.seekable() == True``）。

        本方法需要在文件中寻找并解密主密钥，随后使用主密钥解密音频数据。

        核心密钥 ``core_key`` 是第二个参数，用于解密找到的主密钥。
        """

        def operation(fileobj: IO[bytes]) -> NCM:
            if not fileobj.read(10).startswith(b'CTENFDAM'):
                raise ValueError(f"{fileobj} is not a NCM file")

            master_key_encrypted_xored_len = int.from_bytes(fileobj.read(4), 'little')
            master_key_encrypted_xored = fileobj.read(master_key_encrypted_xored_len)
            master_key_encrypted = bytestrxor(b'd' * master_key_encrypted_xored_len,
                                              master_key_encrypted_xored
                                              )
            master_key = StreamedAESWithModeECB(core_key).decrypt(master_key_encrypted)[17:]  # 去除开头的 b'neteasecloudmusic'
            cipher = ARC4(master_key)

            ncm_163key_xored_len = int.from_bytes(fileobj.read(4), 'little')
            ncm_163key_xored = fileobj.read(ncm_163key_xored_len)
            try:
                ncm_tag = CloudMusicIdentifier.from_ncm_163key(ncm_163key_xored, is_xored=True)
            except Exception as exc:
                warnings.warn(f'skip parsing 163key, because an exception was raised while parsing: '
                              f'{type(exc).__name__}: {exc}',
                              CrypterCreatingWarning
                              )
                warnings.warn(f"you may need to check if the file {repr(ncm_filething)} "
                              f"is corrupted.",
                              CrypterCreatingWarning
                              )
                ncm_tag = None

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
