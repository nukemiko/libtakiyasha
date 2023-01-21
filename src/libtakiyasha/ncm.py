# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import warnings
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field as dcfield
from pathlib import Path
from secrets import token_bytes
from typing import Callable, IO, Literal, NamedTuple, Type

from mutagen import flac, id3

from .exceptions import CrypterCreatingError
from .keyutils import make_random_ascii_string, make_random_number_string
from .miscutils import BINARIES_ROOTDIR, bytestrxor
from .prototypes import EncryptedBytesIOSkel
from .stdciphers import ARC4, StreamedAESWithModeECB
from .typedefs import BytesLike, FilePath
from .typeutils import isfilepath, tobytes, verify_fileobj
from .warns import CrypterCreatingWarning

warnings.filterwarnings(action='default', category=DeprecationWarning, module=__name__)

__all__ = ['CloudMusicIdentifier', 'NCM', 'probe_ncm', 'NCMFileInfo']

MODULE_BINARIES_ROOTDIR = BINARIES_ROOTDIR / Path(__file__).stem


@dataclass(init=True)
class CloudMusicIdentifier:
    """解析、储存和重建网易云音乐 163key 。

    如果 163key 的来源文件来自网易云音乐客户端，根据你使用的客户端平台和版本，
    一些字段可能会缺失，从而被设为默认值。

    可以按照操作数据类（``dataclass``）实例的方式操作本类的实例。
    """

    def __post_init__(self) -> None:
        self._orig_ncm_tag: dict | None = None
        self._orig_ncm_163key: bytes | None = None
        self._orig_tag_key: bytes | None = None

    format: str = ''
    """文件格式，通常为 ``mp3`` 或 ``flac``。"""
    musicId: str = ''
    """此歌曲在网易云音乐的 ID。"""
    musicName: str = ''
    """此歌曲的标题。"""
    artist: list[list[str | int]] = dcfield(default_factory=list)
    """此歌曲的歌手。"""
    album: str = ''
    """此歌曲所属的专辑。"""
    albumId: int = 0
    """此歌曲所属的专辑在网易云音乐平台的 ID。"""
    albumPicDocId: int = 0
    """此歌曲所属的专辑，其封面在网易云音乐平台的 ID。"""
    albumPic: str = ''
    """此歌曲所属的专辑，其封面的下载链接。"""
    mvId: int = 0
    """此歌曲的 MV 在网易云音乐平台的 ID。"""
    flag: int = 0
    bitrate: int = 0
    """此歌曲的比特率。"""
    duration: int = 0
    """此歌曲的长度（单位为秒）。"""
    gain: float = 0.0
    """此歌曲的平均响度。"""
    mp3DocId: str = ''
    alias: list[str] = dcfield(default_factory=list)
    """此歌曲在网易云音乐平台的别名。"""
    transNames: list[str] = dcfield(default_factory=list)
    """此歌曲标题在网易云音乐平台的翻译。"""

    def to_mutagen_tag(self,
                       tag_type: Literal['FLAC', 'ID3'] = None,
                       with_ncm_163key: bool = True,
                       tag_key: BytesLike | None = None,
                       return_cached_first: bytes = True
                       ) -> flac.FLAC | id3.ID3:
        """将 CloudMusicIdentifier 对象导出为 Mutagen 库使用的标签格式实例：
        ``mutagen.flac.FLAC`` 和 ``mutagen.id3.ID3``。

        ``tag_type`` 用于选择需要导出为何种格式的标签实例，仅支持 ``FLAC``
        和 ``ID3``。如果留空，则根据 ``self.format`` 决定。如果两者都为空，则会触发 ``ValueError``。

        Args:
            tag_type: 需要导出为何种格式的标签实例，仅支持 'FLAC' 和 'ID3'
            with_ncm_163key: 是否在导出的标签中嵌入 163key
            tag_key: （仅当 with_163key=True）歌曲信息密钥，用于加密 163key，以便将其写入注释
            return_cached_first: （仅当 with_163key=True）在满足特定条件时，将缓存的 163key 写入注释，而不是重新生成一个

        Examples:
            >>> from mutagen import flac, mp3
            [...]
            >>> ncm_tag1: CloudMusicIdentifier
            >>> ncm_tag1.format
            'flac'
            >>> mutagen_tag1 = ncm_tag1.to_mutagen_tag()
            >>> type(mutagen_tag1)
            mutagen.flac.FLAC
            >>> flactag = flac.FLAC('test.flac')
            >>> flactag.update(mutagen_tag1)
            >>> flactag.save()
            >>>
            [...]
            >>> ncm_tag2: CloudMusicIdentifier
            >>> ncm_tag2.format
            'mp3'
            >>> mutagen_tag2 = ncm_tag2.to_mutagen_tag()
            >>> type(mutagen_tag2)
            mutagen.id3.ID3
            >>> mp3tag = mp3.MP3('test.mp3')
            >>> mp3tag.update(mutagen_tag2)
            >>> mp3tag.save()
            >>>
        """
        if tag_type is None:
            if self.format.lower() == 'flac':
                tag_type = 'FLAC'
            elif self.format.lower() == 'mp3':
                tag_type = 'ID3'
            elif not self.format:
                raise ValueError(
                    "don't know which type of tag is needed: "
                    "self.format and 'tag_type' are empty"
                )
            else:
                raise ValueError(
                    "don't know which type of tag is needed: "
                    "'tag_type' is empty, and the value of self.format is not supported"
                )
        if tag_type == 'FLAC':
            with open(MODULE_BINARIES_ROOTDIR / 'empty.flac', mode='rb') as _f:
                # 受 mutagen 功能限制，编辑 FLAC 标签之前必须打开一个空 FLAC 文件
                tag: flac.FLAC | id3.ID3 = flac.FLAC(_f)
            keymaps = {
                'musicName': ('title', lambda _: [_]),
                'artist'   : ('artist', lambda _: list(str(list(__)[0]) for __ in list(_))),
                'album'    : ('album', lambda _: [_])
            }
        elif tag_type == 'ID3':
            tag: flac.FLAC | id3.ID3 = id3.ID3()
            keymaps = {
                'musicName': ('TIT2', lambda _: id3.TIT2(text=[_], encoding=3)),
                'artist'   : ('TPE1', lambda _: id3.TPE1(text=list(str(list(__)[0]) for __ in list(_)), encoding=3)),
                'album'    : ('TALB', lambda _: id3.TALB(text=[_], encoding=3))
            }
        else:
            raise ValueError(
                f"'tag_type' must be 'FLAC', 'ID3', or None, not {repr(tag_type)}"
            )

        tagkey_constructor: tuple[str, Callable[[str], list[str]] | Callable[[str], id3.Frame]]
        for attrname, tagkey_constructor in keymaps.items():
            tagkey, constructor = tagkey_constructor
            attr = getattr(self, attrname)
            if attr:
                tag[tagkey] = constructor(attr)

        if with_ncm_163key:
            ncm_163key = self.to_ncm_163key(tag_key=tag_key,
                                            return_cached_first=return_cached_first
                                            )
            if isinstance(tag, flac.FLAC):
                tag['description'] = [ncm_163key.decode('ascii')]
            elif isinstance(tag, id3.ID3):
                tag['TXXX::comment'] = id3.TXXX(encoding=3, desc='comment', text=[ncm_163key.decode('ascii')])

        return tag

    @classmethod
    def from_ncm_163key(cls, ncm_163key: str | BytesLike, /, tag_key: BytesLike = None):
        """将一个 163key 字符串/字节对象转换为 CloudMusicIdentifier 对象。

        本方法会缓存给定的 163key，以及该 163key 解密后的结果，用于确保 ``self.to_ncm_163key()``
        返回值的一致性。

        Args:
            ncm_163key: 以“163key”开头的字符串/字节对象
            tag_key: 歌曲信息密钥，用于解密 163key
        """
        if isinstance(ncm_163key, str):
            ncm_163key = bytes(ncm_163key, encoding='utf-8')
        else:
            ncm_163key = tobytes(ncm_163key)
        if tag_key is None:
            tag_key = b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'
        else:
            tag_key = tobytes(tag_key)

        ncm_tag_serialized_encrypted_encoded = ncm_163key[22:]  # 去除开头的 b"163 key(Don't modify):"
        ncm_tag_serialized_encrypted = b64decode(ncm_tag_serialized_encrypted_encoded, validate=True)
        ncm_tag_serialized = StreamedAESWithModeECB(tag_key).decrypt(
            ncm_tag_serialized_encrypted
        )[6:]  # 去除字节串开头的 b'music:'
        ncm_tag = json.loads(ncm_tag_serialized)

        instance = cls(**ncm_tag)
        instance._orig_ncm_tag = ncm_tag
        instance._orig_ncm_163key = ncm_163key
        instance._orig_tag_key = tag_key
        return instance

    def to_ncm_163key(self,
                      tag_key: BytesLike = None,
                      return_cached_first: bytes = True
                      ) -> bytes:
        """将 CloudMusicIdentifier 对象导出为 163key。

        第一个参数 ``tag_key`` 用于解密 163key。如果留空，则使用默认值：
        ``b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'``

        第二个参数 ``return_cached`` 如果为 ``True``，
        那么在当前对象转换而来的字典（下称当前字典）与缓存的 163key 解密得到的字典（下称缓存字典）
        满足以下条件时，本方法会直接返回 ``self.from_ncm_163key()`` 缓存的 163key：

        - 当前字典包含了缓存字典中的所有字段，且在两个字典中，这些键对应的值也是一致的
        - 当前字典中缓存字典没有的字段，其值为默认值（空值）

        如果以上条件中的任意一条未被满足，转而返回一个根据当前对象重新生成的 163key。
        Args:
            tag_key: 歌曲信息密钥，用于加密 163key
            return_cached_first: 在满足特定条件时，返回缓存的 163key，而不是重新生成一个
        """
        if tag_key is None:
            tag_key = b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'
        else:
            tag_key = tobytes(tag_key)

        if return_cached_first and self._orig_ncm_tag:
            target_ncm_tag = {_ck: _cv for _ck, _cv in asdict(self).items() if _cv or _ck in self._orig_ncm_tag}
        else:
            target_ncm_tag = asdict(self)

        def operation() -> bytes:
            ncm_tag_serialized = json.dumps(target_ncm_tag, ensure_ascii=False).encode('utf-8')
            ncm_tag_serialized_encrypted = StreamedAESWithModeECB(tag_key).encrypt(b'music:' + ncm_tag_serialized)
            ncm_163key = b"163 key(Don't modify):" + b64encode(ncm_tag_serialized_encrypted)

            return ncm_163key

        if return_cached_first and tag_key == self._orig_tag_key and self._orig_ncm_tag and self._orig_ncm_163key:
            if len(target_ncm_tag) == len(self._orig_ncm_tag):
                for k, v in self._orig_ncm_tag.items():
                    if target_ncm_tag[k] != v:
                        break
                else:
                    return tobytes(self._orig_ncm_163key)

        return operation()

    def to_mutagen_style_dict(self):
        """（已弃用，且将会在后续版本中删除。请尽快使用
        ``CloudMusicIdentifier.to_mutagen_tag()`` 代替，以便极大简化步骤。）

        根据当前对象储存的解析结果，构建并返回一个 Mutagen VorbisComment/ID3 风格的字典。

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
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.to_mutagen_style_dict() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {type(self).__name__}.to_mutagen_tag() instead.'
            )
        )

        comment = self.to_ncm_163key().decode('utf-8')
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


class NCMFileInfo(NamedTuple):
    """用于储存 NCM 文件的信息。"""
    master_key_encrypted: bytes
    ncm_163key: bytes
    cipher_ctor: Callable[[...], ARC4]
    cipher_data_offset: int
    cipher_data_len: int
    cover_data_offset: int
    cover_data_len: int


def probe_ncm(filething: FilePath | IO[bytes], /) -> tuple[Path | IO[bytes], NCMFileInfo | None]:
    """探测源文件 ``filething`` 是否为一个 NCM 文件。

    返回一个 2 个元素长度的元组：

    - 第一个元素为 ``filething``
    - 如果 ``filething`` 是 NCM 文件，那么第二个元素为一个 ``NCMFileInfo`` 对象；
    - 否则为 ``None``。

    本方法的返回值可以用于 ``NCM.open()`` 的第一个位置参数。

    Args:
        filething: 源文件的路径或文件对象
    Returns:
        一个 2 个元素长度的元组：第一个元素为 filething；如果
        filething 是 NCM 文件，那么第二个元素为一个 NCMFileInfo 对象；否则为 None。
    """

    def operation(fd: IO[bytes]) -> NCMFileInfo | None:
        fd.seek(0, 0)

        if not fd.read(10).startswith(b'CTENFDAM'):
            return

        master_key_encrypted_xored_len = int.from_bytes(fd.read(4), 'little')
        master_key_encrypted_xored = fd.read(master_key_encrypted_xored_len)
        master_key_encrypted = bytestrxor(b'd' * master_key_encrypted_xored_len,
                                          master_key_encrypted_xored
                                          )

        ncm_163key_xored_len = int.from_bytes(fd.read(4), 'little')
        ncm_163key_xored = fd.read(ncm_163key_xored_len)
        ncm_163key = bytestrxor(b'c' * ncm_163key_xored_len, ncm_163key_xored)

        fd.seek(5, 1)

        cover_space_len = int.from_bytes(fd.read(4), 'little')
        cover_data_len = int.from_bytes(fd.read(4), 'little')
        if cover_space_len - cover_data_len < 0:
            raise CrypterCreatingError(f'file structure error: '
                                       f'cover space length ({cover_space_len}) '
                                       f'< cover data length ({cover_data_len})'
                                       )
        cover_data_offset = fd.tell()
        cipher_data_offset = fd.seek(cover_space_len, 1)
        cipher_data_len = fd.seek(0, 2) - cipher_data_offset

        return NCMFileInfo(
            master_key_encrypted=master_key_encrypted,
            ncm_163key=ncm_163key,
            cipher_ctor=ARC4,
            cipher_data_offset=cipher_data_offset,
            cipher_data_len=cipher_data_len,
            cover_data_offset=cover_data_offset,
            cover_data_len=cover_data_len
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


class NCM(EncryptedBytesIOSkel):
    """基于 BytesIO 的 NCM 透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    如果你要新建一个 NCM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
    ``NCM.new()`` 和 ``NCM.open()`` 新建或打开已有 NCM 文件，
    使用已有 NCM 对象的 ``save()`` 方法将其保存到文件。

    使用示例：

    - 新建一个 NCM 对象以便编辑：
    >>> ncmfile = NCM.new()
    >>> ncmfile
    <libtakiyasha.ncm.NCM at 0x7f26c4f4a390, cipher <libtakiyasha.stdciphers.ARC4 object at 0x7f26c51214b0>>
    >>>

    - 获取使用的主密钥：
    >>> ncmfile.master_key  # 此处的密钥是随机生成的
    b'60564957557881842441053098814sAwKPjVq2gK9JXW0nV7BF3iQXh0J1ra34dh9UqfiMCUUzOrcyKERif9IfdFf5toJk6rO8TZaVSYkQVtZClVY'
    >>>

    - 访问内部的 Cipher 对象：
    >>> ncmfile.cipher
    <libtakiyasha.stdciphers.ARC4 object at 0x7f26c51214b0>
    >>>

    - 打开一个外部 NCM 文件：
    >>> ncmfile = NCM.open('/path/to/ncmfile.ncm', core_key=b'YourNCMCoreKey', tag_key=b'YourNCMTagKey')
    >>> ncmfile
    <libtakiyasha.ncm.NCM at 0x7f26c44e5080, cipher <libtakiyasha.stdciphers.ARC4 object at 0x7f26c4ef1270>, source '/path/to/ncmfile.ncm'>
    >>>
    更多使用方法，请使用 ``help(NCM.open)`` 查看帮助。

    - 读取和写入，注意写入操作产生的修改需要调用 ``save()`` 方法显式保存：
    >>> ncmfile.read(16)
    b'fLaC\\x00\\x00\\x00"\\x12\\x00\\x12\\x00\\x00\\x07)\\x00'
    >>> ncmfile.seek(0, 2)
    36137109
    >>> ncmfile.write(b'\\x00Writing something')
    18
    >>>

    - 保存上述操作产生的更改
    >>> # 如果该 NCM 对象不是从文件打开的，还需要 filething 参数
    >>> ncmfile.save(core_key=b'YourNCMCoreKey', tag_key=b'YourNCMTagKey')
    >>>
    更多使用方法，请使用 ``help(NCM.save)`` 查看帮助。

    - 获取歌曲标签和封面信息，详见 ``CloudMusicIdentifier``：
    >>> ncmfile.ncm_tag
    CloudMusicIdentifier(format=..., musicId=..., musicName=..., artist=[[..., ...], [..., ...]], album=..., albumId=..., albumPicDocId=..., albumPic=..., mvId=..., flag=..., bitrate=..., duration=..., gain=..., mp3DocId=..., alias=[...], transNames=[...])
    >>> len(ncmfile.cover_data)
    141248
    >>>
    """

    @classmethod
    def from_file(cls,
                  ncm_filething: FilePath | IO[bytes], /,
                  core_key: BytesLike,
                  ):
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``NCM.open()`` 代替。）

        打开一个已有的 NCM 文件 ``ncm_filething``。

        第一个位置参数 ``ncm_filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``ncm_filething`` 也可以是文件对象，该对象必须可读和可跳转
        （``ncm_filething.seekable() == True``）。

        本方法需要在文件中寻找并解密主密钥，随后使用主密钥解密音频数据。

        核心密钥 ``core_key`` 是第二个参数，用于解密找到的主密钥。
        """
        warnings.warn(
            DeprecationWarning(
                f'{cls.__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {cls.__name__}.open() instead.'
            )
        )
        return cls.open(ncm_filething, core_key=core_key)

    @classmethod
    def open(cls,
             filething_or_info: tuple[Path | IO[bytes], NCMFileInfo | None] | FilePath | IO[bytes], /,
             core_key: BytesLike = None,
             tag_key: BytesLike = None,
             master_key: BytesLike = None
             ):
        """打开一个 NCM 文件，并返回一个 ``NCM`` 对象。

        第一个位置参数 ``filething_or_info`` 需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。

        ``filething_or_info`` 也可以接受 ``probe_ncm()`` 函数的返回值：
        一个包含两个元素的元组，第一个元素是源文件的路径或文件对象，第二个元素是源文件的信息。

        第二个参数 ``core_key`` 一般情况下是必需的，用于解密文件内嵌的主密钥。
        例外：如果你提供了第四个参数 ``master_key``，那么它是可选的。

        第三个参数 ``tag_key`` 可选，用于解密文件内嵌的歌曲信息。如果留空，则使用默认值：
        ``b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'``

        第四个参数 ``master_key`` 可选，如果提供，将会被作为主密钥使用，
        而文件内置的主密钥会被忽略，``core_key`` 也不再是必需参数。
        一般不需要填写此参数，因为 NCM 文件总是内嵌加密的主密钥，从而可以轻松地获得。

        Args:
            filething_or_info: 源文件的路径或文件对象，或者 probe_ncm() 的返回值
            core_key: 核心密钥，用于解密文件内嵌的主密钥
            tag_key: 歌曲信息密钥，用于解密文件内嵌的歌曲信息
            master_key: 如果提供，将会被作为主密钥使用，而文件内置的主密钥会被忽略
        Raises:
            TypeError: 参数 core_key 和 master_key 都未提供
        """
        if core_key is not None:
            core_key = tobytes(core_key)
        if tag_key is not None:
            tag_key = tobytes(tag_key)
        if master_key is not None:
            master_key = tobytes(master_key)
        if master_key is None and core_key is None:
            raise TypeError(
                f"{cls.__name__}.open() missing 1 argument: 'core_key'"
            )

        def operation(fd: IO[bytes]) -> cls:
            if master_key is None:
                target_master_key = StreamedAESWithModeECB(core_key).decrypt(
                    fileinfo.master_key_encrypted
                )[17:]  # 去除开头的 b'neteasecloudmusic'
            else:
                target_master_key = master_key
            cipher = fileinfo.cipher_ctor(target_master_key)

            try:
                ncm_tag = CloudMusicIdentifier.from_ncm_163key(
                    fileinfo.ncm_163key,
                    tag_key=tag_key
                )
            except Exception as exc:
                warnings.warn(f'skip parsing 163key, because an exception was raised while parsing: '
                              f'{type(exc).__name__}: {exc}',
                              CrypterCreatingWarning
                              )
                warnings.warn(f"you may need to check if the file {repr(filething)} "
                              f"is corrupted.",
                              CrypterCreatingWarning
                              )
                ncm_tag = CloudMusicIdentifier()

            fd.seek(fileinfo.cover_data_offset, 0)
            cover_data = fd.read(fileinfo.cover_data_len)

            fd.seek(fileinfo.cipher_data_offset, 0)
            initial_bytes = fd.read(fileinfo.cipher_data_len)

            inst = cls(cipher, initial_bytes)
            inst._cover_data = cover_data
            inst._ncm_tag = ncm_tag

            return inst

        if isinstance(filething_or_info, tuple):
            filething_or_info: tuple[Path | IO[bytes], NCMFileInfo | None]
            if len(filething_or_info) != 2:
                raise TypeError(
                    "first argument 'filething_or_info' must be a file path, a file object, "
                    "or a tuple of probe_ncm() returns"
                )
            filething, fileinfo = filething_or_info
        else:
            filething, fileinfo = probe_ncm(filething_or_info)

        if fileinfo is None:
            raise CrypterCreatingError(
                f"{repr(filething)} is not a NCM file"
            )
        elif not isinstance(fileinfo, NCMFileInfo):
            raise TypeError(
                f"second element of the tuple must be NCMFileInfo or None, not {type(fileinfo).__name__}"
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
                ncm_filething: FilePath | IO[bytes] = None, /,
                core_key: BytesLike = None
                ) -> None:
        """（已弃用，且将会在后续版本中删除。请尽快使用 ``NCM.save()`` 代替。）

        将当前 NCM 对象保存到文件 ``filething``。
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
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.from_file() is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'Use {type(self).__name__}.save() instead.'
            )
        )
        if not core_key:
            core_key = self.core_key
        return self.save(core_key, filething=ncm_filething)

    def save(self,
             core_key: BytesLike,
             filething: FilePath | IO[bytes] = None,
             tag_key: BytesLike | None = None
             ) -> None:
        """将当前对象保存为一个新 NCM 文件。

        第一个参数 ``core_key`` 是必需的，用于加密主密钥，以便嵌入到文件。

        第二个参数 ``filething`` 是可选的，如果提供此参数，需要是一个文件路径或文件对象。
        可接受的文件路径类型包括：字符串、字节串、任何定义了 ``__fspath__()`` 方法的对象。
        如果是文件对象，那么必须可读且可寻址（其 ``seekable()`` 方法返回 ``True``）。
        如果未提供此参数，那么将会尝试使用当前对象的 ``source`` 属性；如果后者也不可用，则引发
        ``TypeError``。

        第三个参数 ``tag_key`` 可选，用于加密歌曲信息，以便嵌入到文件。如果留空，则使用默认值：
        ``b'\x23\x31\x34\x6c\x6a\x6b\x5f\x21\x5c\x5d\x26\x30\x55\x3c\x27\x28'``

        Args:
            core_key: 核心密钥，用于加密主密钥，以便嵌入到文件
            filething: 目标文件的路径或文件对象
            tag_key: 歌曲信息密钥，用于加密歌曲信息，以便嵌入到文件
        """
        core_key = tobytes(core_key)
        if tag_key is not None:
            tag_key = tobytes(tag_key)

        def operation(fd: IO[bytes]) -> None:
            fd.seek(0, 0)

            fd.write(b'CTENFDAM')
            fd.seek(2, 1)

            master_key = self.master_key
            master_key_encrypted = StreamedAESWithModeECB(core_key).encrypt(b'neteasecloudmusic' + master_key)
            master_key_encrypted_xored = bytestrxor(b'd' * len(master_key_encrypted), master_key_encrypted)
            master_key_encrypted_xored_len = len(master_key_encrypted_xored)
            fd.write(master_key_encrypted_xored_len.to_bytes(4, 'little'))
            fd.write(master_key_encrypted_xored)

            ncm_163key = self.ncm_tag.to_ncm_163key(tag_key)
            ncm_163key_xored = bytestrxor(b'c' * len(ncm_163key), ncm_163key)
            ncm_163key_xored_len = len(ncm_163key_xored)
            fd.write(ncm_163key_xored_len.to_bytes(4, 'little'))
            fd.write(ncm_163key_xored)

            fd.write(token_bytes(5))

            cover_data = self.cover_data if self.cover_data else b''
            cover_data_len = len(cover_data)
            fd.write(cover_data_len.to_bytes(4, 'little'))  # cover_space length
            fd.write(cover_data_len.to_bytes(4, 'little'))  # cover_data length
            fd.write(cover_data)

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
    def new(cls):
        """返回一个空 NCM 对象。"""
        master_key = (make_random_number_string(29) + make_random_ascii_string(84)).encode('utf-8')

        return cls(ARC4(master_key))

    @property
    def acceptable_ciphers(self) -> list[Type[ARC4]]:
        return [ARC4]

    def __init__(self, cipher: ARC4, /, initial_bytes=b''):
        """基于 BytesIO 的 NCM 透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        如果你要新建一个 NCM 对象，不要直接调用 ``__init__()``，而是使用构造器方法
        ``NCM.new()`` 和 ``NCM.open()`` 新建或打开已有 NCM 文件，
        使用已有 NCM 对象的 ``save()`` 方法将其保存到文件。

        Args:
            cipher: 要使用的 cipher，必须是一个 libtakiyasha.stdciphers.ARC4 对象
            initial_bytes: 内置缓冲区的初始数据
        """
        super().__init__(cipher, initial_bytes=initial_bytes)

        self._cover_data: bytes | None = None
        self._ncm_tag: CloudMusicIdentifier = CloudMusicIdentifier()
        self._sourcefile: Path | None = None
        self._core_key_deprecated: bytes | None = None

    @property
    def core_key(self) -> bytes | None:
        """（已弃用，且将会在后续版本中删除。）

        核心密钥，用于加/解密主密钥。

        ``NCM.from_file()`` 会在当前对象被创建时设置此属性；而 ``NCM.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.core_key is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage the core key by your self.'
            )
        )
        return self._core_key_deprecated

    @core_key.setter
    def core_key(self, value: BytesLike) -> None:
        """（已弃用，且将会在后续版本中删除。）

        核心密钥，用于加/解密主密钥。

        ``NCM.from_file()`` 会在当前对象被创建时设置此属性；而 ``NCM.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.core_key is deprecated, no longer used, '
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

        ``NCM.from_file()`` 会在当前对象被创建时设置此属性；而 ``NCM.open()`` 则不会。
        """
        warnings.warn(
            DeprecationWarning(
                f'{type(self).__name__}.core_key is deprecated, no longer used, '
                f'and may be removed in subsequent versions. '
                f'You need to manage the core key by your self.'
            )
        )
        self._core_key_deprecated = None

    @property
    def cover_data(self) -> bytes | None:
        """封面图像数据。"""
        return self._cover_data

    @cover_data.setter
    def cover_data(self, value: BytesLike) -> None:
        """封面图像数据。"""
        if value is None:
            raise TypeError(
                f"None cannot be assigned to attribute 'cover_data'. "
                f"Use `del self.cover_data` instead"
            )
        self._cover_data = tobytes(value)

    @cover_data.deleter
    def cover_data(self) -> None:
        """封面图像数据。"""
        self._cover_data = None

    @property
    def ncm_tag(self) -> CloudMusicIdentifier:
        """163key 的解析结果。"""
        return self._ncm_tag

    @ncm_tag.setter
    def ncm_tag(self, value: CloudMusicIdentifier) -> None:
        """163key 的解析结果。"""
        if not isinstance(value, CloudMusicIdentifier):
            raise TypeError(
                f"attribute 'ncm_tag' must be CloudMusicIdentifier, not {type(value).__name__}"
            )
