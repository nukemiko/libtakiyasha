# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, IO, Type, Union

from .dataciphers import *
from .keyciphers import *
from ..common import BytesIOWithTransparentCryptLayer
from ..typedefs import *
from ..utils.typeutils import *

QMCKeyCiphers = Union[QMCv2KeyEncryptV1, QMCv2KeyEncryptV2]
QMCDataCiphers = Union[Mask128, HardenedRC4]
QMCDataCipherMakers = Union[Type[QMCDataCiphers], Callable[[BytesLike], QMCDataCiphers]]


@dataclass
class QMCv2STag:
    song_id: int
    unknown1: int
    unknown2: str

    @classmethod
    def from_bytes(cls, stag_bytestr: BytesLike) -> QMCv2STag:
        stag_bytestr = tobytes(stag_bytestr)
        stag_segments = stag_bytestr.split(b',')
        if len(stag_segments) != 3:
            raise ValueError('invalid STag data: the counts of splitted segments '
                             f'should be equal to 3, got {len(stag_segments)}'
                             )
        song_id = int(stag_segments[0])
        unknown1 = int(stag_segments[1])
        unknown2 = stag_segments[2].decode(encoding='utf-8')

        return cls(song_id, unknown1, unknown2)

    def to_bytes(self) -> bytes:
        return b','.join([str(_).encode('utf-8') for _ in (self.song_id, self.unknown1, self.unknown2)])


@dataclass
class QMCv2QTag:
    master_key_encrypted_b64encoded: bytes
    song_id: int
    unknown1: int

    @classmethod
    def from_bytes(cls, qtag_bytestr: BytesLike) -> QMCv2QTag:
        qtag_bytestr = tobytes(qtag_bytestr)
        qtag_segments = qtag_bytestr.split(b',')
        if len(qtag_segments) != 3:
            raise ValueError('invalid QTag data: the counts of splitted segments '
                             f'should be equal to 3, got {len(qtag_segments)}'
                             )
        master_key_encrypted_b64encoded = qtag_segments[0]
        song_id = int(qtag_segments[1])
        unknown1 = int(qtag_segments[2])

        return cls(master_key_encrypted_b64encoded, song_id, unknown1)

    def to_bytes(self) -> bytes:
        return b','.join([str(_).encode('utf-8') for _ in (self.master_key_encrypted_b64encoded, self.song_id, self.unknown1)])


class QMC(BytesIOWithTransparentCryptLayer):
    @classmethod
    def from_file(cls,
                  filething: FilePath | IO[bytes], /,
                  master_key_or_mask: BytesLike = None,
                  simple_key: BytesLike = None,
                  mix_key1: BytesLike = None,
                  mix_key2: BytesLike = None,
                  validate: bool = False
                  ) -> QMC:
        """打开一个已有的 QMC 文件 ``filething``。

        ``filething`` 可以是 ``str``、``bytes`` 或任何拥有 ``__fspath__``
        属性的路径对象。``filething`` 也可以是文件对象，该对象必须可读和可跳转
        （``filething.seekable() == True``）。

        本方法需要探测文件的 QMC 版本、在文件中寻找并解密主密钥。

        - 如果探测到文件 QMC 版本为 1，你必须提供参数 ``master_key_or_mask``。
        - 如果探测到文件 QMC 版本为 2：
            - 如果探测到文件中没有内嵌加密的主密钥，此时 ``master_key_or_mask`` 是必需的。
            - 如果探测到主密钥使用 V1 加密，你需要提供参数 ``simple_key``；
            - 如果探测到主密钥使用 V2 加密，除了 ``simple_key`` 之外，你还需要提供
            ``mix_key1`` 和 ``mix_key2``。
        - 无论探测结果如何，都会优先使用参数 ``master_key_or_mask`` 作为主密钥。
            - 在探测到文件 QMC 版本为 2 时，如果提供了 ``master_key_or_mask``，那么
            ``simple_key``、``mix_key1`` 和 ``mix_key2`` 的值都会被忽略。

        如果提供参数 ``validate=True``，本方法会验证解密的结果是否为常见的音频格式。
        如果验证未通过，将打印一条警告信息。
        """
