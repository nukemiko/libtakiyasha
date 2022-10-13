# -*- coding: utf-8 -*-
from __future__ import annotations

import warnings
from base64 import b64decode
from binascii import Error as BinasciiError
from dataclasses import dataclass
from typing import Callable, IO, NamedTuple, Type, Union

from .dataciphers import *
from .keyciphers import *
from ..common import BytesIOWithTransparentCryptLayer
from ..exceptions import CrypterCreatingError
from ..formatprober import CommonAudioHeadersInRegexPattern
from ..typedefs import *
from ..utils.typeutils import *
from ..warns import CrypterCreatingWarning

QMCKeyCiphers = Union[QMCv2KeyEncryptV1, QMCv2KeyEncryptV2]
QMCDataCiphers = Union[Mask128, HardenedRC4]
QMCDataCipherMakers = Union[Type[QMCDataCiphers], Callable[[BytesLike], QMCDataCiphers]]


class QMCFileStructureProbeResult(NamedTuple):
    qmcver: int
    audio_encrypted_len: int
    keyencver: None | int
    payload: None | bytes | QMCv2QTag | QMCv2STag


@dataclass
class QMCv2STag:
    song_id: int
    unknown1: int
    song_mid: str

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
        song_mid = stag_segments[2].decode(encoding='utf-8')

        return cls(song_id, unknown1, song_mid)

    def to_bytes(self) -> bytes:
        return b','.join([str(_).encode('utf-8') for _ in (self.song_id, self.unknown1, self.song_mid)])


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
        return self.master_key_encrypted_b64encoded + b','.join([str(_).encode('utf-8') for _ in ('', self.song_id, self.unknown1)])


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
            - 如果探测到主密钥使用 V2 加密，除了 ``simple_key`` 之外，你还需要提供 ``mix_key1`` 和 ``mix_key2``。
                - ``mix_key1`` 和 ``mix_key2`` 的顺序正确与否会影响主密钥能否解密。
        - 无论探测结果如何，都会优先使用参数 ``master_key_or_mask`` 作为主密钥。
            - 在探测到文件 QMC 版本为 2 时，如果提供了 ``master_key_or_mask``，那么
            ``simple_key``、``mix_key1`` 和 ``mix_key2`` 的值都会被忽略。

        如果提供参数 ``validate=True``，本方法会验证解密的结果是否为常见的音频格式。
        如果验证未通过，将打印一条警告信息。
        """
        if master_key_or_mask is not None:
            master_key_or_mask = tobytes(master_key_or_mask)
        if simple_key is not None:
            simple_key = tobytes(simple_key)
        if mix_key1 is not None:
            mix_key1 = tobytes(mix_key1)
        if mix_key2 is not None:
            mix_key2 = tobytes(mix_key2)

        if is_filepath(filething):
            with open(filething, 'rb') as fileobj:
                instance = _extract(fileobj, master_key_or_mask, simple_key, mix_key1, mix_key2)
        else:
            fileobj = verify_fileobj(filething, 'binary',
                                     verify_readable=True,
                                     verify_seekable=True
                                     )
            instance = _extract(fileobj, master_key_or_mask, simple_key, mix_key1, mix_key2)

        if validate and not CommonAudioHeadersInRegexPattern.probe(instance):
            warnings.warn("decrypted data header does not match any common audio file headers. "
                          "Possible cases: broken data, incorrect core_key, or not a NCM file",
                          CrypterCreatingWarning
                          )

        return instance


def _probe_file_structure(fileobj: IO[bytes],
                          offset: int = 0
                          ) -> tuple[int, QMCFileStructureProbeResult]:
    fileobj.seek(offset, 0)

    file_total_len = fileobj.seek(0, 2)
    fileobj.seek(-4, 2)
    master_key_encrypted_b64encoded_len_packed = fileobj.read(4)
    master_key_encrypted_b64encoded_len = int.from_bytes(master_key_encrypted_b64encoded_len_packed, 'little')

    if master_key_encrypted_b64encoded_len_packed == b'QTag':
        # QTag 使用逗号分隔，第一个字段是加密主密钥
        fileobj.seek(-8, 2)
        qtag_len = int.from_bytes(fileobj.read(4), 'little')
        audio_encrypted_len = fileobj.seek(-(qtag_len + 8), 2)
        payload = QMCv2QTag.from_bytes(fileobj.read(qtag_len))
        qmcver = 2
        keyencver = 1
    elif master_key_encrypted_b64encoded_len_packed == b'STag':
        # STag 使用逗号分隔，但没有内嵌密钥，需要用户自己提供
        fileobj.seek(-8, 2)
        stag_len = int.from_bytes(fileobj.read(4), 'big')
        audio_encrypted_len = fileobj.seek(-(stag_len + 8), 2)
        payload = QMCv2STag.from_bytes(fileobj.read(stag_len))
        qmcver = 2
        keyencver = None
    elif master_key_encrypted_b64encoded_len > file_total_len:
        # 加密主密钥大小大于文件大小，判定为无效数据，按 QMCv1 处理
        audio_encrypted_len = file_total_len
        payload = None
        qmcver = 1
        keyencver = None
    else:
        # 首先判断是否为 QMCv2
        audio_encrypted_len = fileobj.seek(-(master_key_encrypted_b64encoded_len + 4), 2)
        master_key_encrypted_b64encoded = fileobj.read(master_key_encrypted_b64encoded_len)
        try:
            # 如果为 KeyEncV1，应当进入 else 分支
            payload = b64decode(master_key_encrypted_b64encoded, validate=True)
        except BinasciiError:
            # 否则，可能为 KeyEncV2 或无效数据
            suspect_master_key_encrypted = b64decode(master_key_encrypted_b64encoded, validate=False)
            if suspect_master_key_encrypted.startswith(b'QQMusic EncV2,Key:'):
                # QMCv2 KeyEncV2
                payload = suspect_master_key_encrypted[18:]
                qmcver = 2
                keyencver = 2
            else:
                # 无效数据，按照 QMCv1 处理
                audio_encrypted_len = file_total_len
                payload = None
                qmcver = 1
                keyencver = None
        else:
            # QMCv2 KeyEncV1
            qmcver = 2
            keyencver = 1

    return fileobj.tell(), QMCFileStructureProbeResult(qmcver, audio_encrypted_len, keyencver, payload)


def _select_cipher(master_key_or_mask: bytes, qmcver: int) -> QMCDataCiphers:
    if qmcver == 1:
        if len(master_key_or_mask) == 44:
            cipher = Mask128.from_qmcv1_mask44(master_key_or_mask)
        elif len(master_key_or_mask) == 128:
            cipher = Mask128(master_key_or_mask)
        elif len(master_key_or_mask) == 256:
            cipher = Mask128.from_qmcv1_mask256(master_key_or_mask)
        else:
            raise ValueError(f"invalid mask length: "
                             f"should be 44, 128 or 256, got {len(master_key_or_mask)}"
                             )
    elif qmcver == 2:
        if len(master_key_or_mask) == 128:
            cipher = Mask128(master_key_or_mask)
        elif len(master_key_or_mask) == 256:
            cipher = Mask128.from_qmcv2_key256(master_key_or_mask)
        elif len(master_key_or_mask) == 512:
            cipher = HardenedRC4(master_key_or_mask)
        else:
            raise ValueError(f"invalid master key or mask length: "
                             f"should be 128, 256 or 512, got {len(master_key_or_mask)}"
                             )
    else:
        raise ValueError(f"unsupported QMC version: should be 1 or 2, got {qmcver}")

    return cipher


def _extract(fileobj: IO[bytes],
             master_key_or_mask: bytes = None,
             simple_key: bytes = None,
             mix_key1: bytes = None,
             mix_key2: bytes = None
             ) -> QMC:
    start_offset = fileobj.tell()

    offset, probe_result = _probe_file_structure(fileobj, start_offset)

    if probe_result.qmcver == 1:
        if master_key_or_mask is None:
            raise TypeError("QMC version is 1, argument 'master_key_or_mask' is required")
        cipher = _select_cipher(master_key_or_mask, probe_result.qmcver)
    elif probe_result.qmcver == 2:
        if master_key_or_mask is None:
            if isinstance(probe_result.payload, QMCv2STag):
                raise TypeError("QMC version is 2 but master key not found, "
                                "argument 'master_key_or_mask' is required"
                                )
            elif isinstance(probe_result.payload, QMCv2QTag):
                master_key_encrypted: bytes = b64decode(probe_result.payload.master_key_encrypted_b64encoded, validate=True)
            elif isinstance(probe_result.payload, bytes):
                master_key_encrypted: bytes = probe_result.payload
            else:
                raise CrypterCreatingError('QMC version is 2, not STag, but master key missing')

            if simple_key is None:
                raise TypeError("QMC version is 2, argument 'simple_key' is required")
            elif probe_result.keyencver == 1:
                master_key = QMCv2KeyEncryptV1(simple_key).decrypt(master_key_encrypted)
            elif probe_result.keyencver == 2:
                if mix_key1 is None and mix_key2 is None:
                    raise TypeError("QMC version is 2 and master key encryption version is 2, "
                                    "argument 'mix_key1' and 'mix_key2' is required"
                                    )
                elif mix_key1 is None:
                    raise TypeError("QMC version is 2 and master key encryption version is 2, "
                                    "argument 'mix_key1' is required"
                                    )
                elif mix_key2 is None:
                    raise TypeError("QMC version is 2 and master key encryption version is 2, "
                                    "argument 'mix_key2' is required"
                                    )
                master_key = QMCv2KeyEncryptV2(simple_key, mix_key1, mix_key2).decrypt(master_key_encrypted)
            else:
                raise CrypterCreatingError('QMC version is 2, not STag, '
                                           'but master key encryption version is unknown'
                                           )
            cipher = _select_cipher(master_key, probe_result.qmcver)
        else:
            cipher = _select_cipher(master_key_or_mask, probe_result.qmcver)
    else:
        raise CrypterCreatingError(f'unknown QMC version: should be 1 or 2, '
                                   f'probed {probe_result.qmcver}'
                                   )

    fileobj.seek(0, 0)
    audio_encrypted = fileobj.read(probe_result.audio_encrypted_len)

    return QMC(cipher, audio_encrypted)
