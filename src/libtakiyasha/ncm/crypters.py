# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import warnings
from base64 import b64decode, b64encode
from typing import Any, IO, Literal, SupportsBytes, TypedDict, Union

from .ciphers import RC4WithNCMSpecs, XorWithRepeatedByteChar
from ..common import Cipher, TransparentCryptIOWrapper
from ..exceptions import CrypterCreateError
from ..formatprober import CommonAudioHeadersInRegexPattern
from ..standardciphers import StreamedAESWithModeECB
from ..utils import is_filepath, verify_fileobj
from ..warns import CrypterCreateWarning

__all__ = ['generate_ncm_tag', 'NCM', 'NCMCiphers', 'NCMMusicIdentityTag']

NCMCiphers = Union[RC4WithNCMSpecs, XorWithRepeatedByteChar]


class NCMMusicIdentityTag(TypedDict):
    format: str
    musicId: str
    musicName: str
    artist: list[list[str | int]]
    album: str
    albumId: int
    albumPicDocId: int
    albumPic: str
    mvId: int
    flag: int
    bitrate: int
    duration: int
    alias: list[str]
    transNames: list[str]


def _extract_masterkey(init_key: bytes,
                       masterkey_encrypted_xored: bytes
                       ) -> RC4WithNCMSpecs:
    # DeXOR masterkey_encrypted_xored to masterkey_encrypted
    masterkey_encrypted = bytes(b ^ 0x64 for b in masterkey_encrypted_xored)

    # 使用 init_key 解密主密钥，并创建 RC4WithNCMSpecs
    masterkey = StreamedAESWithModeECB(init_key).decrypt(masterkey_encrypted)[17:]  # 去除主密钥开头的 b'neteasecloudmusic'
    cipher = RC4WithNCMSpecs(masterkey)

    return cipher


def _extract_163key_tagdata(meta_key: bytes,
                            ncm_163key_xored: bytes
                            ) -> NCMMusicIdentityTag:
    # DeXOR ncm_163key_xored to ncm_163key
    ncm_163key = bytes(b ^ 0x63 for b in ncm_163key_xored)

    # 使用 meta_key 解密 163key 从第 22 个字符往后的数据，得到标签信息
    tagstr_encrypted_b64encoded = ncm_163key[22:]
    tagstr_encrypted = b64decode(tagstr_encrypted_b64encoded, validate=True)
    tagstr = StreamedAESWithModeECB(meta_key).decrypt(tagstr_encrypted)[6:]  # 在 JSON 反序列化之前，去除字节串开头的 b'music:'
    tag: NCMMusicIdentityTag = json.loads(tagstr)

    return tag


def _extract_cover_data(cover_space_data: bytes,
                        cover_data_len: int
                        ) -> bytes:
    # 封面数据所在区域的结构：
    # +--------------------+------------+
    # |      封面数据      |  预留空间  |
    # +--------------------+------------+
    return cover_space_data[:cover_data_len]


def _extract_ncm(fileobj: IO[bytes],
                 init_key: bytes,
                 meta_key: bytes | None = None
                 ) -> tuple[tuple[NCMCiphers, bytes], dict]:
    fileobj.seek(10, 0)

    # 获取加密的主密钥数据
    masterkey_encrypted_xored_len = int.from_bytes(fileobj.read(4), 'little')
    masterkey_encrypted_xored = fileobj.read(masterkey_encrypted_xored_len)

    # 获取 163key
    ncm_163key_xored_len = int.from_bytes(fileobj.read(4), 'little')
    ncm_163key_xored = fileobj.read(ncm_163key_xored_len)

    # 跳过 5 个字节的无意义数据
    fileobj.seek(5, 1)

    # 获取封面数据所在的空间，以及封面数据大小
    cover_space_len = int.from_bytes(fileobj.read(4), 'little')
    cover_data_len = int.from_bytes(fileobj.read(4), 'little')
    cover_space_data = fileobj.read(cover_space_len)

    # 使用 init_key 解密主密钥，并创建 RC4WithNCMSpecs
    if init_key is None:
        raise CrypterCreateError("argument 'init_key' is not provided, cannot to continue")
    cipher = _extract_masterkey(init_key, masterkey_encrypted_xored)

    # 使用 meta_key 解密 163key，获得标签信息
    # 如果 meta_key 为 None，跳过此步骤
    if meta_key is None:
        ncm_tag = {}
    else:
        ncm_tag = _extract_163key_tagdata(meta_key, ncm_163key_xored)

    # 获取封面数据
    cover_data = _extract_cover_data(cover_space_data, cover_data_len)

    # 读取剩余的加密音频数据
    audio_encrypted = fileobj.read()

    ret_tuple = cipher, audio_encrypted
    ret_dict = {
        'ncm_tag'   : ncm_tag,
        'cover_data': cover_data
    }
    ret_dict.update(ncm_tag)

    return ret_tuple, ret_dict


def _extract_ncmcache(fileobj: IO[bytes]) -> tuple[tuple[NCMCiphers, bytes], dict]:
    fileobj.seek(0, 0)

    cipher = XorWithRepeatedByteChar()
    ncm_tag = {}
    cover_data = b''
    audio_encrypted = fileobj.read()

    ret_tuple = cipher, audio_encrypted
    ret_dict = {
        'ncm_tag'   : ncm_tag,
        'cover_data': cover_data
    }

    return ret_tuple, ret_dict


def _extract(fileobj: IO[bytes],
             enctype: Literal['ncm', 'ncmcache'] | None = None,
             init_key: bytes | None = None,
             meta_key: bytes | None = None
             ) -> tuple[tuple[NCMCiphers, bytes], dict]:
    fileobj.seek(0, 0)

    if enctype is None:
        if fileobj.read(10).startswith(b'CTENFDAM'):
            extraction_flow = _extract_ncm
        else:
            extraction_flow = _extract_ncmcache
    elif enctype == 'ncm':
        extraction_flow = _extract_ncm
    elif enctype == 'ncmcache':
        extraction_flow = _extract_ncmcache
    else:
        if isinstance(enctype, str):
            raise ValueError(f"unsupported encryption type '{enctype}'")
        else:
            raise TypeError(f"'enctype' must be str, not {type(enctype).__name__}")

    extraction_flow_kwargs = {
        'fileobj': fileobj
    }
    if extraction_flow is _extract_ncm:
        extraction_flow_kwargs.update({
            'init_key': init_key,
            'meta_key': meta_key
        }
        )

    return extraction_flow(**extraction_flow_kwargs)


def _generate_masterkey_encrypted_xored(init_key: bytes,
                                        cipher: Cipher
                                        ) -> tuple[bytes, bytes]:
    masterkey = cipher.key
    masterkey_encrypted = StreamedAESWithModeECB(init_key).encrypt(b'neteasecloudmusic' + masterkey)

    masterkey_encrypted_xored = bytes(b ^ 0x64 for b in masterkey_encrypted)

    return len(masterkey_encrypted_xored).to_bytes(4, 'little'), masterkey_encrypted_xored


def _generate_163key_encrypted_xored(meta_key: bytes,
                                     ncm_tag: NCMMusicIdentityTag
                                     ) -> tuple[bytes, bytes]:
    tagstr = json.dumps(ncm_tag, ensure_ascii=False).encode()
    tagstr_encrypted = StreamedAESWithModeECB(meta_key).encrypt(b'music:' + tagstr)
    tagstr_encrypted_b64encoded = b64encode(tagstr_encrypted)
    ncm_163key = b"163 key(Don't modify):" + tagstr_encrypted_b64encoded

    ncm_163key_xored = bytes(b ^ 0x63 for b in ncm_163key)

    return len(ncm_163key_xored).to_bytes(4, 'little'), ncm_163key_xored


def _generate_cover_space(cover_data: bytes) -> tuple[bytes, bytes, bytes]:
    return len(cover_data).to_bytes(4, 'little'), len(cover_data).to_bytes(4, 'little'), cover_data


def _generate_ncm(fileobj: IO[bytes],
                  audio_encrypted: bytes,
                  cipher: Cipher,
                  init_key: bytes,
                  meta_key: bytes | None = None,
                  ncm_tag: NCMMusicIdentityTag | dict | None = None,
                  cover_data: bytes = b''
                  ) -> None:
    fileobj.seek(0, 0)

    fileobj.write(b'CTENFDAM\x00\x00')

    if init_key is None:
        raise CrypterCreateError("argument 'init_key' is not provided, cannot to continue")

    masterkey_encrypted_xored_len_packed, masterkey_encrypted_xored = _generate_masterkey_encrypted_xored(init_key, cipher)
    fileobj.write(masterkey_encrypted_xored_len_packed + masterkey_encrypted_xored)

    if meta_key is None:
        fileobj.write(b'\x00' * 4)
    else:
        ncm_163key_encrypted_xored_len_packed, ncm_163key_encrypted_xored = _generate_163key_encrypted_xored(meta_key, ncm_tag)
        fileobj.write(ncm_163key_encrypted_xored_len_packed + ncm_163key_encrypted_xored)

    fileobj.write(b'\x00' * 5)

    cover_space_len_packed, cover_data_len_packed, cover_space = _generate_cover_space(cover_data)
    fileobj.write(cover_space_len_packed + cover_data_len_packed + cover_space)

    fileobj.write(audio_encrypted)


def _generate_ncmcache(fileobj: IO[bytes],
                       audio_encrypted: bytes,
                       ) -> None:
    fileobj.seek(0, 0)

    fileobj.write(audio_encrypted)


def _generate(fileobj: IO[bytes],
              audio_encrypted: bytes,
              cipher: Cipher,
              init_key: bytes,
              meta_key: bytes | None = None,
              ncm_tag: NCMMusicIdentityTag | dict | None = None,
              cover_data: bytes = b''
              ) -> None:
    if isinstance(cipher, RC4WithNCMSpecs):
        generation_flow = _generate_ncm
    elif isinstance(cipher, XorWithRepeatedByteChar):
        generation_flow = _generate_ncmcache
    else:
        raise TypeError("'cipher' must be "
                        f"{RC4WithNCMSpecs.__name__} or {XorWithRepeatedByteChar.__name__}, "
                        f"not {type(cipher).__name__}"
                        )

    generation_flow_kwargs = {
        'fileobj'        : fileobj,
        'audio_encrypted': audio_encrypted
    }
    if generation_flow is _generate_ncm:
        generation_flow_kwargs.update({
            'cipher'    : cipher,
            'init_key'  : init_key,
            'meta_key'  : meta_key,
            'ncm_tag'   : ncm_tag,
            'cover_data': cover_data
        }
        )

    generation_flow(**generation_flow_kwargs)


def generate_ncm_tag(initial_dict: dict[str, Any]) -> NCMMusicIdentityTag:
    return {
        key: initial_dict.pop(key, initvar) for key, initvar in [
            ('format', ''),
            ('musicId', 0),
            ('musicName', ''),
            ('artist', []),
            ('album', ''),
            ('albumId', 0),
            ('albumPicDocId', 0),
            ('albumPic', ''),
            ('mvId', 0),
            ('flag', 0),
            ('bitrate', 0),
            ('duration', 0),
            ('alias', []),
            ('transNames', [])
        ]
    }


class NCM(TransparentCryptIOWrapper):
    @classmethod
    def loadfrom(cls,
                 filething: str | bytes | os.PathLike | IO[bytes],
                 enctype: Literal['ncm', 'ncmcache'] | None = None,
                 /,
                 **kwargs
                 ) -> NCM:
        validate: bool = kwargs.pop('validate', False)
        init_key: bytes = kwargs.pop('init_key', None)
        meta_key: bytes = kwargs.pop('meta_key', None)

        if is_filepath(filething):
            with open(filething, 'rb') as fileobj:
                init_posargs, init_kwargs = _extract(fileobj, enctype, init_key, meta_key)
                cipher, audio_encrypted = init_posargs
                crypter_filename = fileobj.name
        else:
            fileobj = verify_fileobj(filething,
                                     verify_binary_mode=True,
                                     verify_read=True,
                                     verify_seek=True
                                     )
            init_posargs, init_kwargs = _extract(fileobj, enctype, init_key, meta_key)
            cipher, audio_encrypted = init_posargs
            crypter_filename = getattr(fileobj, 'name', None)

        target_crypter = cls(cipher, audio_encrypted, **init_kwargs)
        target_crypter._name = crypter_filename

        if validate:
            if not CommonAudioHeadersInRegexPattern.probe(target_crypter):
                warnings.warn('the format of decrypt result does not match any common audio format. '
                              'Possible cases: '
                              'incorrect key, incorrect cipher type, corrupted data, '
                              'or just not audio format data',
                              CrypterCreateWarning
                              )

        return target_crypter

    def saveto(self, filething: str | bytes | os.PathLike | IO[bytes], /, **kwargs) -> None:

        init_key: bytes = kwargs.pop('init_key', None)
        meta_key: bytes = kwargs.pop('meta_key', None)

        audio_encrypted = self.raw.getvalue()
        cipher = self.cipher
        ncm_tag = self.ncm_tag.copy()
        cover_data = self.cover_data

        if is_filepath(filething):
            with open(filething, 'wb') as fileobj:
                _generate(fileobj, audio_encrypted, cipher, init_key, meta_key, ncm_tag, cover_data)
        else:
            fileobj = verify_fileobj(filething,
                                     verify_binary_mode=True,
                                     verify_read=False,
                                     verify_write=True,
                                     verify_seek=True
                                     )
            _generate(fileobj, audio_encrypted, cipher, init_key, meta_key, ncm_tag, cover_data)

    def __init__(self,
                 cipher: NCMCiphers,
                 initial_encrypted_data: bytes = b'',
                 /,
                 *,
                 cover_data: bytes = b'',
                 **kwargs
                 ):
        if not isinstance(cipher, (RC4WithNCMSpecs, XorWithRepeatedByteChar)):
            raise TypeError("'cipher' must be "
                            f"{RC4WithNCMSpecs.__name__} or {XorWithRepeatedByteChar.__name__}, "
                            f"not {type(cipher).__name__}"
                            )

        super().__init__(cipher, initial_encrypted_data)

        self._ncm_tag = generate_ncm_tag(kwargs)
        self._cover_data = cover_data

    @property
    def ncm_tag(self) -> NCMMusicIdentityTag | dict:
        return self._ncm_tag

    @property
    def cover_data(self) -> bytes:
        return self._cover_data

    @cover_data.setter
    def cover_data(self, value: SupportsBytes) -> None:
        if value is not None:
            value: bytes = bytes(value)

        self._cover_data = value
