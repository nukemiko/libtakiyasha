# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Callable, IO, Literal

from ..typedefs import *

__all__ = [
    'tobytes',
    'tobytearray',
    'toint_nofloat',
    'is_filepath',
    'verify_fileobj',
    'verify_cipher'
]


def tobytes(byteslike: BytesLike) -> bytes:
    """尝试将 ``byteslike`` 转换为 ``bytes``。

    对 ``int`` 类型的对象不适用。如果输入这样的值，会触发 ``TypeError``。
    """
    if isinstance(byteslike, int):
        # 防止出现 bytes(1000) 这样的情况
        raise TypeError(f"a bytes-like object is required, not '{type(byteslike).__name__}'")
    else:
        return bytes(byteslike)


def tobytearray(byteslike: BytesLike) -> bytearray:
    """尝试将 ``byteslike`` 转换为 ``bytearray``。

    对 ``int`` 类型的对象不适用。如果输入这样的值，会触发 ``TypeError``。
    """
    if isinstance(byteslike, int):
        # 防止出现 bytearray(1000) 这样的情况
        raise TypeError(f"a bytes-like object is required, not '{type(byteslike).__name__}'")
    else:
        return bytearray(byteslike)


def toint_nofloat(integerlike: IntegerLike) -> int:
    """尝试将 ``integerlike`` 转换为 ``int``。

    对 ``float`` 类型或拥有 ``__float__`` 属性的对象不适用。
    如果输入这样的值，会触发 ``TypeError``。
    """
    if isinstance(integerlike, float) or hasattr(integerlike, '__float__'):
        raise TypeError(f"'{type(integerlike).__name__}' object cannot be interpreted as an integer")
    else:
        return int(integerlike)


def is_filepath(obj) -> bool:
    """判断对象 ``obj`` 是否可以被视为文件路径。

    只有 ``str``、``bytes`` 类型，或者拥有 ``__fspath__``
    属性的对象，才会被视为文件路径。
    """
    return isinstance(obj, (str, bytes)) or hasattr(obj, '__fspath__')


def verify_fileobj(fileobj: IO,
                   mode: Literal['text', 'binary'],
                   *,
                   verify_readable: bool = True,
                   verify_writable: bool = False,
                   verify_seekable: bool = True,
                   ):
    """

    Args:
        fileobj: 要验证的目标文件对象
        mode: fileobj 打开的模式，只能为 'text'（文本）和 'binary'（二进制）两个值
        verify_readable: 如果为真值，则验证 fileobj 是否可读
        verify_writable: 如果为真值，则验证 fileobj 是否可写
        verify_seekable: 如果为真值，则验证 fileobj 是否可任意改变读/写开始的位置
    """
    if mode == 'text':
        test_content = ''
        result_types = (str,)
    elif mode == 'binary':
        test_content = b'',
        result_types = (bytes, bytearray)
    elif isinstance(mode, str):
        raise ValueError("mode must be either 'text' or 'binary'")
    else:
        raise TypeError("verify_fileobj() argument 'mode' must be str, "
                        f"not {type(mode).__name__}"
                        )

    if bool(verify_readable):
        try:
            result = fileobj.read(0)
        except Exception as exc:
            if not hasattr(fileobj, 'read'):
                raise TypeError(f"{repr(fileobj)} is not a valid file object")
            raise ValueError(f"cannot read from file object {repr(fileobj)}") from exc
        else:
            if not isinstance(result, result_types):
                raise ValueError(f"file object '{repr(fileobj)}' is not open in {mode} mode")

    if verify_seekable:
        try:
            fileobj.seek(0, 1)
        except Exception as exc:
            if not hasattr(fileobj, 'seek'):
                raise TypeError(f"{repr(fileobj)} is not a valid file object")
            raise ValueError(f"cannot seek in file object {repr(fileobj)}") from exc

    if bool(verify_writable):
        try:
            fileobj.write(test_content)
        except TypeError as exc:
            raise ValueError(f"file object '{repr(fileobj)}' is not open in {mode} mode") from exc
        except Exception as exc:
            if not hasattr(fileobj, 'write'):
                raise TypeError(f"{repr(fileobj)} is not a valid file object")
            raise ValueError(f"cannot write to file object {repr(fileobj)}") from exc


def verify_cipher(obj) -> Cipher:
    try:
        offset_related: bool = getattr(obj, 'offset_related')
        encrypt: Callable[[BytesLike, int], bytes] | Callable[[BytesLike, Any], bytes] = getattr(obj, 'encrypt')
        decrypt: Callable[[BytesLike, int], bytes] | Callable[[BytesLike, Any], bytes] = getattr(obj, 'decrypt')
    except AttributeError as exc:
        raise TypeError(f"{repr(obj)} is not a valid Cipher object") from exc
    else:
        if not isinstance(offset_related, bool):
            raise AttributeError(f"attribute 'offset_related' must be bool, "
                                 f"not {type(offset_related).__name__}"
                                 )
        if not callable(encrypt):
            raise AttributeError(f"attribute 'encrypt' must be callable")
        if not callable(decrypt):
            raise AttributeError(f"attribute 'decrypt' must be callable")

        return obj
