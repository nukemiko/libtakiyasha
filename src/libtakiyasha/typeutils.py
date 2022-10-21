# -*- coding: utf-8 -*-
from __future__ import annotations

from threading import RLock
from typing import Any, Callable, IO, Literal, Type

from .typedefs import BytesLike, IntegerLike, PT, RT, T

__all__ = [
    'ClassInstanceProperty',
    'CachedClassInstanceProperty',
    'tobytes',
    'tobytearray',
    'toint_nofloat',
    'is_filepath',
    'verify_fileobj'
]


class ClassInstanceProperty:
    """一个只读属性装饰器实现，通过此装饰器设置的只读属性，
    可同时在类及其实例中访问。

    通过此装饰器装饰的属性，在类未被实例化时，其
    ``setter()`` 和 ``deleter()`` 不可用。

    可用于设置一些需要在类及其实例中都保持只读的属性。
    """

    def __init__(self,
                 fget: Callable[[T], RT] = None,
                 fset: Callable[[T, PT], None] = None,
                 fdel: Callable[[T], None] = None,
                 doc: str = None
                 ) -> None:
        self.fget = fget
        self.fset = fset
        self.fdel = fdel
        if doc is None and fget is not None:
            doc = fget.__doc__
        self.__doc__ = doc
        self._attrname = ''

    def __set_name__(self, obj: T, attrname: str):
        self._attrname = attrname

    def __get__(self, obj: T, objtype: Type[T] = None) -> RT:
        if self.fget is None:
            raise AttributeError(f"unreadable attribute '{self._attrname}'")
        if obj is None:
            return self.fget(objtype)
        return self.fget(obj)

    def __set__(self, obj: T, value: PT) -> None:
        if self.fset is None:
            raise AttributeError(f"can't set attribute '{self._attrname}'")
        self.fset(obj, value)

    def __delete__(self, obj: T) -> None:
        if self.fdel is None:
            raise AttributeError(f"can't delete attribute '{self._attrname}'")
        self.fdel(obj)

    def getter(self, fget: Callable[[T], Any]):
        prop = type(self)(fget, self.fset, self.fdel, self.__doc__)
        prop._attrname = self._attrname
        return prop

    def setter(self, fset: Callable[[T, Any], Any]):
        prop = type(self)(self.fget, fset, self.fdel, self.__doc__)
        prop._attrname = self._attrname
        return prop

    def deleter(self, fdel: Callable[[T], Any]):
        prop = type(self)(self.fget, self.fset, fdel, self.__doc__)
        prop._attrname = self._attrname
        return prop


class CachedClassInstanceProperty(ClassInstanceProperty):
    """一个基于 ``ClassInstanceProperty`` 的只读属性装饰器实现，
    其功能和 ``ClassInstanceProperty`` 一致，但为 ``getter()`` 增加了缓存功能：

    首次访问属性后，本装饰器会记录上一次调用 ``getter()`` 返回的结果；

    如果在下一次访问此属性之前，没有通过 ``setter()`` 或 ``deleter()``
    修改属性，那么 ``getter()`` 会使用上次访问时的返回结果；

    如果通过 ``setter()`` 或 ``deleter()`` 修改了属性，那么 ``getter()`` 会
    再次调用 ``fget()``，记录并返回其返回值。
    """

    def __init__(self,
                 fget: Callable[[T], RT] = None,
                 fset: Callable[[T, PT], None] = None,
                 fdel: Callable[[T], None] = None,
                 doc: str = None
                 ) -> None:
        super().__init__(fget, fset, fdel, doc)
        self._lock = RLock()

    def __get__(self, obj: T, objtype: Type[T] = None) -> RT:
        if not hasattr(self, '_last_instance'):
            self._last_instance = obj
        elif self._last_instance != obj and hasattr(self, '_last_fget_returns'):
            del self._last_fget_returns

        if not hasattr(self, '_last_fget_returns'):
            with self._lock:
                if not hasattr(self, '_last_fget_returns'):
                    self._last_fget_returns = super().__get__(obj, objtype)
                    return self._last_fget_returns
        else:
            return self._last_fget_returns

    def __set__(self, obj: T, value: PT) -> None:
        if hasattr(self, '_last_fget_returns'):
            with self._lock:
                if hasattr(self, '_last_fget_returns'):
                    del self._last_fget_returns
        super().__set__(obj, value)

    def __delete__(self, obj: T) -> None:
        if hasattr(self, '_last_fget_returns'):
            with self._lock:
                if hasattr(self, '_last_fget_returns'):
                    del self._last_fget_returns
        super().__delete__(obj)


def tobytes(byteslike: BytesLike) -> bytes:
    """尝试将 ``byteslike`` 转换为 ``bytes``。

    对 ``int`` 类型的对象不适用。如果输入这样的值，会触发 ``TypeError``。
    """
    if isinstance(byteslike, int):
        # 防止出现 bytes(1000) 这样的情况
        raise TypeError(f"a bytes-like object is required, not '{type(byteslike).__name__}'")
    elif isinstance(byteslike, bytes):
        return byteslike
    else:
        return bytes(byteslike)


def tobytearray(byteslike: BytesLike) -> bytearray:
    """尝试将 ``byteslike`` 转换为 ``bytearray``。

    对 ``int`` 类型的对象不适用。如果输入这样的值，会触发 ``TypeError``。
    """
    if isinstance(byteslike, int):
        # 防止出现 bytearray(1000) 这样的情况
        raise TypeError(f"a bytes-like object is required, not '{type(byteslike).__name__}'")
    elif isinstance(byteslike, bytearray):
        return byteslike
    else:
        return bytearray(byteslike)


def toint_nofloat(integerlike: IntegerLike) -> int:
    """尝试将 ``integerlike`` 转换为 ``int``。

    对 ``float`` 类型或拥有 ``__float__`` 属性的对象不适用。
    如果输入这样的值，会触发 ``TypeError``。
    """
    if isinstance(integerlike, float):
        raise TypeError(f"'{type(integerlike).__name__}' object cannot be interpreted as an integer")
    elif isinstance(integerlike, int):
        return integerlike
    else:
        return int(integerlike)


def is_filepath(obj) -> bool:
    """判断对象 ``obj`` 是否可以被视为文件路径。

    只有 ``str``、``bytes`` 类型，或者拥有 ``__fspath__``
    属性的对象，才会被视为文件路径。
    """
    return isinstance(obj, (str, bytes)) or hasattr(obj, '__fspath__')


def verify_fileobj(fileobj: IO[str | bytes],
                   mode: Literal['text', 'binary'],
                   *,
                   verify_readable: bool = True,
                   verify_writable: bool = False,
                   verify_seekable: bool = True,
                   ) -> IO[str | bytes]:
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

    return fileobj
