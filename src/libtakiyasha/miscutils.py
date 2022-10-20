# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Iterable, Mapping

from .typedefs import BytesLike, KT, T, VT
from .typeutils import tobytes

__all__ = [
    'bytestrxor',
    'getattribute'
]


def getattribute(obj: object,
                 name: str,
                 *default: T,
                 follow_callable: bool = False,
                 callable_args: Iterable = None,
                 callable_kwargs: Mapping | Iterable[tuple[KT, VT]] = None
                 ) -> T:
    """用法：``getattribute(object, name[, default][, follow_callable=...][, callable_args=...][, callable_kwargs=...]) -> value``

    ``getattribute()`` 的用法与 ``getattr()`` 基本一致。

    返回对象 ``obj`` 具名属性 ``name`` 的值。``name`` 必须是字符串。
    如果该字符串是对象的属性之一，则返回该属性的值。

    例如，``getattribute(x, 'foobar')`` 等同于 ``x.foobar``。

    如果指定的属性不存在，且提供了 ``default`` 值，则返回它，否则触发 ``AttributeError``。

    如果向 ``getattribute()`` 提供了关键字参数 ``follow_callable=True``，而且
    ``x.foobar`` 存在并且是一个可调对象（例如目标对象的一个方法），那么 ``getattribute()``
    会尝试获取该属性的返回值，作为 ``getattribute()`` 的返回值。

    Args:
        obj: 目标对象
        name: 目标属性的名字
        default: 可选，在目标对象不存在目标属性时，返回的默认值
        follow_callable: 若为真值，则在目标属性为可调对象时，返回调用该属性后的返回值
        callable_args: 可选，若目标属性为可调对象且
            follow_callable 为真值，调用该属性时传入的位置参数
        callable_kwargs: 可选，若目标属性为可调对象且
            follow_callable 为真值，调用该属性时传入的关键字参数
    """
    if len(default) > 1:
        raise TypeError(f'getattribute expected at most 3 arguments, got {2 + len(default)}')
    else:
        attr = getattr(obj, name, *default)

    if callable_args is None:
        callable_args = ()
    else:
        callable_args = tuple(callable_kwargs)
    if callable_kwargs is None:
        callable_kwargs = {}
    else:
        callable_kwargs = dict(callable_kwargs)

    if callable(attr) and bool(follow_callable):
        return attr(*callable_args, **callable_kwargs)
    return attr


def bytestrxor(term1: BytesLike, term2: BytesLike, /) -> bytes:
    """用法：``bytestrxor(term1, term2) -> xored_bytes``

    返回两个字节对象或类字节对象 ``term1`` 和 ``term2`` 经过异或之后的结果。

    ``term1`` 和 ``term2`` 在转换为 ``bytes`` 之后的长度必须相等，否则会触发
    ``ValueError``。
    """
    bytestring1 = tobytes(term1)
    bytestring2 = tobytes(term2)

    if len(bytestring1) != len(bytestring2):
        raise ValueError('only byte strings of equal length can be xored')

    return bytes(b1 ^ b2 for b1, b2 in zip(bytestring1, bytestring2))
