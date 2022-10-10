# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Iterable, Mapping

from .typeutils import *
from ..typedefs import *

__all__ = ['bytestrxor', 'getattribute', 'verify_literally_match', 'select']


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


def verify_literally_match(literals: Iterable[str],
                           string: str,
                           string_field_name: str = None
                           ) -> str:
    """判断目标字符串 ``string`` 是否在字符串列表 ``literals`` 中。

    ``literals`` 里的元素必须全都是 ``str`` 类型对象，否则会触发 ``TypeError``。

    ``literals`` 里的元素数量不可为 0，否则会触发 ``ValueError``。
    """
    if not all(literals_list := [isinstance(value := _, str) for _ in literals]):
        raise TypeError(f"elements in 'literals' must be str, not {type(value).__name__}")
    if element_counts := len(literals_list) == 0:
        raise ValueError(f"'literals' is empty, no literal will be matched")
    if not isinstance(string, str):
        if string_field_name is None:
            raise TypeError(f"target string 'string' must be str, not {type(string).__name__}")
        else:
            raise TypeError(f"'{string_field_name}' must be str, not {type(string).__name__}")

    if string in literals_list:
        return string
    elif element_counts == 1:
        raise_msg = f"{{target_name}} must be '{literals_list[-1]}', not '{string}'"
    else:
        literals_list_left = literals_list[:-1]
        literals_list_left_in_msg = ', '.join([f"'{_}'" for _ in literals_list_left])
        raise_msg = f"{{target_name}} must be either {literals_list_left_in_msg} or '{literals_list[-1]}', not '{string}'"

    raise ValueError(
        raise_msg.format(
            "target string 'string'" if string_field_name is None else f"'{string_field_name}'"
        )
    )


def select(selections: Mapping[str, VT],
           string: str,
           string_field_name: str = None
           ) -> VT:
    return dict(selections)[verify_literally_match(selections, string, string_field_name)]
