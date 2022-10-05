# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import IO, Iterable, SupportsBytes


def bytestrxor(bytestr1: SupportsBytes | Iterable[int],
               bytestr2: SupportsBytes | Iterable[int],
               /
               ) -> bytes:
    bytestr1 = bytes(bytestr1)
    bytestr2 = bytes(bytestr2)

    if len(bytestr1) != len(bytestr2):
        raise ValueError('only byte strings of equal length can be xored')

    return bytes(b1 ^ b2 for b1, b2 in zip(bytestr1, bytestr2))


def is_filepath(obj) -> bool:
    return isinstance(obj, (str, bytes)) or hasattr(obj, '__fspath__')


def verify_fileobj(obj,
                   *,
                   verify_binary_mode: bool = True,
                   verify_read: bool = True,
                   verify_write: bool = False,
                   verify_seek: bool = True
                   ) -> IO[bytes]:
    if verify_read:
        try:
            b = obj.read(0)
        except Exception as exc:
            if not hasattr(obj, 'read'):
                raise TypeError(f"{repr(obj)} is not a file object")
            raise ValueError(f"cannot read from file object {repr(obj)}") from exc
        else:
            if verify_binary_mode:
                if not isinstance(b, bytes):
                    raise ValueError(f"file object '{repr(obj)}' is not open in binary mode")

    if verify_write:
        try:
            obj.write(b'')
        except TypeError as exc:
            raise ValueError(f"file object '{repr(obj)}' is not open in binary mode") from exc
        except Exception as exc:
            if not hasattr(obj, 'write'):
                raise TypeError(f"{repr(obj)} is not a file object")
            raise ValueError(f"cannot write to file object {repr(obj)}") from exc

    if verify_seek:
        try:
            obj.seek(0, 1)
        except Exception as exc:
            if not hasattr(obj, 'seek'):
                raise TypeError(f"{repr(obj)} is not a file object")
            raise ValueError(f"cannot seek in file object {repr(obj)}") from exc

    return obj
