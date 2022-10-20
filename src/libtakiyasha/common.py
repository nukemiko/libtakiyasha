# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from functools import lru_cache
from threading import Lock
from typing import Generator, Iterable, Literal

from .miscutils import bytestrxor

try:
    import io
except ImportError:
    import _pyio as io

from .typedefs import IntegerLike, BytesLike, Cipher, WritableBuffer
from .typeutils import verify_cipher, tobytes, toint_nofloat

__all__ = [
    'BytesIOWithTransparentCryptLayer',
    'CipherSkel',
    'StreamCipherSkel',
    'CryptLayerWrappedIOSkel'
]


# class CipherSkel:
#     """为 Cipher 类提供的框架，本身没有任何实际功能。"""
# 
#     @ClassInstanceProperty
#     def offset_related(self) -> bool:
#         """此 Cipher 的加密/解密是否依赖于根据输入数据在文件中的具体位置。
# 
#         如果此属性为假值，那么 ``self.encrypt()`` 和 ``self.decrypt()``
#         的 ``offset`` 参数可能会被忽略。
#         """
#         raise NotImplementedError
# 
#     @property
#     def keys(self) -> list[str]:
#         """一个字典，包括所有用到的密钥在此 Cipher 中的属性名称。
# 
#         可以用 ``getattr()`` 通过这里的名称获取到具体的密钥。
#         """
#         raise NotImplementedError
# 
#     def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
#         """加密 ``plaindata`` 并返回加密结果。
# 
#         位置参数 ``offset`` 用于指定 ``plaindata`` 在文件中的位置，从而进行针对性的加密。
# 
#         如果 ``self.offset_related`` 为假值，``offset`` 的值可能会被忽略。
#         """
#         raise NotImplementedError
# 
#     def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
#         """解密 ``cipherdata`` 并返回加密结果。
# 
#         位置参数 ``offset`` 用于指定 ``cipherdata`` 在文件中的位置，从而进行针对性的解密。
# 
#         如果 ``self.offset_related`` 为假值，``offset`` 的值可能会被忽略。
#         """
#         raise NotImplementedError


class BytesIOWithTransparentCryptLayer(io.BytesIO):
    """一个基于 BytesIO 的透明加密 IO 类实现，
    所有的读写操作都将通过一个透明加密层进行。
    """

    @property
    def cipher(self):
        """当前对象使用的 Cipher。"""
        return self._cipher

    @property
    def name(self) -> str | None:
        """一个文件路径，指向当前对象中的数据来源。

        如果当前对象中的数据来自另一个文件对象，且这个文件对象的属性 ``name``
        为 ``None`` 或不存在，那么访问此属性也会得到 ``None``。
        """
        return getattr(self, '_name', None)

    @property
    def master_key(self) -> bytes:
        raise NotImplementedError

    def __init__(self, cipher: Cipher, /, initial_data: BytesLike = b''):
        """一个基于 BytesIO 的透明加密 IO 类实现，
        所有的读写操作都将通过一个透明加密层进行。

        必须提供一个 Cipher 对象作为第一个位置参数。

        Args:
            cipher: 加密/解密所需的 Cipher 对象
            initial_data: 包含初始已加密数据的类字节对象
        """
        super(BytesIOWithTransparentCryptLayer, self).__init__(tobytes(initial_data))

        self._cipher = verify_cipher(cipher)

    def getvalue(self, nocryptlayer: bool = False) -> bytes:
        """获取对象内部缓冲区里的所有数据。

        获取到的数据会在返回之前解密，但如果提供了参数
        ``nocryptlayer=True``，则会返回原始的加密数据。"""
        value = super(BytesIOWithTransparentCryptLayer, self).getvalue()
        if nocryptlayer:
            return value
        else:
            return self._cipher.decrypt(value)

    def getbuffer(self, nocryptlayer: bool = False) -> memoryview:
        """获取与对象内部缓冲区相对应的可读写 memoryview。

        此方法与其他方法不同：由于技术限制，无法为返回的 memoryview
        添加透明加密层。因此，除非提供参数 ``nocryptlayer=True``，否则会触发
        ``NotImplementedError``。
        """
        memview = super(BytesIOWithTransparentCryptLayer, self).getbuffer()
        if nocryptlayer:
            return memview
        else:
            raise NotImplementedError('memoryview with transparent crypt layer support '
                                      'is not implemented'
                                      )

    def read(self, size: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> bytes:
        """读取、解密并返回最多 ``size`` 大小的数据。

        如果位置参数 ``size`` 被忽略，或者为 ``None``、负数，
        则从当前流的位置开始，读取、解密并返回到 EOF 的所有数据。

        如果当前流的位置已经位于 EOF，或没有可用数据，则返回空字节。

        如果提供参数 ``nocryptlayer=True``，将返回原始的加密数据。
        """
        if size is None:
            size = -1
        else:
            size = toint_nofloat(size)
        if nocryptlayer:
            return super(BytesIOWithTransparentCryptLayer, self).read(size)
        else:
            curpos = self.tell()
            return self._cipher.decrypt(
                super(BytesIOWithTransparentCryptLayer, self).read(size), curpos
            )

    def read1(self, size: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> bytes:
        """读取、解密并返回最多 ``size`` 大小的数据。

        如果位置参数 ``size`` 被忽略，或者为 ``None``、负数，
        则从当前流的位置开始，读取、解密并返回到 EOF 的所有数据。

        如果当前流的位置已经位于 EOF，或没有可用数据，则返回空字节。

        如果提供参数 ``nocryptlayer=True``，将返回原始的加密数据。
        """
        return self.read(size, nocryptlayer)

    def write(self, data: BytesLike, /, nocryptlayer: bool = False) -> int:
        """加密并写入数据。

        如果提供参数 ``nocryptlayer=True``，将会跳过加密过程，直接写入数据。
        如果错误使用此参数，缓冲区的数据可能会受到破坏。
        """
        data = tobytes(data)
        if nocryptlayer:
            return super(BytesIOWithTransparentCryptLayer, self).write(data)
        else:
            curpos = self.tell()
            return super(BytesIOWithTransparentCryptLayer, self).write(
                self._cipher.encrypt(data, curpos)
            )

    def seek(self, offset: IntegerLike, whence: IntegerLike = 0) -> int:
        """改变流的位置，到相对于 ``whence`` 指示位置的字节偏移量 ``offset``：
            - ``whence=0`` - 流的起点（默认值），``offset`` 应当大于等于 0
            - ``whence=1`` - 当前流的位置，``offset`` 可能小于 0
            - ``whence=2`` - 流的终点，``offset`` 通常都小于 0
        之后返回新的绝对位置。
        """
        return super(BytesIOWithTransparentCryptLayer, self).seek(
            toint_nofloat(offset), toint_nofloat(whence)
        )

    def truncate(self, size: IntegerLike | None = None, /) -> int:
        """将流截断到最多 ``size`` 大小。

        如果 ``size`` 被忽略或为 ``None``，默认为当前流的位置（可由 ``tell()`` 获得）。
        当前流位置不变。

        返回新的流大小。
        """
        if size is None:
            size = self.tell()
        else:
            size = toint_nofloat(size)

        return super(BytesIOWithTransparentCryptLayer, self).truncate(size)


class CipherSkel(metaclass=ABCMeta):
    @abstractmethod
    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        """加密 ``plaindata`` 并返回加密结果。"""
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        """解密 ``cipherdata`` 并返回加密结果。"""
        raise NotImplementedError


class StreamCipherSkel(metaclass=ABCMeta):
    @abstractmethod
    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        plaindata = tobytes(plaindata)
        offset = toint_nofloat(offset)

        return bytestrxor(plaindata, self.keystream(offset, len(plaindata)))

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        cipherdata = tobytes(cipherdata)
        offset = toint_nofloat(offset)

        return bytestrxor(cipherdata, self.keystream(offset, len(cipherdata)))


class CryptLayerWrappedIOSkel(io.BytesIO):
    @property
    def name(self) -> str | None:
        if hasattr(self, '_name'):
            name: str = self._name
            return name

    @property
    def iter_nocryptlayer(self) -> bool:
        return self._iter_nocryptlayer

    @iter_nocryptlayer.setter
    def iter_nocryptlayer(self, value: bool):
        self._iter_nocryptlayer = bool(value)

    @property
    def iter_mode(self) -> Literal['block', 'line']:
        return self._iter_mode

    @property
    def iter_block_size(self) -> int:
        return self._iter_block_size

    @iter_block_size.setter
    def iter_block_size(self, value: IntegerLike) -> None:
        self._iter_block_size = toint_nofloat(value)

    @iter_mode.setter
    def iter_mode(self, value: Literal['block', 'line']) -> None:
        if value in ('block', 'line'):
            self._iter_mode = value
        elif isinstance(value, str):
            raise ValueError(f"attribute 'iter_mode' must be 'block' or 'line', not '{value}'")
        else:
            raise TypeError(f"attribute 'iter_mode' must be str, not {type(value).__name__}")

    def __init__(self, cipher, /, initial_bytes: BytesLike = b'') -> None:
        super().__init__(tobytes(initial_bytes))

        for method_name in 'keystream', 'encrypt', 'decrypt':
            try:
                method = getattr(cipher, method_name)
            except Exception as exc:
                if hasattr(cipher, method_name):
                    raise exc
                else:
                    raise TypeError(f"{repr(cipher)} is not a StreamCipher object: "
                                    f"method '{method_name}' is missing"
                                    )
            if not callable(method):
                raise TypeError(f"{repr(cipher)} is not a StreamCipher object: "
                                f"method '{method_name}' is not callable"
                                )
        self._cipher = cipher
        self._iter_nocryptlayer = False
        self._iter_mode: Literal['block', 'line'] = 'block'
        self._iter_block_size: int = io.DEFAULT_BUFFER_SIZE
        self._lock = Lock()

    def __iter__(self):
        return self

    def __next__(self):
        if self._iter_mode == 'line':
            if self._iter_nocryptlayer:
                return super().__next__()
            else:
                curpos = self.tell()

                target_data = super().getvalue()[curpos:]
                result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=b'\n'))

                if result_data == b'':
                    raise StopIteration

                self.seek(curpos + len(result_data), 0)

                return result_data
        elif self._iter_mode == 'block':
            curpos = self.tell()

            target_data = super().getvalue()[curpos:curpos + self._iter_block_size]
            if self._iter_nocryptlayer:
                result_data = target_data
            else:
                result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=None))

            if result_data == b'':
                raise StopIteration

            self.seek(curpos + len(result_data), 0)

            return result_data
        elif isinstance(self._iter_mode, str):
            raise ValueError(f"attribute 'iter_mode' must be 'block' or 'line', not '{self._iter_mode}'")
        else:
            raise TypeError(f"attribute 'iter_mode' must be str, not {type(self._iter_mode).__name__}")

    @lru_cache
    def __repr__(self) -> str:
        repr_strings = ['<', f'{type(self).__module__}.{type(self).__name__}', f' at {hex(id(self))}']
        if self.name is not None:
            repr_strings.append(f" from '{self.name}'")
        repr_strings.append('>')

        return ''.join(repr_strings)

    def _xor_data_keystream(self,
                            offset: int,
                            data: bytes,
                            eof: bytes = None
                            ) -> Generator[int, None, None]:
        if eof is None:
            eoford = None
        else:
            eoford = ord(tobytes(eof))

        keystream = self._cipher.keystream(offset, len(data))
        for databyteord, streambyteord in zip(data, keystream):
            resultbyteord = databyteord ^ streambyteord
            yield resultbyteord
            if resultbyteord == eoford:
                return

    def getvalue(self, nocryptlayer: bool = False) -> bytes:
        if nocryptlayer:
            return super().getvalue()
        else:
            return self._cipher.decrypt(super().getvalue())

    def getbuffer(self, nocryptlayer: bool = False) -> memoryview:
        if nocryptlayer:
            return super().getbuffer()
        else:
            raise NotImplementedError('memoryview with crypt layer is not supported')

    def read(self, size: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> bytes:
        if nocryptlayer:
            return super().read(size)
        else:
            curpos = self.tell()
            if size is None:
                size = -1
            size = toint_nofloat(size)
            if size < 0:
                target_data = super().getvalue()[curpos:]
            else:
                target_data = super().getvalue()[curpos:curpos + size]

            result_data = bytes(self._xor_data_keystream(curpos, target_data))
            self.seek(curpos + len(result_data), 0)

            return result_data

    def readinto(self, buffer: WritableBuffer, /, nocryptlayer: bool = False) -> int:
        if nocryptlayer:
            return super().readinto(buffer)
        else:
            if isinstance(buffer, memoryview):
                memview = buffer
            else:
                memview = memoryview(buffer)
            memview = memview.cast('B')

            data = self.read(len(memview))
            data_len = len(data)

            memview[:data_len] = data

            return data_len

    def read1(self, size: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> bytes:
        return self.read(size, nocryptlayer)

    def readblock(self,
                  size: IntegerLike | None = -1, /,
                  nocryptlayer: bool = False, *,
                  block_size: IntegerLike | None = io.DEFAULT_BUFFER_SIZE
                  ) -> bytes:
        curpos = self.tell()
        if size is None:
            size = -1
        size = toint_nofloat(size)
        if block_size is None:
            block_size = io.DEFAULT_BUFFER_SIZE
        block_size = toint_nofloat(block_size)
        if block_size < 0:
            block_size = io.DEFAULT_BUFFER_SIZE
        if size < 0:
            target_data = super().getvalue()[curpos:block_size]
        else:
            target_data = super().getvalue()[curpos:curpos + min([size, block_size])]

        if nocryptlayer:
            result_data = target_data
        else:
            result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=None))

        self.seek(curpos + len(result_data), 0)

        return result_data

    def readline(self, size: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> bytes:
        if nocryptlayer:
            return super().readline(size)
        else:
            curpos = self.tell()
            if size is None:
                size = -1
            size = toint_nofloat(size)
            if size < 0:
                target_data = super().getvalue()[curpos:]
            else:
                target_data = super().getvalue()[curpos:curpos + size]

            result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=b'\n'))
            self.seek(curpos + len(result_data), 0)

            return result_data

    def readlines(self, hint: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> list[bytes]:
        if nocryptlayer:
            return super().readlines(hint)
        else:
            results_lines = []
            if hint is None:
                hint = -1
            hint = toint_nofloat(hint)
            if hint < 0:
                while 1:
                    line = self.readline()
                    if line == b'':
                        return results_lines
                    results_lines.append(line)
            else:
                for _ in range(hint):
                    line = self.readline()
                    if line == b'':
                        return results_lines
                    results_lines.append(line)

    def write(self, data: BytesLike, /, nocryptlayer: bool = False) -> int:
        if nocryptlayer:
            return super().write(data)
        else:
            curpos = self.tell()
            return super().write(self._cipher.encrypt(data, curpos))

    def writelines(self, lines: Iterable[BytesLike], /, nocryptlayer: bool = False) -> None:
        if nocryptlayer:
            return super().writelines(lines)
        else:
            for line in lines:
                super().write(line)
