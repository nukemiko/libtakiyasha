# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from functools import lru_cache
from typing import Generator, Iterable, Literal

from .miscutils import bytestrxor

try:
    import io
except ImportError:
    import _pyio as io

from .typedefs import IntegerLike, BytesLike, WritableBuffer
from .typeutils import tobytes, toint_nofloat

__all__ = [
    'CipherSkel',
    'StreamCipherSkel',
    'CryptLayerWrappedIOSkel'
]


class CipherSkel(metaclass=ABCMeta):
    """适用于一般加密算法的框架类。子类必须实现 ``encrypt()`` 和 ``decrypt()`` 方法。"""

    @abstractmethod
    def encrypt(self, plaindata: BytesLike, /) -> bytes:
        """加密明文 ``plaindata`` 并返回加密结果。

        Args:
            plaindata: 要加密的明文
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, cipherdata: BytesLike, /) -> bytes:
        """解密密文 ``cipherdata`` 并返回解密结果。

        Args:
            cipherdata: 要解密的密文
        """
        raise NotImplementedError


class StreamCipherSkel(metaclass=ABCMeta):
    """适用于简单流式加密算法的框架类。子类必须实现 ``keystream()`` 方法。"""

    @abstractmethod
    def keystream(self, offset: IntegerLike, length: IntegerLike, /) -> Generator[int, None, None]:
        """返回一个生成器对象，对其进行迭代，即可得到从起始点
        ``offset`` 开始，持续一定长度 ``length`` 的密钥流。

        Args:
            offset: 密钥流的起始点，不应为负数
            length: 密钥流的长度，不应为负数
        """
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        """加密明文 ``plaindata`` 并返回加密结果。

        Args:
            plaindata: 要加密的明文
            offset: 明文在文件中的位置（偏移量），不应为负数
        """
        plaindata = tobytes(plaindata)
        offset = toint_nofloat(offset)

        return bytestrxor(plaindata, self.keystream(offset, len(plaindata)))

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        """解密密文 ``cipherdata`` 并返回解密结果。

        Args:
            cipherdata: 要解密的密文
            offset: 密文在文件中的位置（偏移量），不应为负数
        """
        cipherdata = tobytes(cipherdata)
        offset = toint_nofloat(offset)

        return bytestrxor(cipherdata, self.keystream(offset, len(cipherdata)))


class CryptLayerWrappedIOSkel(io.BytesIO):
    """基于 BytesIO 的透明加密二进制流。

    所有读写相关方法都会经过透明加密层处理：
    读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

    调用读写相关方法时，附加参数 ``nocryptlayer=True``
    可绕过透明加密层，访问缓冲区内的原始加密数据。

    ``__init__()`` 方法的第一个位置参数 ``cipher`` 必须拥有
    ``encrypt()``、``decrypt()`` 和 ``keystream()`` 方法，且这些方法必须能接受两个位置参数。
    其中，``encrypt()`` 和 ``decrypt()`` 的第一个位置参数接受字节对象，第二个位置参数接受非负整数；
    ``keystream()`` 的两个位置参数均只接受非负整数。

    如果 ``cipher`` 未实现这些方法中的任何一个，都需要明确抛出 ``NotImplementedError``。
    未实现的 ``encrypt()``/``decrypt()`` 方法会导致创建的对象不可通过透明加密层读/写；
    未实现的 ``keystream()`` 方法不会影响对读写的支持，但可能会极大影响读取的速度。

    ``__init__()`` 方法的第二个参数 ``initial_bytes``
    会在转换为 ``bytes`` 后作为对象内置缓冲区的初始数据。

    基于本类的子类可能拥有自己的构造器方法或函数，而不是直接调用
    ``__init__()``；详情请参考该类的文档字符串。

    本类和基于本类的子类，同时兼容 ``IO[bytes]``
    和 ``typedefs.StreamCipherBasedCryptedIOProto`` 类型。
    """

    @property
    def name(self) -> str | None:
        """当前对象来源文件的路径。

        在此类的对象中，此属性总是 ``None``。

        如果是通过子类的构造器方法或函数创建的对象，此属性可能会为来源文件的路径字符串。
        """
        if hasattr(self, '_name'):
            name: str = self._name
            return name

    @property
    def encryptable(self) -> bool:
        """此对象的内置透明加密层是否支持加密（内置 ``Cipher`` 对象的 ``encrypt()`` 方法是否可用）。

        这会影响到写入相关方法在参数 ``nocryptlayer=False`` 时是否可用。
        """
        return self._encrypt_available

    @property
    def decryptable(self) -> bool:
        """此对象的内置透明加密层是否支持解密（内置 ``Cipher`` 对象的 ``decrypt()`` 方法是否可用）。

        这会影响到读取相关方法在参数 ``nocryptlayer=False`` 时是否可用，以及此对象是否可迭代。
        """
        return self._decrypt_available

    @property
    def iter_nocryptlayer(self) -> bool:
        """迭代当前对象时，是否需要绕过透明加密层。默认为 ``False``。"""
        return self._iter_nocryptlayer

    @iter_nocryptlayer.setter
    def iter_nocryptlayer(self, value: bool):
        self._iter_nocryptlayer = bool(value)

    @property
    def iter_mode(self) -> Literal['block', 'line']:
        """迭代的模式，只能设置为 ``block`` 或 ``line``：

        - ``block``（默认值）- 以块为单位进行迭代：每次迭代时，返回等长的“一块”数据。
            - 每次迭代返回的数据长度由 ``self.iter_block_size`` 决定。
        - ``line`` - 以一行为单位进行迭代：每次迭代时，返回的数据都以 ``b'\\n'`` 结尾。
            - 此模式会极大降低迭代的速度，不推荐使用。

        尝试设置为其他值会触发 ``ValueError`` 或 ``TypeError``。
        """
        return self._iter_mode

    @iter_mode.setter
    def iter_mode(self, value: Literal['block', 'line']) -> None:
        if value in ('block', 'line'):
            self._iter_mode = value
        elif isinstance(value, str):
            raise ValueError(f"attribute 'iter_mode' must be 'block' or 'line', not '{value}'")
        else:
            raise TypeError(f"attribute 'iter_mode' must be str, not {type(value).__name__}")

    @property
    def iter_block_size(self) -> int:
        """以块为单位进行迭代时，每次迭代返回的数据长度。

        如果尝试设置为负数，会触发 ``ValueError``。

        本属性不会影响以一行为单位进行的迭代。
        """
        return self._iter_block_size

    @iter_block_size.setter
    def iter_block_size(self, value: IntegerLike) -> None:
        size = toint_nofloat(value)
        if size < 0:
            raise ValueError("attribute 'iter_block_size' cannot be a negative integer")
        self._iter_block_size = size

    def __init__(self, cipher, /, initial_bytes: BytesLike = b'') -> None:
        """基于 BytesIO 的透明加密二进制流。

        所有读写相关方法都会经过透明加密层处理：
        读取时，返回解密后的数据；写入时，向缓冲区写入加密后的数据。

        调用读写相关方法时，附加参数 ``nocryptlayer=True``
        可绕过透明加密层，访问缓冲区内的原始加密数据。

        ``__init__()`` 方法的第一个位置参数 ``cipher`` 必须拥有
        ``encrypt()``、``decrypt()`` 和 ``keystream()`` 方法，且这些方法必须能接受两个位置参数。
        其中，``encrypt()`` 和 ``decrypt()`` 的第一个位置参数接受字节对象，第二个位置参数接受非负整数；
        ``keystream()`` 的两个位置参数均只接受非负整数。

        如果 ``cipher`` 未实现这些方法中的任何一个，都需要明确抛出 ``NotImplementedError``。
        未实现的 ``encrypt()``/``decrypt()`` 方法会导致创建的对象不可通过透明加密层读/写；
        未实现的 ``keystream()`` 方法不会影响对读写的支持，但可能会极大影响读取的速度。

        ``__init__()`` 方法的第二个参数 ``initial_bytes``
        会在转换为 ``bytes`` 后作为对象内置缓冲区的初始数据。

        基于本类的子类可能拥有自己的构造器方法或函数，而不是直接调用
        ``__init__()``；详情请参考该类的文档字符串。

        本类和基于本类的子类，同时兼容 ``IO[bytes]``
        和 ``typedefs.StreamCipherBasedCryptedIOProto`` 类型。
        """
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
        # 检测 keystream() 是否已实现（可用）
        self._keystream_available = True
        try:
            cipher.keystream(0, 0)
        except NotImplementedError:
            self._keystream_available = False
        # 检测 encrypt() 是否已实现（可用）
        self._encrypt_available = True
        try:
            cipher.encrypt(b'', 0)
        except NotImplementedError:
            self._encrypt_available = False
        # 检测 decrypt() 是否已实现（可用）
        self._decrypt_available = True
        try:
            cipher.decrypt(b'', 0)
        except NotImplementedError:
            self._decrypt_available = False

        self._cipher = cipher
        self._iter_nocryptlayer = False
        self._iter_mode: Literal['block', 'line'] = 'block'
        self._iter_block_size: int = io.DEFAULT_BUFFER_SIZE

    def __iter__(self):
        return self

    def __next__(self) -> bytes:
        if self._iter_mode == 'line':
            if self._iter_nocryptlayer:
                return super().__next__()
            elif not self._decrypt_available:
                raise io.UnsupportedOperation('iter with crypt layer')
            else:
                curpos = self.tell()

                target_data = super().getvalue()[curpos:]
                if self._keystream_available:
                    result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=b'\n'))
                else:
                    result_data = bytearray()
                    start = curpos
                    while 1:
                        stop = start + self._iter_block_size
                        target_data_segment = target_data[start:stop]
                        if target_data_segment == b'':
                            break
                        d = self._cipher.decrypt(target_data_segment, start)
                        if b'\n' in d:
                            result_data.append(d[:d.index(b'\n')])
                            break
                        else:
                            result_data.append(d)
                            start += self._iter_block_size
                if result_data == b'':
                    raise StopIteration

                self.seek(curpos + len(result_data), 0)

                return result_data
        elif self._iter_mode == 'block':
            if not self._decrypt_available:
                raise io.UnsupportedOperation('iter with crypt layer')

            curpos = self.tell()

            target_data = super().getvalue()[curpos:curpos + self._iter_block_size]
            if self._iter_nocryptlayer:
                result_data = target_data
            elif self._keystream_available:
                result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=None))
            else:
                result_data = bytes(self._cipher.decrypt(target_data, curpos))

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
        repr_strings = [
            f'<{type(self).__module__}.{type(self).__name__} object',
            f' at {hex(id(self))}',
            f', cipher={repr(self._cipher)}'
        ]
        if self.name is not None:
            repr_strings.append(f", from '{self.name}'")
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

        if data == b'':
            return

        keystream = self._cipher.keystream(offset, len(data))
        for databyteord, streambyteord in zip(data, keystream):
            resultbyteord = databyteord ^ streambyteord
            yield resultbyteord
            if resultbyteord == eoford:
                return

    def getvalue(self, nocryptlayer: bool = False) -> bytes:
        if nocryptlayer:
            return super().getvalue()
        elif not self._decrypt_available:
            raise io.UnsupportedOperation('getvalue with crypt layer')
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
        elif not self._decrypt_available:
            raise io.UnsupportedOperation('read with crypt layer')
        else:
            curpos = self.tell()
            if size is None:
                size = -1
            size = toint_nofloat(size)
            if size < 0:
                target_data = super().getvalue()[curpos:]
            else:
                target_data = super().getvalue()[curpos:curpos + size]

            if self._keystream_available:
                result_data = bytes(self._xor_data_keystream(curpos, target_data))
            else:
                result_data = self._cipher.decrypt(target_data, curpos)
            self.seek(curpos + len(result_data), 0)

            return result_data

    def readinto(self, buffer: WritableBuffer, /, nocryptlayer: bool = False) -> int:
        if nocryptlayer:
            return super().readinto(buffer)
        elif not self._decrypt_available:
            raise io.UnsupportedOperation('readinto with crypt layer')
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
        if nocryptlayer or self._decrypt_available:
            return self.read(size, nocryptlayer)

        raise io.UnsupportedOperation('read1 with crypt layer')

    def readinto1(self, buffer: WritableBuffer, /, nocryptlayer: bool = False) -> int:
        if nocryptlayer or self._decrypt_available:
            return self.readinto(buffer, nocryptlayer)

        raise io.UnsupportedOperation('readinto1 with crypt layer')

    def readblock(self,
                  size: IntegerLike | None = -1, /,
                  nocryptlayer: bool = False, *,
                  block_size: IntegerLike | None = io.DEFAULT_BUFFER_SIZE
                  ) -> bytes:
        if not self._decrypt_available:
            raise io.UnsupportedOperation('readblock with crypt layer')

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
            target_data = super().getvalue()[curpos:curpos + block_size]
        else:
            target_data = super().getvalue()[curpos:curpos + min([size, block_size])]

        if nocryptlayer:
            result_data = target_data
        elif self._keystream_available:
            result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=None))
        else:
            result_data = self._cipher.decrypt(target_data, curpos)

        self.seek(curpos + len(result_data), 0)

        return result_data

    def readline(self, size: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> bytes:
        if nocryptlayer:
            return super().readline(size)
        else:
            if not self._decrypt_available:
                raise io.UnsupportedOperation('readline with crypt layer')
            curpos = self.tell()
            if size is None:
                size = -1
            size = toint_nofloat(size)
            if size < 0:
                target_data = super().getvalue()[curpos:]
            else:
                target_data = super().getvalue()[curpos:curpos + size]

            if self._keystream_available:
                result_data = bytes(self._xor_data_keystream(curpos, target_data, eof=b'\n'))
            else:
                result_data = bytearray()
                start = curpos
                while 1:
                    stop = start + self._iter_block_size
                    target_data_segment = target_data[start:stop]
                    if target_data_segment == b'':
                        break
                    d = self._cipher.decrypt(target_data_segment, start)
                    if b'\n' in d:
                        result_data.append(d[:d.index(b'\n')])
                        break
                    else:
                        result_data.append(d)
                        start += self._iter_block_size
            self.seek(curpos + len(result_data), 0)

            return bytes(result_data)

    def readlines(self, hint: IntegerLike | None = -1, /, nocryptlayer: bool = False) -> list[bytes]:
        if nocryptlayer:
            return super().readlines(hint)
        elif not self._decrypt_available:
            raise io.UnsupportedOperation('readlines with crypt layer')
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
        elif not self._encrypt_available:
            raise io.UnsupportedOperation('write with crypt layer')
        else:
            curpos = self.tell()
            return super().write(self._cipher.encrypt(data, curpos))

    def writelines(self, lines: Iterable[BytesLike], /, nocryptlayer: bool = False) -> None:
        if nocryptlayer:
            return super().writelines(lines)
        elif not self._encrypt_available:
            raise io.UnsupportedOperation('writelines with crypt layer')
        else:
            for line in lines:
                super().write(line)
