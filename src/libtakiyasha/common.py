# -*- coding: utf-8 -*-
from __future__ import annotations

try:
    import io
except ImportError:
    import _pyio as io

from .typedefs import *
from .typeutils import verify_cipher, ClassInstanceProperty, tobytes, toint_nofloat

__all__ = ['CipherSkel', 'BytesIOWithTransparentCryptLayer']


class CipherSkel:
    """为 Cipher 类提供的框架，本身没有任何实际功能。"""

    @ClassInstanceProperty
    def offset_related(self) -> bool:
        """此 Cipher 的加密/解密是否依赖于根据输入数据在文件中的具体位置。

        如果此属性为假值，那么 ``self.encrypt()`` 和 ``self.decrypt()``
        的 ``offset`` 参数可能会被忽略。
        """
        raise NotImplementedError

    @property
    def keys(self) -> list[str]:
        """一个字典，包括所有用到的密钥在此 Cipher 中的属性名称。

        可以用 ``getattr()`` 通过这里的名称获取到具体的密钥。
        """
        raise NotImplementedError

    def encrypt(self, plaindata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        """加密 ``plaindata`` 并返回加密结果。

        位置参数 ``offset`` 用于指定 ``plaindata`` 在文件中的位置，从而进行针对性的加密。

        如果 ``self.offset_related`` 为假值，``offset`` 的值可能会被忽略。
        """
        raise NotImplementedError

    def decrypt(self, cipherdata: BytesLike, offset: IntegerLike = 0, /) -> bytes:
        """解密 ``cipherdata`` 并返回加密结果。

        位置参数 ``offset`` 用于指定 ``cipherdata`` 在文件中的位置，从而进行针对性的解密。

        如果 ``self.offset_related`` 为假值，``offset`` 的值可能会被忽略。
        """
        raise NotImplementedError


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
