# LibTakiyasha ![](https://img.shields.io/badge/Python-3.8%2B-blue)

LibTakiyasha 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。**LibTakiyasha 不提供任何命令行或图形界面支持。**

## 使用前必读

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于同类项目：

-   [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/cli)
-   [parakeet-rs/libparakeet](https://github.com/parakeet-rs/libparakeet)

**本项目不内置任何密钥，要正常打开/保存任何类型的加密文件，你需要提供正确的对应的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

如果你要解密别人提供的文件，你可以从提供者处索要密钥，或者寻求同类项目和他人的帮助。

**LibTakiyasha 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---

## 特性

-   使用纯 Python 代码编写
    -   **兼容 Python 3.8 及后续版本**，兼容多种 Python 解释器实现（见下文 [#性能测试](#性能测试)）
    -   易于阅读，方便 Python 爱好者学习
    -   （包括依赖库）无任何 C/C++ 扩展模块，跨平台性强

### 性能测试

由于 Python 语言自身原因，LibTakiyasha 相较于同类项目，运行速度较慢。因此我们使用不同解释器实现，对常用操作做了一些性能测试：

|      操作      | 测试大小 | Python 3.10.9 (CPython) | Python 3.8.12 (Pyston 2.3.5) | Python 3.9.16 (PyPy 7.3.11) |
| :------------: | :------: | :---------------------: | :--------------------------: | :-------------------------: |
|    NCM 加密    | 36.8 MiB |         4.159s          |            2.159s            |           1.366s            |
|    NCM 解密    | 36.8 MiB |         4.393s          |            2.360s            |           1.480s            |
|   QMCv1 加密   | 36.8 MiB |         3.841s          |            2.116s            |           1.594s            |
|   QMCv1 解密   | 36.8 MiB |         3.813s          |            2.331s            |           1.406s            |
| QMCv2 掩码加密 | 36.8 MiB |         4.065s          |            2.201s            |           1.727s            |
| QMCv2 掩码解密 | 36.8 MiB |         3.990s          |            2.200s            |           1.848s            |
| QMCv2 RC4 加密 | 36.8 MiB |         12.820s         |            5.596s            |           2.717s            |
| QMCv2 RC4 解密 | 36.8 MiB |         12.588s         |            5.913s            |           2.552s            |
|    KGM 解密    | 64.4 MiB |         49.014s         |           22.053s            |           8.376s            |
|    VPR 解密    | 87.9 MiB |         70.030s         |           32.252s            |           11.902s           |

仅在你对速度有要求时，可以考虑在调用 LibTakiyasha 时使用 PyPy/Pyston 解释器。

一般情况下，建议使用官方解释器实现（CPython）。

## 安装

可用的最新版本：2.1.0rc2，可前往[发布页面](https://github.com/nukemiko/libtakiyasha/releases/tag/2.1.0rc2)或 [PyPI](https://pypi.org/project/libtakiyasha/2.1.0rc2/) 下载。

如果你要下载其他版本：

-   PyPI：https://pypi.org/project/libtakiyasha/#history ，挑选自己所需的版本，下载安装包，手动安装。
    -   或者使用 pip 安装：`python -m pip install -U libtakiyasha==<你所需的版本>`
-   前往[发布页面](https://github.com/nukemiko/libtakiyasha/releases)挑选自己所需的版本，下载安装包，手动安装。

### 依赖项

LibTakiyasha 依赖以下包，均可从 PyPI 获取：

-   [pyaes](https://pypi.org/project/pyaes/)
-   [mutagen](https://pypi.org/project/mutagen/)

## 常见问题

> 为什么 2.x 打开文件需要密钥，而 1.x 版本不需要？

这是出于以下考虑：

-   LibTakiyasha 是一个加解密库，当然需要为用户提供自定义密钥的权利
-   为了保护本项目不受美国<ruby>数字千年版权法<rt>Digital Millennium Copyright Act</rt></ruby>（DMCA）影响，避免仓库被误杀
    -   因此，本仓库所有 1.x 及更早版本的提交和发布版本都已删除。

> 如何使用？

当你 `import libtakiyasha` 时，`libtakiyasha` 下有四个子模块 `ncm`、`qmc`、`kgmvpr`、`kwm` 会被自动导入。这些子模块下各有一个加密文件对象类（`qmc` 除外，有两个），和一个 `probe` 开头的探测函数（`qmc` 除外，有三个），用于确认目标文件是否被该模块支持：

|         模块          |   加密文件对象类   |                     探测函数                      |
| :-------------------: | :----------------: | :-----------------------------------------------: |
|  `libtakiyasha.ncm`   |       `NCM`        |                   `probe_ncm()`                   |
|  `libtakiyasha.qmc`   | `QMCv1` 和 `QMCv2` | `probe_qmc()`、`probe_qmcv1()` 和 `probe_qmcv2()` |
| `libtakiyasha.kgmvpr` |     `KGMorVPR`     |                 `probe_kgmvpr()`                  |
|  `libtakiyasha.kwm`   |       `KWM`        |                   `probe_kwm()`                   |

每个探测函数都会返回一个内含两个元素的元组：

-   第一个元素为文件路径或文件对象，取决于探测函数收到的参数；
-   在探测到受支持的文件时，第二个元素为文件的信息，否则为 `None`

每一个加密文件对象都可以按照普通文件对象对待（拥有 `read()`、`write()`、`seek()` 等方法），也拥有一个 `save()` 方法，以便将该加密文件对象保存到文件。

以 `libtakiyasha.ncm.NCM` 为例，以下是简单的使用示例：

-   要想打开外部加密文件，或新建空加密文件，使用对应加密文件对象类的构造器方法 `open()` 或 `new()`：

    ```pycon
    >>> # 打开外部加密文件
    >>> ncmfile_from_open = libtakiyasha.ncm.NCM.open('/path/to/ncmmfile.ncm', core_key=..., tag_key=...)
    >>> ncmfile_from_open
    <libtakiyasha.ncm.NCM at 0x7f26c44e5080, cipher <libtakiyasha.stdciphers.ARC4 object at 0x7f26c4ef1270>, source '/path/to/ncmfile.ncm'>
    >>> # 新建空加密文件对象
    >>> ncmfile_new = libtakiyasha.ncm.NCM.new()
    >>> ncmfile_new
    <libtakiyasha.stdciphers.ARC4 object at 0x7f26c51214b0>
    >>>
    ```

-   从加密文件中读取和写入数据：

    ```pycon
    >>> # 读取 16 字节
    >>> ncmfile_from_open.read(16)
    b'fLaC\\x00\\x00\\x00"\\x12\\x00\\x12\\x00\\x00\\x07)\\x00'
    >>> # 读取一行数据，直到下一个换行符 \n
    >>> ncmfile_from_open.readline()
    b'\xc4B\xf0\x00\xb6\xe14A\x86nz.\x97\xa8\xe3\xbe\x1d\xb7\xb02?u&\x03\x00\t\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x01V\x00\x00\x00\x00\x00\x00\x01\xd6`\x12\x00\x00\x00\x00\x00\x00\x02\xac\x00\x00\x00\x00\x00\x00\x04\x92B\x12\x00\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\x00\x07\x0f\xb2\x12\x00\x00\x00\x00\x00\x00\x05X\x00\x00\x00\x00\x00\x00\t\xd4\x8c\x12\x00\x00\x00\x00\x00\x00\x06\xae\x00\x00\x00\x00\x00\x00\x0c\xa3\xb6\x12\x00\x00\x00\x00\x00\x00\x08\x04\x00\x00\x00\x00\x00\x00\x0f|\x90\x12\x00\x00\x00\x00\x00\x00\tZ\x00\x00\x00\x00\x00\x00\x12^T\x12\x00\x00\x00\x00\x00\x00\n'
    >>>
    >>> # 使用 for 循环按照固定大小迭代加密文件对象
    >>> ncmfile_from_open.seek(0, 0)
    0
    >>> for blk in ncmfile_from_open:
    ...     print(len(blk))
    ...
    8192
    8192
    8192
    8192
    8192
    8192
    [...]
    >>> # 向加密文件对象写入数据
    >>> ncmfile_from_open.seek(0, 2)
    36137109
    >>> ncmfile_from_open.write(b'Now I writing something...')
    26
    >>>
    ```

-   保存加密文件对象到文件：

    ```pycon
    >>> # 如果该 NCM 对象不是从文件打开的，还需要 filething 参数
    >>> ncmfile_from_open.save(core_key=..., tag_key=...)
    >>>
    ```

有关每个加密文件的操作示例，请使用 `help()` 查看对应加密文件对象类的文档。
