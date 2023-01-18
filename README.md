# LibTakiyasha ![](https://img.shields.io/badge/Python-3.8%2B-blue)

LibTakiyasha 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。**不提供任何命令行或图形界面支持。**

## 使用前必读

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于：

-   [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/cli)
-   [parakeet-rs/libparakeet](https://github.com/parakeet-rs/libparakeet)

**本项目没有所谓的“默认密钥”或“内置密钥”，打开/保存任何类型的加密文件都需要你提供对应的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

你可以<u>在内容提供商的应用程序中查找这些必需参数</u>，或<u>寻求同类项目以及他人的帮助</u>，**但请不要在 Issues/讨论区直接向作者索要所谓“缺失”的“内置密钥”。**

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

可用的最新版本：2.1.0rc1，可前往[发布页面](https://github.com/nukemiko/libtakiyasha/releases/tag/2.1.0rc1)或 [PyPI](https://pypi.org/project/libtakiyasha/2.1.0rc1/) 下载。

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

LibTakiyasha 的文档（DocStrings）写得非常清晰，你可以在导入后，使用 Python 内置函数 `help(<...>)` 查看用法。
