# libtakiyasha ![](https://img.shields.io/badge/Version-2.1.0a1-yellow) ![](https://img.shields.io/badge/Python-3.8%2B-blue)

`libtakiyasha` 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。

`libtakiyasha` 只是一个工具库，不提供任何命令行或图形界面支持。

---

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于：

-   [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/cli)
-   [jixunmoe/qmc2](https://github.com/jixunmoe/qmc2)

**本项目没有所谓的“内置密钥”，打开任何类型的加密文件都需要你提供对应的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

你可以在内容提供商的应用程序中查找这些必需参数，或寻求同类项目以及他人的帮助。**但请不要在 Issues/讨论区向作者索要所谓“缺失”的“内置密钥”，你的此类想法不会被满足。**

**`libtakiyasha` 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---

## 特性

-   纯 Python 实现（包括所有依赖关系），无 C/C++ 扩展模块，跨平台可用
-   支持多种加密文件格式的加密和解密

## 当前版本：[2.1.0a1](https://github.com/nukemiko/libtakiyasha/releases/tag/2.1.0a1)

此版本为测试版。如果发现任何 `libtakiyasha` 自身的问题，欢迎[提交 Issue](https://github.com/nukemiko/libtakiyasha/issues)。

**`libtakiyasha` 2.x 版本和 1.x 版本之间的接口并不兼容，使用 1.x 版本的应用程序需要进行大量改造，才能使用 2.x 版本。**

### 变更日志

详见[版本发布页](https://github.com/nukemiko/libtakiyasha/releases/tag/2.1.0a1)。

### 支持的格式

~~请在[此处](https://github.com/nukemiko/libtakiyasha/wiki/%E6%94%AF%E6%8C%81%E7%9A%84%E6%A0%BC%E5%BC%8F%E5%92%8C%E6%89%80%E9%9C%80%E5%AF%86%E9%92%A5%E5%8F%82%E6%95%B0)查看。~~

鉴于以上信息无法正确反映当前版本，请以当前版本的文档为准（可在 Python 交互式终端中使用 `help(<函数/方法/对象>)` 查看）。

### 兼容性

到目前为止（版本 2.1.0a1），`libtakiyasha` 已在以下 Python 实现中通过了测试：

-   [CPython（官方实现）](https://www.python.org)3.8 至 3.10，可能支持 3.11
-   [Pyston](https://github.com/pyston/pyston) [2.3.5](https://github.com/pyston/pyston/releases/tag/pyston_2.3.5)（基于 CPython 3.8.12），其他版本或许也可用
-   [PyPy](https://www.pypy.org/) 7.3.9（[CPython 3.8 兼容版本、CPython 3.9 兼容版本](https://downloads.python.org/pypy/)），其他版本或许也可用

**注意：`libtakiyasha` 所需的最低 Python 版本为 3.8，因为它使用的很多 Python 特性从 Python 3.8 开始才出现，这意味着使用更低的 Python 版本会出现大量不可预知的错误。**

提示：在作者运行的测试中（仅测试了 NCM），CPython 实现是速度最慢的；PyPy 比 Pyston 快了大约两倍（两者都内置了不同形式的 JIT），比 CPython 快了接近五倍。

### 安装

-   运行命令：`pip install -U libtakiyasha==2.1.0a1`
-   或者前往 [GitHub 发布页](https://github.com/nukemiko/libtakiyasha/releases/tag/2.1.0a1) 下载安装

#### 所需依赖关系

-   `setuptools` - 安装依赖
-   `pyaes` - AES 加解密支持
-   `mutagen` - 导出网易云音乐使用的 163key 数据

如果你是通过[上文提到的方式](#安装)安装的 `libtakiyasha`，这些依赖会被自动安装。

### 基本使用方法

_未完待续_
