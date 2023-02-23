# LibTakiyasha ![](https://img.shields.io/badge/Python-3.8%2B-blue)

LibTakiyasha 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。**LibTakiyasha 不提供任何命令行或图形界面支持。**

## 使用前必读

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于<span id='similar-projects'>同类项目</span>：

-   [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/cli)
-   [parakeet-rs/libparakeet](https://github.com/parakeet-rs/libparakeet)

**本项目不内置任何密钥，要正常打开/保存任何类型的加密文件，你需要提供正确的对应的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

如果你要解密别人提供的文件，你可以从提供者处索要密钥，或者寻求同类项目和他人的帮助。

**LibTakiyasha 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---

## 新变化？

请参阅[变更记录](CHANGELOG.md)。

（如果你是在 PyPI 上浏览本 README，以上链接是无效的；变更记录可能会出现在页面的底部。）

## 特性

-   使用纯 Python 代码编写
    -   **兼容 Python 3.8 及后续版本**，兼容多种 Python 解释器实现
        -   可在[此处](https://github.com/nukemiko/libtakiyasha/wiki/%E6%80%A7%E8%83%BD%E8%A1%A8%E7%8E%B0)查看具体兼容哪些实现
    -   易于阅读，方便 Python 爱好者学习
    -   （包括依赖库）无任何 C/C++ 扩展模块，跨平台性强
-   支持四种加密文件：
    -   网易云音乐加密文件 `.ncm`
    -   QQ 音乐加密文件 QMCv1 `.qmc[0-9]`、`.qmcflac`、`.qmcogg`、`.qmcra` 等
    -   QQ 音乐加密文件 QMCv2 `.mflac[0-9]`、`.mgg[0-9]` 等
    -   酷狗音乐加密文件 KGM/VPR `.kgm`、`.vpr`
        -   不支持创建新加密文件
    -   酷我音乐加密文件 `.kwm`
    -   更多信息，请参见[此处](https://github.com/nukemiko/libtakiyasha/wiki/%E6%94%AF%E6%8C%81%E7%9A%84%E6%A0%BC%E5%BC%8F%E4%BB%A5%E5%8F%8A%E6%89%80%E9%9C%80%E7%9A%84%E5%8F%82%E6%95%B0)

**注意：LibTakiyasha 的所有操作都不是线程安全的。尽量不要尝试在多线程环境下使用 LibTakiyasha 的任何功能。**

### 性能表现

参见[此处](https://github.com/nukemiko/libtakiyasha/wiki/%E6%80%A7%E8%83%BD%E8%A1%A8%E7%8E%B0)。

## 安装

可用的最新版本：2.1.1，[GitHub 发布页面](https://github.com/nukemiko/libtakiyasha/releases/tag/2.1.1)，[PyPI](https://pypi.org/project/libtakiyasha/2.1.1/)

### 安装方式

-   使用 `pip`，通过 PyPI 安装最新版本：`python -m pip install -U libtakiyasha`

如果你要下载其他版本：

-   PyPI：https://pypi.org/project/libtakiyasha/#history ，挑选自己所需的版本，下载安装包，手动安装。
    -   或者使用 pip 安装：`python -m pip install -U libtakiyasha==<你所需的版本>`
-   前往[发布页面](https://github.com/nukemiko/libtakiyasha/releases)挑选自己所需的版本，下载安装包，手动安装。

### 依赖项

LibTakiyasha 依赖以下包，均可从 PyPI 获取：

-   [pyaes](https://pypi.org/project/pyaes/) - 用于加解密 NCM 文件内嵌的主密钥和元数据
-   [mutagen](https://pypi.org/project/mutagen/) - 用于以 `mutagen` 可接受的形式导出 NCM 文件内嵌的元数据

## 如何使用？

在[这里](https://github.com/nukemiko/libtakiyasha/wiki/%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8%E5%8F%8A%E7%A4%BA%E4%BE%8B)可以找到使用方法和示例。

同时，在[本项目的 Wiki 主页](https://github.com/nukemiko/libtakiyasha/wiki)可以找到其他一些可能对你有用的东西。

## 常见问题

> 为什么 2.x 打开文件需要密钥，而 1.x 版本不需要？

这是出于以下考虑：

-   LibTakiyasha 是一个加解密库，当然需要为用户提供自定义密钥的权利
-   为了保护本项目不受美国<ruby>数字千年版权法<rt>Digital Millennium Copyright Act</rt></ruby>（DMCA）影响，避免仓库被误杀
    -   因此，本仓库所有 1.x 及更早版本的提交和发布版本都已删除。
