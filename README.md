# libtakiyasha ![](https://img.shields.io/badge/Version-2.0.0.dev0-green) ![](https://img.shields.io/badge/Python-3.8%2B-blue)

`libtakiyasha` 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。

`libtakiyasha` 是从 [`takiyasha`](https://github.com/nukemiko/takiyasha) 项目中拆分出来的，现在 `libtakiyasha` 仍然被此项目使用。**它只是一个工具库，不提供任何命令行或图形界面支持。**

---

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于 [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/web) 和 [jixunmoe/qmc2](https://github.com/jixunmoe/qmc2)。

**本项目现在不会内置任何解密所需的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

你可以在内容提供商的应用程序中查找这些必需参数，或寻求他人的帮助，但请**不要在本仓库下的 Issues 或讨论区中报告“缺少内置密钥”、“不能免密钥/一键解密”之类的问题，否则你的 Issue 会被立即关闭。**

**`libtakiyasha` 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---

## 当前版本：2.0.0.dev0

此版本为开发版，如果发现任何 `libtakiyasha` 自身的问题，欢迎[提交 Issue](https://github.com/nukemiko/libtakiyasha/issues)。

### 安装

-   运行命令：`pip install -U libtakiyasha`
-   或者前往 [GitHub 发布页](https://github.com/nukemiko/libtakiyasha/releases) 下载安装

### 基本使用方法

提取加密文件里的音频内容：

```python
from libtakiyasha import NCM, QMCv2

...  # 定义你提供的核心密钥 your_provided_core_key 和 your_provided_simple_key

ncmfile = NCM.from_file('source.ncm', core_key=your_provided_core_key)
target_file_format = ncm.ncm_tag.format

with open('target_from_ncm.' + target_file_format, mode='wb') as fd:
    for block in ncmfile:
        fd.write(block)

qmcv2file = QMCv2.from_file('source.mflac', simple_key=your_provided_simple_key)
target_file_format = 'flac'

with open('target_from_mflac.' + target_file_format, mode='wb') as fd:
    for block in qmcv2file:
        fd.write(block)
```

-   打开加密文件时，如果不提供核心密钥，会报错而无法继续：

    ```pycon

    >>> from libtakiyasha import QMCv2
    >>> qmcv2file = QMCv2.from_file('source.mflac')
    Traceback (most recent call last):
        File "<stdin>", line 1, in <module>
        <...>
        ValueError: 'simple_key' is required for QMCv2 file master key decryption
    >>>
    ```
