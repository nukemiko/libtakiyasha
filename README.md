# libtakiyasha ![](https://img.shields.io/badge/Version-2.0.0.dev0-green) ![](https://img.shields.io/badge/Python-3.8%2B-blue)

`libtakiyasha` 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。

`libtakiyasha` 是从 [`takiyasha`](https://github.com/nukemiko/takiyasha) 项目中拆分出来的，现在 `libtakiyasha` 仍然被此项目使用。**它只是一个工具库，不提供任何命令行或图形界面支持。**

---

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于 [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/web) 和 [jixunmoe/qmc2](https://github.com/jixunmoe/qmc2)。

**本项目现在不会内置任何解密所需的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

你可以在内容提供商的应用程序中查找这些必需参数，或寻求他人的帮助，但请**不要在本仓库下的 Issues 或讨论区中报告“缺少内置密钥”、“不能免密钥/一键解密”之类的问题，你的此类 Issue 不会得到作者的回复。**

**`libtakiyasha` 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---

## 当前版本：[2.0.0.a1](https://github.com/nukemiko/libtakiyasha/releases/tag/2.0.0.a1)

此版本为开发版，如果发现任何 `libtakiyasha` 自身的问题，欢迎[提交 Issue](https://github.com/nukemiko/libtakiyasha/issues)。

**`libtakiyasha` 2.x 版本不是向后兼容的，使用 1.x 版本的应用程序需要进行一些改造，才能使用 2.x 版本。**

### 支持的格式

请在[此处](https://github.com/nukemiko/libtakiyasha/wiki/%E6%94%AF%E6%8C%81%E7%9A%84%E6%A0%BC%E5%BC%8F%E5%92%8C%E6%89%80%E9%9C%80%E5%AF%86%E9%92%A5%E5%8F%82%E6%95%B0)查看。

### 安装

-   运行命令：`pip install -U libtakiyasha==2.0.0.a1`
-   或者前往 [GitHub 发布页](https://github.com/nukemiko/libtakiyasha/releases/tag/2.0.0.a1) 下载安装

### 基本使用方法

提取加密文件里的音频内容：

```python
from libtakiyasha.ncm import NCM
from libtakiyasha.qmc import QMCv2

...  # 定义你提供的核心密钥 your_core_key、your_simple_key、your_mix_key1 和 your_mix_key2

# 打开 NCM 文件
ncmfile = NCM.from_file('source.ncm', core_key=your_core_key)
target_file_format = ncm.ncm_tag.format

with open('target_from_ncm.' + target_file_format, mode='wb') as fd:
    # libtakiyasha 的所有透明加密文件对象（NCM、QMCv1、QMCv2、KGMorVPR 等）默认以固定大小的块为单位进行迭代
    # 通过修改对象的 iter_mode 属性为 'line'，可以使其以一行为单位进行迭代
    # 不过进行行迭代会导致性能大幅下降，不推荐使用
    for block in ncmfile:
        fd.write(block)

# 打开 QMCv2 文件
qmcv2file = QMCv2.from_file('source.mflac', simple_key=your_simple_key)
target_file_format = 'flac'

with open('target_from_mflac.' + target_file_format, mode='wb') as fd:
    for block in qmcv2file:
        fd.write(block)

# 也可以打开来自 QQ 音乐 PC 客户端 18.57 及更新版本的 QMCv2 文件，
# 但需要正确的 mix_key1 和 mix_key2 参数
qmcv2file_keyencv2 = QMCv2.from_file('source.mflac', simple_key=your_simple_key, mix_key1=your_mix_key1, mix_key2=your_mix_key2)
target_file_format = 'flac'

with open('target_from_mflac.' + target_file_format, mode='wb') as fd:
    for block in qmcv2file_keyencv2:
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

    你需要向 `QMCv2.from_file()` 传入正确的 `simple_key` 参数才能打开文件。

    同样，你需要向 `NCM.from_file()` 传入正确的 `core_key` 参数才能打开 NCM 文件。

生成加密文件（以 QMCv2 为例）：

```python
from libtakiyasha.qmc import QMCv2

...  # 定义你的 your_simple_key、your_mix_key1 和 your_mix_key2

new_qmcv2 = QMCv2.new()

new_qmcv2.simple_key = your_simple_key  # 可选，但如果跳过此步骤，在保存到文件时需要填写参数 simple_key

with open('plain.flac', 'rb') as fd:
    for line in fd:
        new_qmcv2.write(line)

# 保存为 QMCv2 KeyEncV1
new_qmcv2.to_file('encrypted.mflac')

# 也可以保存为 QMCv2 KeyEncV2 - QQ 音乐 PC 端 18.57 及更高版本的格式
new_qmcv2.to_file('encrypted-keyencv2.mflac', master_key_enc_ver=2, mix_key1=your_mix_key1, mix_key2=your_mix_key2)
```
