# libtakiyasha ![](https://img.shields.io/badge/Version-2.1.0rc1-yellow) ![](https://img.shields.io/badge/Python-3.8%2B-blue)

`libtakiyasha` 是一个 Python 音频加密/解密工具库（当然也可用于加密非音频数据），支持多种加密文件格式。**不提供任何命令行或图形界面支持。**

## 使用前必读

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于：

- [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/cli)
- [jixunmoe/kugou-crypto](https://github.com/jixunmoe/kugou-crypto)
- [jixunmoe/qmc2](https://github.com/jixunmoe/qmc2)

**本项目没有所谓的“默认密钥”或“内置密钥”，打开/保存任何类型的加密文件都需要你提供对应的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**

你可以<u>在内容提供商的应用程序中查找这些必需参数</u>，或<u>寻求同类项目以及他人的帮助</u>，**但请不要在 Issues/讨论区直接向作者索要所谓“缺失”的“内置密钥”。**

**`libtakiyasha` 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---
