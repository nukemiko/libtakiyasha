# libtakiyasha ![](https://img.shields.io/badge/Python-3.8+-red)

`libtakiyasha` 是一个 Python 加密/解密工具库，支持多种加密文件格式。

`libtakiyasha` 是从 [`takiyasha`](https://github.com/nukemiko/takiyasha) 项目中拆分出来的，现在 `libtakiyasha` 仍然被此项目使用。

`libtakiyasha` 只是一个工具库，它不提供任何命令行或图形界面支持。**如果您需要命令行程序，请安装使用 [`takiyasha`](https://github.com/nukemiko/takiyasha) 项目。**

---

**本项目是以学习和技术研究的初衷创建的，修改、再分发时请遵循 [License](https://github.com/nukemiko/libtakiyasha/blob/master/LICENSE)。**

本项目的设计灵感，以及部分解密方案，来源于 [Unlock Music Project - CLI Edition](https://git.unlock-music.dev/um/web) 和 [jixunmoe/qmc2](https://github.com/jixunmoe/qmc2)。

**为规避风险，本项目现在不会内置任何解密所需的密钥。你需要自行寻找解密所需密钥或加密参数，在调用时作为参数传入。**
你可以在内容提供商的应用程序中查找这些必需参数，或寻求他人的帮助。

**`libtakiyasha` 对输出数据的可用性（是否可以识别、播放等）不做任何保证。**

---

`libtakiyasha` 支持以下加密格式（使用 [glob 表达式](<https://en.wikipedia.org/wiki/Glob_(programming)>)表示文件名模式）：

-   NCM 以及缓存文件（`*.ncm`、`*.uc[!]`），
    -   对于 NCM，需要核心密钥（必需，用于提取音频数据）和元数据密钥（可选，用于提取元数据）
-   QMCv1（`*.qmc*`），需要原始密钥
-   QMCv2（`*.mflac`、`*.mflac[0-9a-zA-Z]`、`*.mgg`、`*.mgg[0-9a-zA-Z]`），需要种子
