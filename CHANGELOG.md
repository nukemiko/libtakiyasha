## 变更记录

### 版本 2.1.1.post1

-   修复了 `import libtakiyasha` 时因为缺少数据文件而抛出 `FileNotFoundError`，从而导致 `libtakiyasha` 彻底无法使用的问题
-   将 `libtakiyasha.ncm.CloudmusicIdentifier` 加入顶层 `__init__.py` 的导入内容

在[这里](https://github.com/nukemiko/libtakiyasha/compare/2.1.1...2.1.1.post1)查看更详细的变更记录。

### 版本 2.1.1

-   修复了各个模块的文件探测函数 `probe_*()` 的类型提示，现在 `PyCharm`、`Pylance` 等 IDE 和 LSP 应该会正确识别和显示它们的参数类型和返回类型
-   修改了 `libtakiyasha.__init__` 中导入的内容：不再导入常用模块 `ncm`、`qmc`、`kgmvpr`、`kwm`、`pkgmetadata`，而是直接导入这些模块中的常用函数、方法和类，可以在只导入了 `libtakiyasha` 包后直接使用。
    -   可以在[这里](https://github.com/nukemiko/libtakiyasha/tree/3bf8bef7e3e975c73cfdc410711c224d0ff5adf1)看到 `libtakiyasha.__init__` 中导入的内容。
-   为各个模块都添加了另一个文件探测函数 `probeinfo_*()`，此函数与 `probe_*()` 不同：
    -   `probeinfo_*()` 仅在输入文件是受支持的文件类型时才会返回探测结果（`*FileInfo` 对象），否则为 `None`；
    -   `probe_*()` 始终返回一个 2 元组：
        -   如果输入了文件路径，第一个元素是输入的路径使用 `pathlib.Path` 转换过的路径对象；如果输入了文件对象，第一个元素就是输入的文件对象
        -   如果输入文件是受支持的文件类型，第二个元素是探测结果（`*FileInfo` 对象）；否则为 `None`
-   `libtakiyasha.qmc` 中作为文件探测信息容器的 `QMCv1FileInfo` 和 `QMCv2FileInfo` 已被删除，它们的作用被 `QMCFileInfo` 取代。这意味着不应该再使用内置函数 `isinstance()` 判断 QMC 文件版本，转而通过访问探测结果的 `version` 属性获得。

在[这里](https://github.com/nukemiko/libtakiyasha/compare/2.1.0...2.1.1)查看更详细的变更记录。

### 版本 2.1.0

-   减少了一些重复代码的使用，删除了大量不再使用的代码
-   优化了判断是否为 QMCv1 文件的逻辑、QMCv2 文件的主密钥探测逻辑
-   `libtakiyasha.qmc.QMCv2` 的 `open()` 和 `save()` 现在可接受多个混淆密钥，通过关键字参数 `garble_keys` 在需要时传入。
    -   **因此，上述方法中原来的关键字参数 `garble_key1` 和 `garble_key2` 已经被干掉了，请及时修改你的工具链。**
    -   如果提供此参数，需要提供一个产生至少一个混淆密钥（类字节对象）的可迭代对象（例如列表），且混淆密钥的顺序必须正确。

在[这里](https://github.com/nukemiko/libtakiyasha/compare/2.1.0rc2...2.1.0)查看更详细的变更记录。

### 版本 2.0.1 至 2.1.0rc2

在[这里](https://github.com/nukemiko/libtakiyasha/compare/2.0.1...2.1.0rc2)查看更详细的变更记录。
