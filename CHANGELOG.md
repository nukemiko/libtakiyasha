## 变更记录

### 版本 2.1.0

-   减少了一些重复代码的使用，删除了大量不再使用的代码
-   优化了判断是否为 QMCv1 文件的逻辑、QMCv2 文件的主密钥探测逻辑
-   `libtakiyasha.qmc.QMCv2` 的 `open()` 和 `save()` 现在可接受多个混淆密钥，通过关键字参数 `garble_keys` 在需要时传入。
    -   **因此，上述方法中原来的关键字参数 `garble_key1` 和 `garble_key2` 已经被干掉了，请及时修改你的工具链。**
    -   如果提供此参数，需要提供一个产生至少一个混淆密钥（类字节对象）的可迭代对象（例如列表），且混淆密钥的顺序必须正确。

在[这里](https://github.com/nukemiko/libtakiyasha/compare/2.1.0rc2...2.1.0)查看更详细的变更记录。

### 版本 2.0.1 至 2.1.0rc2

在[这里](https://github.com/nukemiko/libtakiyasha/compare/2.0.1...2.1.0rc2)查看更详细的变更记录。
