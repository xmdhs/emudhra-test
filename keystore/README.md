# 签名密钥库

`release.jks` 是**故意提交到仓库里的**，供 CI 给 APK 签名使用。

- 别名：`emudhra-checker`
- store / key 口令均为：`emudhra-checker`（见 `app/build.gradle`）

这样做的前提是这个 App 只是一次性的检测工具，唯一的发布渠道是 GitHub Actions
产出的 APK 供人自行侧载（sideload），并且固定签名可以让后续版本覆盖安装。
**任何正式产品都不应把签名私钥放进仓库**：拿到这个 jks 的人可以伪装本应用的更新。
