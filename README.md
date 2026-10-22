# eMudhra 中间 CA 信任检查（Android）

把 [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/) 上
“Does your client still trust the compromised intermediates?” 一节搬到原生 Android 上，
用来检查**本机 Android 系统**是否仍然信任 2026 年 10 月私钥泄露的那 8 个 eMudhra 中间 CA。

## 检查方式

网页版会向 12 个测试主机发起请求，靠“是否握手成功”判断；这 12 个主机覆盖了
DV / OV / EV × G3B / G3C × 两个签发根（eMudhra 直签与 Sectigo 交叉签名）。

App 做两件事，逐条对应那 12 个域名：

1. **实际连接**：与网页版相同，对每个主机发起 HTTPS 请求（`HttpsURLConnection`，
   走系统 TLS 栈与主机名校验）。成功即说明本机仍信任该链；失败时 App 会区分
   “证书被拒”和“网络不通”——这是网页版做不到的。
2. **信任库（离线）**：把 12 条链（与 `chains.zip` 中的逐字节相同）直接交给本机
   默认的 `X509TrustManager` 校验，并说明相关根证书是否仍在设备信任库中。
   这一项不依赖网络，对应网页版给出的 `openssl verify -CAfile <bundle>` 检查，
   也是系统更新真正修复的东西。

结果按 12 条链分别给出“实际连接”和“信任库”两个结论；顶部汇总按实际连接给总判定：

| 汇总 | 含义 |
| --- | --- |
| ✅ 已修补 | 没有主机握手成功，且信任库也不再接受这些链 |
| ❌ 不安全 | 至少一个主机握手成功（或离线判断仍信任），持有私钥者可冒充该主机 |
| ⚠️ 结果不一致 / 无法判断 | 连接全部被网络问题挡住，或握手被拒但离线路径仍成立 |

## 为什么 Android 上很可能不安全

这些中间证书的私钥是 CA 生成时就用错了随机数，任何人都能从证书里还原出私钥；
而 Android 默认的证书校验**不检查吊销状态**（CRL/OCSP 都不看）。浏览器之所以安全，
是靠在浏览器侧下发 OneCRL / CRLSet / CRLite，并且强制证书透明度（CT）；
Android 系统自带的 TLS 栈（Conscrypt）默认不做 CT 强制，因此也不吃浏览器那套缓解措施。
Android 只能靠系统更新（或 Mainline 根证书更新）把相关根证书移出信任库。

如果 App 报“❌ 不安全”，请检查系统是否有可用的安全更新；没有的话，
避免在该设备上登录敏感账号。

## 构建

CI 在 `.github/workflows/build.yml`，**只能手动触发**（Actions → Build APK → Run
workflow）。每次运行都会：

1. 构建签好名的 release APK，并用 `apksigner` 校验；
2. 用 `actions/attest@v4` 为该 APK 生成 Sigstore 构建来源证明；
3. 上传 workflow artifact；
4. 直接发布一个 GitHub Release，把 APK 附上去（tag 默认
   `build-<run number>-<sha>`，可用 `tag` 输入自定义）。

验证来源证明需要仓库是公开的（私有仓库需要 GitHub Enterprise Cloud）：

```sh
gh attestation verify app-release.apk --repo <owner>/<repo>
```

签名用的 `keystore/release.jks` 按项目要求直接放在仓库里，口令见
`keystore/README.md`。这不是好习惯，只因为该应用是一次性侧载工具才这么做；
也因此 APK 签名只能证明它出自哪个构建，不能证明只有你能构建。

CI 里用到的 action 均为当前最新 major 版本：`actions/checkout@v7`、
`actions/setup-java@v6`、`android-actions/setup-android@v4`、
`gradle/actions/setup-gradle@v6`、`actions/attest@v4`、
`actions/upload-artifact@v7`、`softprops/action-gh-release@v3`。

本地构建（需要 JDK 17 + Android SDK）：

```sh
./gradlew assembleRelease
# app/build/outputs/apk/release/app-release.apk
```

## 目录

```
app/src/main/java/dev/wehaveaproblem/emudhra/
  MainActivity.java    纯 View 构建的界面（不使用 Compose、不引入任何依赖）
  TestData.java        从 assets 读取并解析证书链
  TrustEvaluator.java  离线用系统信任库校验
  NetworkProbe.java    实际连接 12 个测试主机
app/src/main/assets/tests.json   12 条链 + 4 个根证书（上游数据快照）
tools/fetch_data.py   重新从上游生成 tests.json
tools/make_icon.py    生成启动图标（无第三方依赖）
```

数据更新：上游重新抓链之后运行 `python3 tools/fetch_data.py` 并提交结果。
