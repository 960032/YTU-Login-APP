# 测试向量生成记录（SrunCrypto 等价性判据）

本目录下的 `vectors.json` 是 Kotlin 移植版的**唯一判据**：它的每一条期望值都由 **Node 参考实现**
`artifacts/srun-impl/srun-crypto.js` 现算产出，Kotlin 侧逐字符比对。

## 1. 生成命令原文

```powershell
node "F:\Program\Harness_Workspace\YTU校园网\artifacts\android-app\testvectors\generate-vectors.cjs"
```

（脚本自身位置：`artifacts/android-app/testvectors/generate-vectors.cjs`；它以 `__dirname/../../srun-impl/srun-crypto.js`
定位参考实现，并在计算任何向量之前先校验该文件的 SHA256。）

## 2. 完整原始输出（逐字，未翻译、未删改）

```text
自检: 参考实现 base64Encode("Ā") 抛出 -> INVALID_CHARACTER_ERR: DOM Exception 5
自检: 参考实现 base64Encode("你好") 抛出 -> INVALID_CHARACTER_ERR: DOM Exception 5
自检: 参考实现 base64Encode("😀") 抛出 -> INVALID_CHARACTER_ERR: DOM Exception 5
自检: 参考实现 base64Encode("abĀ") 抛出 -> INVALID_CHARACTER_ERR: DOM Exception 5
参考实现 sha256 = 1A56E0EA990F98E6D2A7E0F4A914FCBCEED86B7A52B0F6094EF076FEFD424FE6  （与基准一致）
node v24.15.0
输出文件 = F:\Program\Harness_Workspace\YTU校园网\artifacts\android-app\testvectors\vectors.json
  md5: 6 条
  sha1: 6 条
  hmacMd5: 9 条
  base64Encode: 15 条
  passwordField: 6 条
  chksum: 5 条
  infoField: 5 条
总向量条数 = 52
抽样 md5("") = d41d8cd98f00b204e9800998ecf8427e
抽样 base64Encode("") = ""
抽样 infoField(合成账号) = {SRBX1}alJEaYjZ+qhvHtuGTMVlItcSSgb5d2FgQHB33372iPjC+Ke2KN+R5k0XgLizZ9Un80tvezRyd7PQbA878B7w/HxGi7+zz3tlVjDPegv4RjoaExKLCoCHj+592Mab/9fC0xq2/4r5yh9xZQUTgDmHSZcSnf+=
退出码 = 0
```

同一段原始输出也保存在 `testvectors/generate-vectors.raw-output.txt`，并作为附录出现在
`artifacts/kotlin-crypto/build-log.txt`（「命令 A：node ...」段）。

## 3. 向量构成（52 条）

| 类别 | 条数 | 覆盖点 |
| --- | --- | --- |
| `md5` | 6 | 空串、`abc`、中文、emoji、含 NUL、1100 字符超长串 |
| `sha1` | 6 | 同上 6 组 |
| `hmacMd5` | 9 | **空 key**（`key=""` × 3，含 `msg=""`）、非空 key（`onlykey`、合成 token、120 字符长 token）、中文、含 NUL 的 unicode、613 字符超长 msg |
| `base64Encode` | 15 | `""`、`A`、`AB`、`ABC`、`abcd`、`abc123`、`abc+/=`、NUL、`0x00-0xFF` 全 256 字节、255 字节、1000 字符超长串；**4 条 expectError**（`"Ā"`、`"你好"`、`"😀"`、`"abĀ"` 必须抛错） |
| `passwordField` | 6 | 合成密码 × 空 token / 正常 token / 120 字符长 token；空密码 + 空 token；中文密码；emoji 密码 |
| `chksum` | 5 | 正常、**空 token**、中文用户名/密码、120 字符长 token 且 `n=300/type=2`、IPv6 形式 ip |
| `infoField` | 5 | 正常、**空 token**、中文用户名/密码、长 token + 另一 IP、IPv6 形式 ip |

## 4. 安全性

- 全部输入均为**合成数据**：`username = 202000000000@ytu`、`password = TestPassword123`、
  `token = 3a5f9b2c1d8e4f7a`、`ip = 10.10.20.30`、`acId = "5"`。
- 生成脚本**不读取任何真实凭据文件**，运行期也不打印任何外部文件内容；只读参考实现 `srun-crypto.js`。
- 参考实现的 SHA256 在生成前被校验为 `1A56E0EA990F98E6D2A7E0F4A914FCBCEED86B7A52B0F6094EF076FEFD424FE6`，
  与基准卡一致；不一致时脚本以退出码 3 终止（不会产出可疑向量）。

## 5. 复现步骤

```powershell
# 1) 重新生成向量（幂等；仅 meta.generatedAt 会变化）
node artifacts/android-app/testvectors/generate-vectors.cjs
# 2) 用 Kotlin 实现逐字符核对（本机可离线复现，见 artifacts/kotlin-crypto/build-log.txt 的命令原文）
java -Dstdout.encoding=UTF-8 -cp "artifacts/kotlin-crypto/classes;<kotlin-stdlib-2.3.0.jar>" `
     top.ytu.srunautologin.crypto.VectorCheckKt "artifacts/android-app/testvectors/vectors.json"
# 期望输出：用例总数 = 52，通过 = 52，失败 = 0；退出码 0
```
