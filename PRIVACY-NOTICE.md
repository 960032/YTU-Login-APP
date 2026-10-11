# 隐私须知（PRIVACY-NOTICE）

> 面向使用者：**在把本目录（或整个工作区）纳入 git 仓库、打包分发、或上传到任何平台之前，请先读完本文件。**
> 本文件由隐私清理轮次写入，用于说明「哪些文件涉及你的个人信息」以及「怎样才不会被误提交」。

## 1. 绝对不能提交的文件

| 路径 | 内容 | 处理方式 |
| --- | --- | --- |
| `artifacts/srun-impl/config.json` | 你的**真实校园网账号与明文密码**（本机运行配置，属于你个人的本地文件，不属于交付物） | **永远不要** `git add`、不要上传、不要粘贴到聊天/工单/截图里 |
| 其它本地凭据与产物：`local.properties`、`*.keystore`、`*.jks`、`*.apk` | 本机 SDK 路径、签名密钥、构建产物 | 已由 `artifacts/android-app/.gitignore` 忽略；提交前仍建议用 `git status` 人工确认 |

交付物一侧（应用代码、测试向量 `artifacts/android-app/testvectors/vectors.json`，全部为合成数据）**不含**你的任何个人信息；依据是两处审计记录（`artifacts/kotlin-crypto/credential-scan.txt`、`artifacts/kotlin-crypto/equivalence-report.md` 第 9 节）以及 `artifacts/privacy-cleanup/scan-after.txt` 的全工作区再检索记录。

## 2. 关键提醒：子目录的 .gitignore 不覆盖全仓库

**这是本文件最重要的一条，请务必理解：**

- `artifacts/android-app/.gitignore` 里的规则**只对 `artifacts/android-app/` 目录及其子目录生效**。
- 它**管不到** `artifacts/srun-impl/config.json` —— 那个文件在 `android-app/` 之外。
- 因此**不要**以为「已经有 .gitignore 了，所以 config.json 是安全的」。**不是。**

### 正确做法

- 若只把 `artifacts/android-app/` 单独作为一个仓库（在该目录下 `git init`）：现有 `.gitignore` 已足够——`config.json` 本来就不在这个仓库范围内，但仍请人工确认待提交清单。
- 若把**整个工作区**（`YTU校园网/`）纳入 git 仓库：**必须**在**仓库根目录**的 `.gitignore`（即与 `artifacts/` 同级的 `YTU校园网/.gitignore`）中显式排除它：

```gitignore
# 用户本地凭据（含明文账号密码），绝不提交
artifacts/srun-impl/config.json
# 更保险的做法：连同整个用户本地目录一起排除
# artifacts/srun-impl/
```

  等价替代：在 `artifacts/.gitignore` 中写 `srun-impl/config.json`（该文件对 `artifacts/` 子树生效）。
  两种写法任选其一——**但 `artifacts/android-app/.gitignore` 无论如何都做不到这件事**，因为忽略规则的生效范围不能超出该文件所在目录的子树。

### 验证方法

```powershell
git check-ignore -v artifacts/srun-impl/config.json   # 有输出 = 已被忽略；无输出 = 没被忽略
```

## 3. config.json 的性质

- 该文件以**明文**保存账号与密码（程序运行需要读它，属于你的本机配置）。
- 明文意味着：一旦提交或上传，任何人都能直接读到你的账号密码；即使事后删除，git 历史里仍留有痕迹，需要重写历史才能彻底清除。
- 请把它当作**你自己的本地文件**：只放本机、只供本机运行使用；备份时也放在你自己可控的位置。

## 4. 提交前自检清单（约 30 秒）

1. `git status --porcelain` → 检查待提交清单里有没有 `config.json`、`local.properties`、`*.apk`、`*.jks`、`*.keystore`；
2. `git diff --cached --name-only` → 再确认一次**已暂存**的文件内容；
3. 确认提交内容里没有真实手机号/密码（检索时请用正则或分段拼接，**别把完整真号写进命令或输出文件**——这正是本轮需要脱敏两处审计记录的成因）；
4. 对可疑路径跑一次 `git check-ignore -v <路径>` 验证是否真被忽略。

## 5. 本轮已做的事（供追溯）

- `artifacts/kotlin-crypto/credential-scan.txt` 与 `artifacts/kotlin-crypto/equivalence-report.md` 中，**检索命令原文里出现的真实手机号字面量**已替换为占位符 `[REDACTED_PHONE]`（含义：原检索命令中引用的真实号码，已脱敏；检索结论「0 命中」不变），并在其后插入了一行中文说明；两文件的审计结论（命中数、被检索文件数、命令结构等）**未做任何删改**。
- `artifacts/privacy-cleanup/` 下留有完整证据：`scan-after.txt`（全工作区再检索的原始命令 + 原始输出）、`before-after.diff`（两文件逐字对照，带行号）、`cleanup-report.md`（脱敏前后 SHA256 与改动说明）。
- `artifacts/srun-impl/config.json` **未被改动**（逐字节一致，SHA256 前后相同）。
