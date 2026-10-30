# LLVM 20.1.2 本机工具链恢复

本次已恢复并实际运行 **Ubuntu LLVM / Clang / LLD 20.1.2**，软件包版本为 `1:20.1.2-0ubuntu1~24.04.3`。工具解压在独立目录，供当前 Core 组合任务使用。

```sh
source /workspace/scratch/b484d4086829/llvm-restoration-20261029-evening/llvm20-env.sh
```

该文件将 `/workspace/scratch/b484d4086829/toolchains/llvm20-evening/usr/lib/llvm-20/bin` 放到 `PATH` 前面，并加入独立目录下的 LLVM 共享库搜索路径。

## 身份与认证

- 使用已记录的 Ubuntu 快照 `https://snapshot.ubuntu.com/ubuntu/20260828T000000Z/`，恢复原来的精确版本。
- 新取得的 `noble-updates/InRelease` 与恢复出的旧记录逐字节一致，SHA-256 为 `3b2e0ca04c6c8381fc54a06e0a494d76c3b941c34f2c7e2513565fead35da0d2`。
- 本次重新验证了签名，实际签名指纹为 Ubuntu Archive 2018 密钥 `F6ECB3762474EDA9D21B7022871920D1991BC93C`。所用公开密钥环、原始签名状态和进程输出均有保留。
- `noble-updates` 的 `main` 和 `universe` 两份 amd64 索引，其压缩及解压后的字节数、SHA-256 均与签名中的记录一致。
- 10 个软件包合计 **81,240,606 字节**，全部按这些认证索引验证后解压。7 个包的字节数与 SHA-256 同时匹配恢复出的旧软件包回执；另 3 个包取自同一签名快照和精确版本。
- 本次选择的是上述 Ubuntu 快照。源码工作流列出的 `apt.llvm.org` 密钥及仓库是另一条安装路线，本次没有把 Ubuntu 签名伪称为该仓库签名。

解压后校对了 **568 个普通文件和 128 个符号链接**。没有执行软件包维护脚本，也没有修改系统 apt 配置。实际 `clang` / `clang++` 可执行文件 SHA-256 为：

```text
b15e7640bf3082f36ef14321711706b265df3058721e3c2caef3a4b83895d07d
```

## 实际验证结果

| 检查 | 结果 |
| --- | --- |
| `clang`、`clang++`、`llvm-readobj`、`llvm-ar`、`llvm-ranlib`、`ld.lld` | 6 个实际版本命令均成功，版本均为 20.1.2 |
| 关键程序共享库加载 | `ldd` 检查没有缺失库，记录了实际解析的 16 个库文件身份 |
| LLVM IR → 目标文件 → `llvm-ar` / `llvm-ranlib` → C / LLD 可执行程序 | 编译、归档、链接、执行成功，标准输出 `llvm20-c-ir=42`，退出码 0 |
| C++20 / LLD 可执行程序 | 使用 `unique_ptr`、`vector`、iostream，编译、链接、执行成功，标准输出 `llvm20-cpp=42`，退出码 0 |
| 生成物检查 | 两个可执行程序均由实际 `llvm-readobj` 识别为 x86-64 ELF |

20 个进程检查的完整命令、原始 stdout / stderr、返回码及观察到的耗时位于 `probes/` 和 `probe-summary.json`。探针源码、对象文件、静态库和可执行程序一并保留。

## 当前边界

本次宿主为 **Debian 13 x86-64**，C / C++ 标准头文件和运行库来自现有 **GCC 14.2**。LLVM 软件包恢复到了上述精确字节版本；这不等于重建了旧 Ubuntu 宿主的全部身份或全部传递依赖。范围是本机工具恢复及小型原生程序的启动、编译、链接、运行，不代表完整 Hepta 回归、跨目标、物理设备或 P0–P7 全部关闭。

本任务未修改源码仓库、Rust 工具链、先前官方 full-release 审计产物或系统包配置。当前源码功能验收由对应任务继续执行。

第一次检索只查 `universe`，没有找到位于 `main` 的 `libllvm20`，因此帮助程序退出 1。原始脚本和输出保留在 `development/selection-attempt01/`；修正为认证两个索引后完成。该记录是工具恢复程序的一次查询失败，不是编译器或 Hepta 验收失败。

## 证据文件

- `summary.json`：当前结果和边界。
- `selected-packages.json`、`downloaded-packages.json`、`historical-package-comparison.json`：精确软件包、原始索引条目、下载记录及历史身份比较。
- `provenance/`：恢复出的旧记录、新取得的签名与索引、认证结果，以及源码提交 `699de39a8e92e0f083df316ecc5333fb3ecf8571` 的工作流原文绑定。
- `installed-files.json`、`extraction-receipt.json`：实际解压内容和读回结果。
- `processes/`、`probes/`、`stage-execution-receipts.json`：原始进程记录。
- `llvm20-restoration-metadata.tar.gz`：上述小型证据及恢复辅助程序的完整包；归档清单和读回回执由 `metadata-retention.json`、`metadata-archive-receipt.json` 记录。

原始 `.deb` 文件和解包中间 `.tar` 均仍保留在当前工作区的 `packages/` 与 `data-archives/`。元数据归档不重复收录这些大文件或整个安装目录；认证索引、软件包官方 URL 与 SHA-256 足以定位重新下载的原始字节。
