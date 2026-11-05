# 已执行硬件与 ABI 日志独立复核

本复核读取并逐一核对了 17 份完整原始 job log 的字节数与 SHA256，共 856,758 字节。未运行编译、测试、模型或网络请求。

公开源码 `3102c2bb6cd819c27aef36cc927c23b39b279204`，tree `d47a711461dc66d4606bdc9659203889e205d6c7`，对应原始本地测量源码 `5ee6d8fec0e5c72d87a36dbed60789de211abf1b`。后续候选不在此证据范围内。

OS 来自运行器实际日志；架构结合实际工具链安装输出、运行器镜像和完成的 native-host 检查。任务名称只用于索引。CLI 参数属于已执行步骤的配置，不能当作编译器自报版本；本表没有从矩阵标签推断 CPU 型号或其他主机结果。

## 实际执行表

| Job | 实际 OS / 架构依据 | 编译器 lane | 日志可直接支持的结果 |
|---|---|---|---|
| [127061903386](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903386) | Ubuntu 24.04.5 LTS / aarch64 | clang-20 / ld.lld-20 | 17 return + 1 bounds abort + 1 null + 2 wrong-Core；4 alloc / 4 free / 0 outstanding |
| [127061903492](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903492) | Microsoft Windows Server 2025 10.0.26100 Datacenter / x86_64 | clang | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903505](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903505) | Microsoft Windows Server 2025 10.0.26100 Datacenter / x86_64 | msvc | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903538](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903538) | Ubuntu 24.04.5 LTS / aarch64 | clang | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903568](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903568) | macOS 15.8.2 24H232 / aarch64 | clang | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903589](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903589) | Ubuntu 24.04.5 LTS / x86_64 | gcc | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903612](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903612) | Ubuntu 24.04.5 LTS / x86_64 | clang | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903670](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915915/job/127061903670) | Ubuntu 24.04.5 LTS / aarch64 | gcc | ABI passed；stb component passed；fixed-array 通过 1，VLA 拒绝 1 |
| [127061903055](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903055) | Ubuntu 24.04.5 LTS / aarch64 | clang | 2 upstream versions passed；16 contract tests OK |
| [127061903292](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903292) | Ubuntu 24.04.5 LTS / x86_64 | clang | 2 upstream versions passed；16 contract tests OK |
| [127061903343](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903343) | Microsoft Windows Server 2025 10.0.26100 Datacenter / x86_64 | msvc | 2 upstream versions passed；16 contract tests OK |
| [127061903358](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903358) | Ubuntu 24.04.5 LTS / aarch64 | gcc | 2 upstream versions passed；16 contract tests OK |
| [127061903363](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903363) | Ubuntu 24.04.5 LTS / x86_64 | gcc | 2 upstream versions passed；16 contract tests OK |
| [127061903372](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903372) | macOS 15.8.2 24H232 / aarch64 | clang | 2 upstream versions passed；16 contract tests OK |
| [127061903448](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915863/job/127061903448) | Microsoft Windows Server 2025 10.0.26100 Datacenter / x86_64 | clang | 2 upstream versions passed；16 contract tests OK |
| [127061903117](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915881/job/127061903117) | Ubuntu 24.04.5 LTS / x86_64 | clang-20 / gcc (executed CLI; detailed identities in artifacts) | controls 与 native LLVM/C qualifier 步骤 success；详细输出已重定向，数量未知 |
| [127061903330](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41971915881/job/127061903330) | Ubuntu 24.04.5 LTS / aarch64 | clang-20 / gcc (executed CLI; detailed identities in artifacts) | controls 与 native LLVM/C qualifier 步骤 success；详细输出已重定向，数量未知 |

## 拒绝、清理与恢复的范围

7 个普通 ABI job 的实际终态 stdout 同时报告 native-host passed 与完整 stb_divide 组件 passed；原始类型预检直接打印 fixed-array 通过，以及 `E_C_VLA_PARAMETER` 拒绝通过。各 job 的 adapter、捕获进程所有权和序列化 AST 控制另有逐项日志。它们的 unit-test 数量不等于原生 C 调用数量。

独立 Linux AArch64 HIA job 直接打印 17 个 reference/native 返回用例、1 个真实 bounds abort、1 个 null refusal、2 个 wrong-Core controls，以及 4 次成功分配、4 次释放、0 个未释放分配。

7 个 C++ job 直接打印 `versions_passed: 2` 与无错误的 passed 结果。16 个 host/evidence contract tests 的 OK 是另一组观察；日志没有打印具体上游 tag，也没有逐项输出所有 native 调用，因此这里不补写版本名或调用数量。

2 个 captured-C job 的完整控制与 qualification 输出重定向到 artifacts。日志与原始 step metadata 可确认实际命令和步骤成功，但本复核没有打开那些 artifact payload；其完整 receipt、拒绝数与 native case 数在本 JSON 中为 null。

这些日志支持的清理包括 allocation/free 统计和编译子进程所有权控制。它们没有建立 host-region epoch 恢复或双恢复者竞争的结论；那类主张必须引用独立恢复实验。

14 个 ABI/C++ lane 的日志记录了原生 Rust 1.90.0 安装与实际调用参数；这是既有源码参考/互操作角色，不能写成 AOT/NDU/Agent 科学实验所用的 Rust 1.95。JSON 中的 unittest 秒数是各测试子进程自报的嵌套时钟，不是完整 CI 墙钟或整项研发成本，也不与其父 job 时间相加。

## 可审计引用

`REVIEW.json` 对每个 job 保留原始 log 路径、完整 SHA256、实际 OS/架构输出、执行命令行号、终态 JSON 行号、全部 unit case 输出及原始 step 状态。原始日志内容未改。

本复核不把成功 CI 升格为未审阅 artifact 的成功，也不把该 head 的 CI 成功追溯用于覆盖 desktop 的 600 秒证明验收超时。未证明普适 ABI、任意 C++ 自动迁移或全部七轨闭合。
