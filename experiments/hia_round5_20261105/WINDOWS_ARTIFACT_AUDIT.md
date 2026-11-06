# Windows 实际 CI 产物审计

四份原始 GitHub Actions ZIP 均匹配 API 给出的 SHA256 和大小，最终 JSON、源身份、原生产物、实际输出及拒绝控制已逐项核对。此次是只读审计：没有执行 ZIP 中的程序，没有重跑 CI，也没有模型请求。

公开 commit 为 `67da0ab0a51203f6f640c4459bc15bef442885b8`，tree 为 `a5239982f9fd8f08ab3a6e791147fc989e8d9df6`。它与 Linux 实测 commit `0a06ef4f0894681af92b0caefba0704c1278d2cc` 的完整树一致，但保留为不同 commit、不同执行队列和不同平台资格。

| 实际 profile | C/C++ 工具版本 | Artifact ID | 校验原 retained 文件 | 单独校验原 streams |
| --- | --- | --- | --- | --- |
| Clang / C++ 上游集成 | clang version 20.1.8 | 13462982914 | 74 | 30 |
| MSVC / C++ 上游集成 | MSVC _MSC_FULL_VER=195136260 _MSC_BUILD=0 | 13462714569 | 70 | 26 |
| Clang / Native ABI + STB | clang version 20.1.8 | 13464400891 | 138 | 24 |
| MSVC / Native ABI + STB | MSVC _MSC_FULL_VER=195136260 _MSC_BUILD=0 | 13462749878 | 139 | 20 |

共核对 421 个原 retained 文件和 100 份原始 stdout/stderr。四份 ZIP 的完整文件名、大小、SHA256、源/工具链身份与 GitHub job 元数据在 `WINDOWS_ARTIFACT_AUDIT.json`，其中最终报告 SHA256 为 `f476ede92f429fee7e84cddde4737530f9c0f9be99170ef42e7c449a61359cdc`。4×21,453 = 85,812 条 STB TSV 由独立的 Python 整数截断、向下取整和 Euclidean 商余数定义逐行读回核对。

## 实际支持的结论

C++ 两个 profile 都执行 nlohmann/json 3.11.3 与 3.12.0；每版本 98 cases，经 direct C++ 和实际 Hepta consumer 两条路线。错误、普通对象 live delta、32 个生命周期 cases、1,024 次并发调用、重复销毁、stale read 和有界取消状态均有真实 native 输出。错误代码产物实际运行后返回 2，并出现 mismatch 标记；不兼容返回类型由真实编译器以 `E_CPP_NATIVE` 拒绝发布。原始 read-only audit 的证据篡改负控也保留。

ABI 两个 profile 的两个优化等级各执行 181 次 foreign calls，并检查普通布局。错误 C echo 的实际产物被拒绝，三个类型不匹配负控被真实编译器拒绝。original-type preflight 只有两个 capture/类型检查 case，其中 VLA 被拒；它明确记录 native_program_executions=0。

STB 覆盖选定的完整 stb_divide 0.94 组件、generic 和 truncating 两种 macro 配置。每 profile 共 42,906 input-configuration pairs、514,872 次 native 函数观察、24 个 target-only 非法输入 trap 进程。原始 C 不接收未定义输入；普通 resource counters 前后均为零。wrong-but-resource-legal 目标实际执行后由功能 oracle 拒绝，新增不支持声明时整 bundle 拒绝发布。

## 必须保留的边界

- C++ consumer、ABI matrix object 以及两个 STB native targets 的实际 backend 都是 Rust。Windows STB 每个配置（generic / truncating）HIA native_requested/native_executed 均为 false，HIA 部分只有 58 输入/348 次 interpreter 函数观察；不能改写为 HIA LLVM AOT 已在 Windows 全量通过。
- 两个 Native ABI jobs 的第 10 步 `Check non-reaping POSIX leader and capture-read boundaries` 均为 **skipped**。此前后的 native 执行成功不改变这一事实。
- ABI 原资格器未保留 Rust 编译器完整 argv/raw streams 或临时 Rust 源字节；保留的是结构化 Rust receipt、canonical Rust input 和最终 object 的 SHA。这一证据边界在 manifest.scope 原文保留。
- C++ 普通对象 live delta=0，但报告明确记录 3 个 process-lifetime registry allocations。它不同于 P2 host-region 报告的 owner/library registry 全空。
- 原生 Windows runner 进程不是物理设备、MMIO/DMA/IRQ/GPU 或硬件故障恢复资格。有限 ABI、并发与取消案例也不是完整内存模型或全交错证明。
- 这里的 C++ 上游集成复用原生库及生成 bridge；没有把整个 nlohmann/json 改写成 HIA，也没有证明所有上游升级或开发成本收益。

## 归档

本审计的独立小包包含上述审计、API/job metadata、脚本与 100 份完整小型原 streams，不包含四个原始 CI ZIP、编译器、运行库或私有模型材料。原 ZIP 在远端对应 artifact-ID.zip 保留，API digest 和完整 member hashes 均有记录。审计过程中只读原文件。

对归一化路径后的源文件字节比对：四个 profile 合计匹配 1346 个记录，差异或缺失 16 个；详细逐项结果在 JSON，未做换行或内容归一化。

## 发布补注

上述 STB 统计单位是 generic / truncating 宏配置，不是两个上游版本。本独立网页稿修正这一术语；原始审计包中的原稿保持原字节。16 个 Windows 示例文件差异已进一步核验为精确 LF→CRLF，见 [SOURCE_EOL_NOTE.md](SOURCE_EOL_NOTE.md) 和包内 SOURCE_EOL_AUDIT.json；不将不同物化字节重新标记为相同。
