# macOS ARM64 原始 CI 产物独立审计

两份已完成 GitHub Actions 产物通过本次只读审计。实际执行范围是 **macOS ARM64 上的 Apple Clang 17 + Hepta Rust 1.90 后端**。STB 的 HIA 路径仅有 **696 次解释器函数观察**，两配置均明确记录 native_requested=false、native_executed=false；本报告不构成 HIA LLVM AOT 的 macOS 验收。

## 来源与身份

- 发布提交：67da0ab0a51203f6f640c4459bc15bef442885b8；GitHub commit API 独立返回 tree a5239982f9fd8f08ab3a6e791147fc989e8d9df6。
- Linux 全组合测量提交：0a06ef4f0894681af92b0caefba0704c1278d2cc。两提交 tree 相同，但其提交身份与资格 profile 分开保留。
- 两个 job 均在 macos-15 / aarch64 / clang 配置实际完成 success，原始报告记录 Darwin 24.6.0、Python 3.13.17、native_host_process。两个 Visual Studio 环境设置 step 为 skipped；日志中 73 个 unittest 均有逐项 ok 和 Ran/OK，未见内部 skipped。
- C++ 报告登记的 204 份源输入、STB 报告登记的 477 份 implementation 文件，均与本轮冻结 Linux checkout 的相应字节 SHA256 一致；未把此子集核对扩称为独立重建整个 Git tree。
- 本次只读取 ZIP、报告、日志和冻结源输入，未运行 ZIP 内原生程序，未重跑 CI、benchmark 或 model。

| 产物 | workflow run / job | 字节数 | ZIP SHA256 |
| --- | --- | ---: | --- |
| C++ 13462959486 | 42131297029 / 127608285065 | 585007 | 0f64ae7b5febb17be4f83377a0eb0454fb6431356de743a532c6e498573ffdad |
| ABI + STB 13463139429 | 42131297248 / 127608287303 | 1959656 | 6afa7ad97ebd44554162b1cdad61e6894de1ed609b2955ac5710df4905157434 |

原始 ZIP 的实际字节数、SHA256 均与 GitHub artifact API digest 一致。完整 ZIP 留在远端 macos-gha-artifacts-r1 目录；公开小包保留 API 元数据、逐文件哈希、报告和小型输出流，不重复装入大 ZIP、原生二进制、TSV 或完整语料。

## 实际原生结果

| 项目 | 已有实际执行与本次核对 |
| --- | --- |
| nlohmann JSON 3.11.3、3.12.0 | 每版本 98 个 direct/Hepta case 的 status、value 与 live_delta 对齐；两份执行 stdout JSON 与观察报告一致，return 0，执行文件 SHA 不变；消费者为 Rust 对象，经 C ABI 调用保留的原库。 |
| C++ 生命周期 | 每版本 lifecycle 32、borrowed input overwritten 32、duplicate destroy 32、stale read 32、pointer guard 4、refused mutation 64、malformed constructor 1、有限 concurrent calls 1024。ordinary_live_delta=0，但每版本 **registry_ordinary_allocations_retained=2**，不能改写成所有分配归零。 |
| C++ 取消与负例 | 每版本 requested 7 / committed 3 / replayed 0 / value 107；实际错码程序 return 2；不兼容签名在 C++ 编译阶段以 E_CPP_NATIVE 及 HEPTA_CPP_METHOD_RESULT 诊断拒绝。此取消观察不代表异步外部调用可任意取消。 |
| C ABI | -O0、-O2 两份 ARM64 Mach-O 可执行文件各有 181 个 foreign calls，layout_checked=true，保留原始输出与 return 0；生成对象为 Rust backend。三个 ill-typed declarations 拒绝，编译后的 wrong echo 以非零状态拒绝。 |
| 原始数组类型预检 | fixed_array 和 vla_entry 两个预期 admission/refusal case 通过；此预检明确 native_program_executions=0。 |
| stb_divide | generic 与 -DC_INTEGER_DIVISION_TRUNCATES 两配置各执行 21,453 个输入；同一 21,453 唯一输入集构成 42,906 个 input/configuration pairs、514,872 次报告中的原生函数观察，包含原协议的重复 original/target 调用。 |
| STB 独立整数 oracle | 两份保留 TSV 各 21,453 行，每行 a/b 和三组六整数均逐项对独立整数除法/余数公式；普通原生过程各 return 0，输出 summary 与原始记录一致。两 TSV 的 SHA 相同，不能当作两个独立语料集。 |
| STB 边界与资源 | 两配置各 12 个 target-only trap 子过程，合计 24 个均 return -6；输入为除零及 INT_MIN/-1，均有 ENTERED_SAFE_TARGET，原 C 未调用。错码目标 return 2，whole-bundle refusal 未发布 partial bundle。声明的 STB allocation probe 前后均 [0,0,0,0]，其作用域独立于 C++ 保留 registry。 |
| HIA 解释观察 | 每配置 58 个解释器输入、348 次函数观察，合计 **696 次 interpreted**；native allocator counters 未观察。 |

## 独立校验与原始证据边界

本次审计对 2 个 ZIP 的 **245 个普通文件**建立 SHA256 与 Git blob 身份清单；核对 **212 个声明 retained 文件**的哈希及其目录闭包，校验 **19 个 ARM64 Mach-O** 的文件类型和有界 load-command 表；交叉核对 **54 份单独保留的 stdout/stderr 文件**及 **40 个 C++ 嵌入字节流记录**。原始 STB subprocess stdout/stderr 是报告内的解码字符串，公开包按原报告字节保留；本次为其 UTF-8 表示另记哈希，未伪称其为另存的原始二进制流。

实际 Rust 目标为 aarch64-apple-darwin，编译器为 rustc 1.90.0，二进制 SHA256 b2011d06d5c7efff7b48b1e1aec6106989e44f3a5ad1d171e06a41c0fbc3ffea。C/C++ 是 Apple clang 17.0.0，arm64-apple-darwin24.6.0，编译器二进制 SHA256 8291fbbbaa75761bb649970a16af2ef84b4afd5da0bc133f4d8915f0f2f63e98。这些工具链身份由原 job 的保留记录提供；Rust 自身使用 LLVM 20.1.8 不等同于项目 HIA LLVM lowering。

Native ABI 原资格程序未保留 Rust compiler argv/raw streams 及临时 Rust 输入的原始字节；它保留 structured backend receipt、canonical input 与最终对象哈希。本次保留该限制，不补造编译账本。

已有日志包括 C++ 16 tests；native-host contracts 17、capture budgets 16、POSIX/Darwin ownership 20、original-type process 4 tests，全部 Ran/OK。macOS POSIX/Darwin step 实际成功，其有限测试证据不能外推为所有并发交错、一般内存模型定理或硬件故障恢复。

本证据不证明完整外库已被重写、不证明 foreign memory/lifetime 一般安全、不证明全部上游配置或版本兼容，也不测维护成本或 AOT 性能改善。STB 未覆盖的配置（含 C_INTEGER_DIVISION_FLOORS 等）按原 scope 保留；真实硬件、设备与故障恢复仍需各自独立 profile。

## 文件与过程

- MACOS_ARTIFACT_AUDIT.json：完整独立审计，含每个 ZIP 文件、retained 文件、Mach-O、源码、日志、有限 oracle 与原始 claim 边界。
- GITHUB_METADATA.json / GITHUB_LOG_AUDIT.json：API 身份和只包含测试结果的安全日志摘录；不包含临时下载 URL 或认证配置。
- audit_macos_artifacts.py / AUDIT_REGISTRATION.json / AUDIT_TERMINAL.json：只读解析实现、执行前身份与权威终态。
- 原始审计 job 1a1ae600956-fc05-5f52：succeeded，exit 0，output complete/durable，terminal publication confirmed。解析 CPU 0.932609996 秒、wall 1.064072751 秒；这些是审计成本，不是产品性能测量。
- public-manifest.json / PUBLICATION_RECEIPT.json：公开包清单及独立 fresh restore 字节一致性收据。

原始 job 链接：[C++ job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42131297029/job/127608285065)，[ABI + STB job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42131297248/job/127608287303)。
