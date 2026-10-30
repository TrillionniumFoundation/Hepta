# 发布后 CI 与测试修正补充

本补充记录 [PR #399](https://github.com/TrillionniumFoundation/Hepta/pull/399) 的后续实际观察。四条完整 CI 的测试提交均为 `1c13caeb08993fcbb2c4d64e6b10f22f3356c18f`。原先的源码、模型、四臂性能和失败结果保持原字节；本补充不改写它们的分母或资格。

## 1c13 的四条最终结果

| 工作流 | Run | 最终结果 | 实际范围 |
| --- | --- | --- | --- |
| C 应用的原生宿主资格 | [41017484034](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41017484034) | success | Linux x86_64 与 AArch64 各自实际执行 |
| 六类退出与源码应用 | [41017484010](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41017484010) | success | 277/277 安全边界、354 回归、449/449 选定标量验证义务 |
| CRC 有限上下文比较 | [41017483894](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41017483894) | failure | 登记的 120 秒总墙钟预算耗尽，未完成固定分母 |
| 原生 NDU 集成 | [41017484079](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41017484079) | failure | 1,000 tests 中 1 个旧 continue 拒绝断言失败，0 errors / 0 skipped |

这些是四条工作流，不是四份互相独立的语言安全证明。各测试集合存在重叠，不能相加当成独立测试总数。完整 CI 在该提交上未通过；release qualification 仍为 false。

## 实际双架构宿主进展

每种架构各运行 48 个功能输入，经 HIA LLVM、原始 Clang C 和 GNU C 三路执行，共 144 次函数调用；它们位于三个批量功能进程中，不是 144 次进程启动。资源部分为 16 组合、两路执行，共 32 次调用。相同的 12 项宿主控制分别在两种架构通过。

AArch64 由实际 `uname=aarch64`、三份运行时 LP64 ABI 探针、编译目标 `aarch64-unknown-linux-gnu`、ELF machine 183 和直接进程记录相互印证；x86_64 对应 ELF machine 62。每架构的 197 个工件、51 条命令的 102 份原始流、功能值和分配/释放/live=0 观察均经过独立只读核对，6,490 个源码文件及捕获输入前后一致。

这是有限的 Core→目标 LLVM object→scalar C ABI 应用资格。它使用 checksum 后测试循环维护 profile，与本地 96 组合的 ring-buffer 维护实验分开。没有据此宣称指定物理板卡、MMIO、DMA、中断、设备恢复、整进程 RSS、WCET 或一般 AArch64 shared-image/JIT 已通过。详见 [HOST_AUDIT.json](native-hosts/HOST_AUDIT.json) 及两份原始 ZIP。

## 六类退出与源码应用

从保存的原始归档确认：277/277 canonical 方法通过；354 个有限回归零 failure/error/skip；449 个选定 scalar lowering obligations 均 verified，unknown=0、refuted=0。范围仍由该登记形状与输入域限定，不构成任意源码到机器码精化定理。

该 CI 的 Agent 条目是 reference/hostile 工程控制，均为 `model_requests=0`。它们不能算模型成功，也不覆盖或修改原先实际 frontier pilot 的 3/3 资格、14/16 主实验和 23 次请求。

62,118,935 字节的原 ZIP 与 GitHub API digest 一致。为保存实际成员而避免展开副本，原始 3,696 个成员、220,280,134 字节被逐项哈希后重打包为 7,583,496 字节的 tar.xz；内存和最终落盘两轮逐成员核验均通过。每个成员的原字节保留，tar 元数据经过规范化，因此不声称可以逐字节重建原 ZIP 容器。详见 [ARCHIVE_SUMMARY.json](six-outcome/ARCHIVE_SUMMARY.json)、[完整 manifest](six-outcome/artifact-12960198980.manifest.json) 与 [归档](six-outcome/artifact-12960198980.tar.xz)。

## CRC 失败保持失败

52 项边界控制通过后，完整研究在 120.642876251 秒记录到 `E_HIA_CRC_STUDY: registered study deadline exhausted`。登记总预算为 120 秒；这不是 GitHub 的 30 分钟 job timeout。

固定分母是 210 observations / 2,856 contexts。实际完成 164 observations，另一个完成 64 个请求中的 14 个，45 个尚未开始；2,194 个 context 已尝试并保留完成记录，662 个未尝试。

已保留的 2,194 份 context 记录均有成功退出、完整 prefix 和确认清理，bank 释放完成，源码前后相同。这些前缀事实不能替代完整分母，不能给出完整经济性结果，更不能把该工作流改报为通过。没有放宽预算、缩减样本、抑制非零退出或重跑取优；当前也没有证据把速度原因唯一归于环境或某个实现改动。详见 [DIAGNOSIS.json](crc-context/DIAGNOSIS.json) 和保留完整原始成员的 [artifact.zip](crc-context/artifact.zip)。

## 原生 NDU 集成中的旧断言与后续修正

四种 NDU bridge 均构建成功，但完整回归在旧方法 `test_uninitialized_local_and_unsupported_continue_are_rejected` 失败：它仍要求 `int f(int x){while(x>0){--x;continue;}return x;}` 以 `E_C_STATEMENT` 拒绝，而本轮明确集成的有限控制流 profile 已支持这一程序。

同一份 1,000 项失败日志中，新 loop-jumps 六个用例以及更新的嵌套作用域/跳转用例均通过，包括真实 C/C++、VM、LLVM 对照与 `goto/switch`、变异条件、未初始化读取和过度展开的拒绝。随后 clean-source 创建步骤被跳过，后续步骤因目录不存在再次失败；这是级联错误，不能代表未执行的 qualification 已通过或发生语义失败。

旧发布源码 `37d3…` 的同类失败单独保存在 `history-native-ndu-37d3/`，没有用于代替当前 `1c13…` 的结果。完整诊断见 [NDU_AND_SIX_OUTCOME_DIAGNOSIS.json](NDU_AND_SIX_OUTCOME_DIAGNOSIS.json)。

已在独立工作树完成最小测试修正，并发布到 PR #399 的 [e0ab595468d67bcf95485eacd22cea8ff332520c](https://github.com/TrillionniumFoundation/Hepta/commit/e0ab595468d67bcf95485eacd22cea8ff332520c)：唯一变更为 `tests/test_c_project.py`，生产实现、registry、安全 contract、协议和预算均不变。

原未初始化读取及 `E_C_UNINITIALIZED` 断言保留；原 while/continue 源码保留，改为断言 `frontend_checked_not_native_qualified`、native/differential 仍为 `not_run`、广泛 proof claims 仍为 false。另以 8 个有定义的正/零/负输入比较原 C、Core VM 和直接 LLVM 结果。

实际 red 为原方法 1 failure；修正后完整 `test_c_project` 与原 `test_hia_c_loop_jumps` 两模块 **41/41 通过，0 failure/error/skip**。独立审阅逐一核对旧方法 AST、原 fixture 和日志。原 1,000 项失败不改写；未来相同 104 个模块预计 1,001 个方法只是计数预期，不是已执行结果。新提交的完整 CI 资格不能由这 41 项或旧报告继承。

本地修正 commit 为 `a5bb127019d57cb0afd9b3dd2c51df766a902e76`；远端 metadata 产生 `e0ab595…`。二者 tree 均为 `d4ff4cff01ce8010bab0ae7a40da664d07188e0b`，parent 均为 `1c13…`。实际绿色测试发生在 base 加精确测试文件的候选上，候选字节与随后提交相同；没有改写执行时的 source identity。详见 [修正摘要](continue-test-fix/SUMMARY.json)、[独立审阅](continue-test-fix/INDEPENDENT_REVIEW.json) 和 [发布身份](TEST_FIX_PUBLICATION.json)。

本补充保存在独立 evidence 分支，测试修正已进入原 PR。证据归档不会再改动该 PR 的代码 head 或触发重复旧 benchmark 来获取更好成绩。所有经济性、真实项目人时、完整 Agent 生产力和指定设备要求仍按原报告保持未闭合。
