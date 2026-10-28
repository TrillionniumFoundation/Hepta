# HIA 资源、迁移、NDU 与显式状态：同源验收记录

本轮交付的是已实现、已实际执行并有独立核对的增量。**同一源码版本的六项本地集成门槛通过；用户提出的六个研发阶段尚未全部关闭。** 尤其是 NDU 的增量价值、运行时重优化净收益、任意存活资源迁移和完整语言安全证明，仍不能宣布成立。

## 源码与证据身份

| 对象 | 固定身份 |
| --- | --- |
| 已发布并实际验收的源码 | `389f33b0dccec3fcbb0e2205b3cb1f07bd3ff9c4` |
| 源码 tree | `0f6bff924e6926eb7e4031828426c960c129465b` |
| 源码父提交 | `817713b163b6812a6516179951412b4a6c93ae2b` |
| 源码分支 | `codex/hia-contract-integration-20261027` |
| 审阅入口 | [Draft PR #329](https://github.com/TrillionniumFoundation/Hepta/pull/329) |
| 本轮证据分支 | `codex/hia-resource-ndu-evidence-20261028`，只增加 `evidence/` 文件 |
| 独立 NDU 实验源码 | `01310b2e6c1676e73cd0f338fcf0b8bf072d3fe4`，不是本轮集成提交 |

源码相对 `817713b` 修改 49 个文件。源码发布后，在独立冻结工作区运行验收；执行前后 **3,540 个 tracked 文件和 244 个外部工具／上游文件身份保持一致**。资源和 musl 专项使用同一个 `389f33b` 工作区。完整回归耗时约 865.66 秒，外层命令成功退出。

NDU 的独立实验发生在集成之前；它的原始 source commit 保留为 `01310b2`，没有改写成集成提交。归档内的 `source/development-source.bundle` 保存资源、迁移、NDU 和本地集成准备的四个确切开发提交；bundle 以前述 `817713b` 为已具备的前置对象。其中文件 tree 与正式集成源码的对应关系也有单独发布记录。

历史 `817713b` 的验收和 CI 补包仍在[上一版证据](https://github.com/TrillionniumFoundation/Hepta/blob/de1bbb5b0d7e8ef1f3fc43900115d472be1eed92/evidence/hia_contract_integration_20261027/README.md)。这些历史结果没有计入本轮分母。

## 六项工作的验收状态

| 顺序 | 本轮已成立的结果 | 尚未关闭的条件 |
| --- | --- | --- |
| 1. 统一 HIA 语义入口 | 同一提交上的真实前端、canonical verifier、Python/Rust VM、原生后端和两个原生 NDU 桥通过完整集成验收；实际源码与外部输入身份未变。 | 只对声明的 profile 成立；没有完整语言或全后端 refinement 定理。 |
| 2. 资源核心与 Rust 差分 | Rust 执行器扩展到六个 bulk 操作与 v7 chain；822 份配对执行账本一致，25 个非法输入被拒，primitive 控制在两套条件下稳定拒绝；组合资源、预算、失败及声明的返回投影有真实执行。 | primitive 跨调用 Loan 返回仍拒绝；源码返回投影 helper 通过内联降低，不等于通用返回借用 ABI。陷阱／预算中止不冒充自动展开清理。 |
| 3. 优化前后验证 | 资源合法性与行为保持独立；可接纳候选重新做 canonical 检查和全输入证明。实际编译的资源合法但结果错误候选被拒绝；unknown 不接受旧证明收据。 | 原生探针及 Core 等价性不是 LLVM／机器码全链路证明。 |
| 4. 有限动作 NDU | 实际原生桥、预先冻结的候选／预算／输入／成本口径、六策略对照全部执行，零删样；控制器避免 18 次无价值证明尝试。 | 主指标失败：36 个 episode 全部 abstain，未证明相对固定策略和简单搜索的增量价值。 |
| 5. C/C++ 迁移与 ABI | 完整 musl 两函数组件实际翻译；同源 C++ scoped 四路线和七平台原生 ABI 执行通过；全项目声明盘点和不支持项拒绝仍有效。 | 不是全 musl 或通用 C++ 重写；新增 musl 只在 Linux x86-64 实际执行。七平台 ABI profile 的通过不能替代这个组件的七平台迁移验收。 |
| 6. 多版本与状态 | 增加一个显式标量状态会话，16 项真实 native 测试覆盖发布、回滚、取消、并发 revision、失败计费和旧版本租约寿命。 | 尚无可接纳净收益；不支持活跃 heap/loan/stack 的迁移、持久化恢复或任意低层指令搜索。 |

## 1. 同源完整回归与独立审计

| 门槛 | 结果 |
| --- | --- |
| 实际工具与 Linux sealed artifact 能力 | PASS |
| ranking NDU 固定上游、源码与原生桥身份 | PASS |
| recursive NDU 固定上游、源码与原生桥身份 | PASS |
| Rust resource crate | **57 tests，0 fail / ignore / filtered** |
| 完整 Python regression | **2,785 tests，0 fail / error / skip** |
| 合并契约与关键 profile 覆盖 | PASS，直接从同一次完整运行取子集 |

独立审计从原始 verbose 方法记录和 footer 重算 Python 分母，从 Rust binary summaries 和各测试记录重算 Rust 分母；也从冻结 Git 对象解析关键模块清单并逐文件重算源码摘要。精选模块、16 项状态测试及组件专项不叠加成一个更大的“总测试数”。

[qualification.json](qualification.json)、[full-audit.json](full-audit.json) 和 [acceptance.json](acceptance.json) 保留完整身份和判定。组件／平台审计的逐比较次数只用于说明审计覆盖，不能称为新增测试数量。

## 2. 资源语义：执行账本与拒绝边界

实现继续使用现有 Rust `Machine`，没有另造一套更宽松的解释器。新 profile 是 `bounded-cfg-owned-memory-v3`，旧 byte-owner v2 行为保留。

- byte bulk 操作先验证完整范围再写入；copy 使用固定大小 scratch，重叠 move 按 memmove 语义处理。
- chain 使用平坦节点 ID，并将每节点 24 字节计入同一资源预算；包含 owner 转移、内部调用、head loan/reborrow、pop 和逐节点析构计费。
- 12 个专项测试实际产生 **822 份 Python/Rust 完整账本对照**：379 returned、50 trapped、393 budget_exceeded。194 份走 v2，628 份走 v3。
- **25 个不同非法输入**的原始字节、摘要和拒绝记录经过独立核对。其中 primitive 控制在两套预算／失败条件下执行，合计 35 个 Rust 负向进程；两者不是同一个分母。
- 379 个正常返回的资源归零。50 个 trap 中有 35 个、393 个 budget stop 中有 369 个保留存活资源，报告如实记录中止现场，未把它们改写成已完成清理。

声明的取消协议是协作式协议。primitive 跨调用 Loan 返回仍不支持；源码层经检查的返回投影会内联进 canonical 路径。完整资源执行器说明见[固定源码文档](https://github.com/TrillionniumFoundation/Hepta/blob/389f33b0dccec3fcbb0e2205b3cb1f07bd3ff9c4/docs/HIA_RUST_OWNED_MEMORY_VM_20261028.md)。

## 3. 证明与实际 native 行为分开验收

新增守卫特化保留真实可执行的 guard 和通用 fallback，并对 SSA 名称重新映射。单次仅允许有限个守卫假设。条件不命中时仍执行原程序，不把训练输入当成全体输入。

符号编码把单一到达路径的参数绑定直接接到该路径的值；到达条件、陷阱条件、分支和首个陷阱顺序保留。旧／新编码等价测试以及独立 **3,072 组**编码、canonical VM、整数规格交叉检查通过。强制 solver unknown 后，已有 proved 收据仍不能绕过重新验收。

经济性下界只允许提前放弃候选：被裁剪候选保持 `proof: null`、`equivalence_proved: false`，不获得执行权限。真正被选中的候选仍需 fresh proof 和最终成本门槛。NDU 提供建议，不能修改验证器、成本门槛或授予自己执行权限。ranking 和 recursive 两个既有 pin／协议继续分别核验；未把第三种不兼容协议覆盖到现有桥。

musl 与 C++ 专项另含实际编译的错误控制。资源合法、甚至 alloc/free 数量相等，都不足以通过功能和析构顺序验收。这些是实测证据；完整编译器 refinement 和全语言 soundness 仍为 false。

## 4. NDU 原生实验：负结果及成本分母

完整冻结协议、输入、45 个训练 batch、36 个 holdout episode、证明、反汇编、旧失败和回放记录见[独立 NDU 实验目录](../hia-specialization-01310b2/SUMMARY.md)。本包额外保留实际执行的三个 `.so`、驱动和原始 NDU bridge 二进制及其构建输入。

实验工作负载为自写 u32 的 8 轮 wrapping add/xor。两个候选分别对 mask=0 和 mask=all-ones 特化，均通过全输入等价证明；三份实际机器码不同。但对应 hot profile 中，训练基线约 **2.61 ns/call**，特化约 **3.05–3.18 ns/call**，更短机器码没有转化为更快运行。

六个策略各执行 3 个 profile × 2 次重复，每个 holdout 为 2.5 亿次实际调用，合计 90 亿次；**36/36 完成，36/36 保留基线，0 次发布**。没有更换 profile 或重复跑到候选获胜。

| 策略 | 每策略 episode | 发布 | 含共享成本 warm 中位数（秒） | 再计 NDU 冷构建摊销（秒） |
| --- | ---: | ---: | ---: | ---: |
| fixed_stop | 6 | 0 | 1.677540 | 1.677540 |
| fixed_zero | 6 | 0 | 1.700684 | 1.700684 |
| fixed_ones | 6 | 0 | 1.662918 | 1.662918 |
| fixed_selected | 6 | 0 | 1.649751 | 1.649751 |
| light | 6 | 0 | 1.675004 | 1.675004 |
| NDU | 6 | 0 | 1.650057 | 3.462571 |

共享训练与构建成本为 816.280115 ms；NDU fresh target 冷构建 10.875083207 秒，严格只摊到六个 NDU episode。每次独立部署全额承担共享表成本；这不表示 campaign 真的把共享表重复构建 36 次。warm 差异出现在实际运行相同基线的不同 episode，不能归因于 NDU 加速。

预先冻结的主指标以配对冷摊销成本比较各控制组，并要求每个 profile 有正增益。NDU 对 light 的配对成本增加 **1.807760729 秒**，未通过主指标。直接部署基线另有账本，不被强加无需执行的搜索／训练成本：其中位数 **0.861260299 秒**；NDU 相对它的配对 warm 成本增加 0.805626971 秒、冷摊销增加 2.618140839 秒。

单独的控制器回放隔离 preproof pruning：九对运行均调用真实 NDU、均 abstain；旧 ranker 尝试 18 次 fresh proof，新 ranker 为 0。观察墙钟中位数约 162.20 → 12.13 ms，但主机并发负载未隔离，**可确定的是少做了 18 次证明，不能把墙钟变化宣称为可归因的 NDU 或原生程序加速。**

独立审查还发现八个当前空目录，其路径精确对应八个完成 episode。原运行未记录删除 errno 或关闭后的目录／FD 快照，且当前 inode 时间戳不能直接解释创建和删除过程。原因未确定；既不能据此断言 FD 仍存活，也不能宣称磁盘零残留。归档保留只读审计，没有删目录或重跑 campaign 改写观察。

## 5. 实际 C/C++ 迁移与平台证据

### 完整 musl 小组件

新前端能力支持缺省 initializer 的 `for`、语句位置 comma 顺序以及直接 return 中的惰性三元表达式，同时继续拒绝不支持的控制流和表达式。捕获阶段保留语义编译选项、原始 include spelling/cwd/symlink 关系，并拒绝隐藏 calling-convention attribute 和数组／VLA 参数退化等未声明 ABI。

未修改 musl 1.2.5 的完整 `memcmp.c` 和 `bcmp.c`：**2 个函数、319 bytes、16 行**。两个平台适配头和四个 pointer contract 是明确编写的适配工作，未计为上游源码，也没有据此声称全自动、零人工或全语言低成本迁移。

每个 `-O0`／`-O2` 配置盘点并处理全部五个活跃项目声明（两个定义、三个原型）。同一个 **67,558 输入**的语料重复用于两个配置，形成 **135,116 input/configuration executions、810,696 native function observations**，不是 135,116 个不同输入。每个输入通过 Clang 原 C、GCC 原 C、生成的 Hepta → Rust native 三路线执行两个函数，并独立重算精确字节差值。

实际 C caller 链接和执行生成库；目标不链接原始 C 对象。实际编译的错误候选在第一个非相等字节控制上被拒绝。另有 12 个外部边界子进程控制、3 个整包拒绝控制，以及 authored Hepta owner 的 7 次调用：4 次分配／4 次释放、2 次真实分配拒绝、最终 0 live。

这些新增迁移实测只覆盖 Linux x86-64。FFI 调用者仍须保证指针的真实 extent、provenance、lifetime、初始化及无并发写入；数值检查不能证明所有外部条件。源码后端验证也不等于 HIA LLVM slice refinement。详见[固定源码说明](https://github.com/TrillionniumFoundation/Hepta/blob/389f33b0dccec3fcbb0e2205b3cb1f07bd3ff9c4/docs/C_MUSL_COMPARE.md)。

### 同一源码上的七主机与 C++ scoped CI

| 实际执行 | 已核对结果 |
| --- | --- |
| Linux x86-64 / GCC、Clang | 每主机 2 × 181 foreign calls |
| Linux ARM64 / GCC、Clang | 每主机 2 × 181 foreign calls |
| macOS ARM64 / Clang | 2 × 181 foreign calls |
| Windows x86-64 / MSVC、Clang | 每主机 2 × 181 foreign calls |
| 七主机合计 | **2,534 foreign calls、21 个类型拒绝、7 个实际错误 echo 拒绝、77 个 adapter tests** |
| C++ scoped native | **1,121 cases × 4 routes = 4,484 case-route executions** |
| C++ 每条路线资源合计 | 3,180 alloc = 3,180 free，398 refusals，最终 live=0 |
| C++ 错误控制 | alloc/free 相等但析构顺序错误仍拒绝；8 个 live 的泄漏控制拒绝 |
| 同源 verified selected regression | **219 tests / 26 modules，0 fail / error / skip**，是精选集，不是完整回归 |

七份原始 host ZIP 全部核对下载摘要及成员 CRC／SHA。它们保留报告和日志，**没有包含远程目标对象／可执行文件本体**；未把本地 ZIP 重算写成远程二进制重算。C++ 和 adaptive 的 verified ZIP 确实保留实际 ELF／sealed artifact 字节，并逐一重算。

verified CI 的源码文件身份未变，但工作区有报告中明示的 untracked artifact/upstream 目录，因此不称为 clean checkout。adaptive 只覆盖 empty-state pure-u64；其 `net_before_switch_ns = -213901942`，不具备盈利结论。最终 `closed=false` 是关闭前快照，未当作关闭后证据。

归档采集时，source `389f33b` 的 [host push run 40608034674](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40608034674) 和 [verified push run 40608034707](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40608034707) 均 success；[full push run 40608034666](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40608034666) 当时仍在运行。原始状态快照带有采集时间。本地完整验收已独立结束，不依赖等待远程完整 run。

## 6. 显式标量状态的多版本运行

新增 `ScalarStateSession` 复用现有 `ScalarMultiversionRuntime`、fresh 等价证明、原生 sealed artifact 和 generation lease。应用状态仅是函数第一个参数／返回值的同类型标量；候选必须对包括状态在内的全部 typed arguments 等价。

- `expected_revision` 是每次调用的必需参数。会话锁串行化转换，同 revision 的并发请求至多一个提交。
- 状态、revision 和最后收据作为同一个不可变记录一次提交；不自动重放。失败或执行后取消仍计入有限 native call 预算。
- 一次性取消 token 与提交共享明确的锁顺序；`cancel()` 返回 true 后不能再提交该次状态。已进入 native 的纯函数可以结束，其结果被丢弃。
- 发布／回滚与调用重叠时，旧 generation lease 继续固定实际执行代码。代码回滚保留已提交的数据状态。
- 会话关闭等待在途转换，但不关闭调用者拥有的公共 runtime；快照独立、历史有界。

16 个真实 native 测试覆盖整数域、取消、失败、并发、发布／回滚、关闭及旧代码 FD 生命周期。独立审查发现并修复了“native 完成后取消同时宿主异常”漏计失败的诊断问题；保留最初复现、修复后复现和原异常。无堆／借用／栈迁移、无持久化恢复和自动净收益保证。详见[状态协议源码文档](https://github.com/TrillionniumFoundation/Hepta/blob/389f33b0dccec3fcbb0e2205b3cb1f07bd3ff9c4/docs/HIA_SCALAR_STATE.md)。

## 证据内容与复现

[raw-evidence-manifest.json](raw-evidence-manifest.json) 为每个归档成员记录原始路径、字节数、模式与 SHA-256；原始记录不会因原始绝对路径在其他机器不存在而被改写。[SHA256SUMS](SHA256SUMS) 绑定本目录交付文件。交付容器按字节分为 [part01](raw-evidence.tar.xz.part01) 和 [part02](raw-evidence.tar.xz.part02)，运行 `python assemble_archive.py` 还原 `raw-evidence.tar.xz`。还原后为 14,182,632 bytes，SHA-256 `b9b271fa70326a95607c150cdd916942a412c5d3b6a7e56f1ea2d36f8240ee4e`。原始 gzip 元数据保存在 `assembly-gzip/`；[无损转换收据](archive-repack.json) 证明两者解压后的 tar 流完全相同，932 个成员没有变动。

归档分为 `same-source/`、`ci/`、`audits/`、`development/`、`native/`、`source/` 和 `assembly/`。保留正式运行与开发失败、输入、源码、生成文件、执行二进制、独立 oracle、原始 CI ZIP 和完整收据。排除可重新生成的 Cargo 中间缓存和安装工具链；这些外部身份仍记录于资格报告。NDU 的文本证据另在相邻目录，未重复塞入归档。

重新执行需先 checkout 固定源码、准备报告所记录的 Clang 20.1.8、Rust 1.90.0、Z3 4.15.4、相关系统工具与两个各自固定的 NDU 上游；所有输出目录必须是新的。完整参数和非秘密环境记录于 `same-source/full-invocation.json`，不要直接把原机器绝对路径当成通用安装路径。

```sh
python tools/qualify_hia_integrated.py \
  --expected-head 389f33b0dccec3fcbb0e2205b3cb1f07bd3ff9c4 \
  --output-directory /path/to/new/full \
  --clang /path/to/clang --cargo /path/to/cargo --rustc /path/to/rustc \
  --ranking-bridge /path/to/ranking/bridge \
  --ranking-build-receipt /path/to/ranking/build-receipt.json \
  --ranking-upstream /path/to/ranking/upstream \
  --recursive-bridge /path/to/recursive/bridge \
  --recursive-identity /path/to/recursive/identity.json \
  --recursive-upstream /path/to/recursive/upstream --timeout 2400

python tools/qualify_hia_rust_owned_memory.py --output /path/to/new/owned-memory.json
python tools/qualify_c_musl_compare.py --output-directory /path/to/new/musl
python -m unittest tests.test_hia_scalar_state -v
```

NDU 复现必须使用它自己的 `01310b2` 源码、冻结协议、实际 bridge 和原始分母；不能将新版结果覆写为同一次实验。校验 bundle 可在已取得 `817713b` 对象的仓库中执行 `git bundle verify source/development-source.bundle`，再按其中 refs 导入到新分支。

当前证据支持继续扩展声明子集，但不支持把“更少指令”当成更快、把测试通过当成绝对安全、把有限搜索当成全局最优，或把 C ABI 兼容当成外部调用者已经满足内存契约。
