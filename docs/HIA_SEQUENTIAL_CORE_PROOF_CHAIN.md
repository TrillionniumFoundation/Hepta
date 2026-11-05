# Sequential scalar Core proof chain

`tools/qualify_hia_sequential_core.py` binds the existing normal-return and
actual LLVM translation validators to one exact primitive Core. It recomputes
both obligations for **every public scalar export**; there is no caller-supplied
receipt and no option to omit a failing export. The emitted LLVM is retained and
its actual instructions, branches, guards and reachable callees are parsed by
the existing independent lowering checker.

## Quantifiers and limits

| Property | Quantifier and evidence | Remaining trust or exclusion |
| --- | --- | --- |
| Register reads and total execution of the abstract straight-line register model | Generic Lean theorems in `formal/HiaRegisterSafety.lean` quantify over every well-formed program in that mathematical model | This is not a proof of the production verifier, exporter, LLVM, or ownership |
| Normal return of the selected Core | Fresh Z3 query for every typed input of every selected public scalar export; reachable direct callees use their original bodies under actual caller path conditions | Acyclic scalar CFG/call profile, with existing function/block/operation/expansion limits; verifier and symbolic encoder remain trusted |
| Value and abort preservation for actual emitted LLVM | A separate fresh Z3 query parses the emitted internal functions and compares them with the selected Core, including poison conditions | Actual LLVM internal-body profile only; encoder/parser and Z3 remain trusted; native machine code and ABI are outside the proof |
| Composed normal return without LLVM abort or poison | Both obligations must pass for the same Core, same function and exact emitted LLVM digest, for every public scalar export | Per-artifact translation validation; not a generic soundness theorem for every legal Core program |
| Owners, loans, external resources and concurrency | No composed claim | Existing resource verification and separate abstract ownership theorems do not become implementation refinement proofs through this tool |

The distinction is between a bounded **program shape** and an unbounded choice
of values within each declared machine type. The input check is not a finite
random sample. For example, each two-`u32` export in
`formal/selected_sequential_u32.hia.json` has `2^64` possible argument tuples.
The query covers those tuples, but does not establish a theorem for all
programs with that signature.

The selected module contains a private, potentially trapping unsigned division
helper and a public caller that checks a zero denominator. The caller can be
total without claiming the private helper is total on every possible argument.
Exporting that helper creates another independent obligation and fails with a
replayed division-by-zero counterexample. The second public export performs
wrapping arithmetic. Its proof cannot be used to hide a trap in another export.

Normal return refers to the mathematical program semantics. It does not promise
that a host will never exhaust memory, kill a process or stop at a runtime quota.

## Proof identity and deadlines

Primitive scalar totality now identifies the pinned Z3 binding and actual loaded
library, hashes the checker, opcode catalog, schemas, symbolic semantics and VM
replay implementation, and checks their identities again before accepting SAT
or UNSAT. Both totality profiles and the composed source lock include the
extracted `hia_capability_flow.py` rules used by the canonical verifier. A byte
change in that dependency during a proof invalidates the result even when the
solver has returned UNSAT. The deadline covers source checking, encoding, solving, replay and
final identity checks. A late result is `unknown`, even if the solver returned
UNSAT. The deadline rejects late evidence; it is not a hard process timeout.

The compound checker also uses a single overall deadline across exports and
both proof stages. Source drift, unknown solver results, invalid profiles,
incomplete paths, failed replay, empty exports and incomplete evidence leave
all composed claims false. Partial successful rows remain visible for diagnosis.

The result always leaves `all_legal_programs_proved`,
`all_programs_in_profile_proved`, `verifier_or_encoder_refinement_proved`,
`ownership_or_resource_safety_proved`, `native_machine_code_or_c_abi_proved`
and `execution_authority` false.

## Reproduce

Use the repository's pinned Z3 4.15.4 environment:

```sh
python -m unittest tests.test_hia_scalar_totality tests.test_hia_sequential_core -v
python tools/qualify_hia_sequential_core.py \
  --core formal/selected_sequential_u32.hia.json \
  --output /tmp/hepta-sequential-proof \
  --timeout-ms 10000
```

The output directory must be new. It contains the canonical `core.hia.json`,
actual `program.ll`, `qualification.json`, retained lowering SMT-LIB queries
and a byte/hash manifest. Totality reports retain the query digest and complete
source/solver identity; rerunning the command recomputes totality from the
exact Core. Lowering queries can also be replayed independently with the
qualified Z3 installation. No saved JSON is accepted as execution authority.

The regression suite checks an added public trapping helper, overflow in a
second export, a changed actual LLVM arithmetic instruction, unrelated
same-shape totality evidence, missing solver proof, implementation drift,
unsupported loops/schemas and an exhausted whole-chain deadline. It also
replays the retained lowering queries with fresh solver instances.

## 顺序 Safe Core 源码连接矩阵 / source connection matrix

本节把更宽的顺序 Safe Core 工作接到真实入口；上面的已组合证明仍限于
**固定、无环、标量 Core 及其实际 LLVM 内部函数**，不能借本表扩展到完整语言。
下列四类证据不可相互替代：**G** 是对明确数学模型的一般定理；**P** 是对一个
固定程序的全部已声明类型输入进行的新鲜检查，依赖编码器与求解器；**F** 是有限
运行、测试或具体 witness；**S** 是生产实现中的结构检查，本身不是机器证明。
文件中的定理和历史证据须按各自固定版本重放，本表不宣称在文档提交上重跑了所有资格检查。

| 语义 / semantics | 真实源码与关键 lowering | 已有证据及量词 | 尚未连接的边界 |
| --- | --- | --- | --- |
| 源码入口与类型 / source and types | [hia_program_source.py](../hepta/hia_program_source.py) `lower_source` → [hia_program.py](../hepta/hia_program.py) `verify_program`、`_type`、`_function_shape`、`_BlockCheck.instruction`；路由见 [hia_routes.py](../hepta/hia_routes.py) `admit_route` | **S**：对实际 canonical Core 重新验证 schema、类型、标量值域和指令形状。**G**：[HeptaMemory.lean](../formal/HeptaMemory.lean) `TypedCore.preservation`、`progress`、`trace_preservation`、`well_typed_cannot_get_stuck` 只覆盖其 wrapping word/bool/add/eq/if 模型 | 未证明源语言检查器或 `lower_source` 精化该模型。HSIR、HMIR、resource IR 或 legacy envelope 不能单独代替 primitive Core admission；见 [可信核心范围](HIA_TRUSTED_CORE_CONVERGENCE.md) |
| SSA、寄存器与控制流 / registers and CFG | `_BlockCheck.transfer` 检查 Core 边参数；[hia_program_runtime.py](../hepta/hia_program_runtime.py) `_Machine.invoke` 执行；[hia_program_llvm.py](../hepta/hia_program_llvm.py) `_FunctionEmitter.edge`、`terminal` 产生 LLVM 边和 PHI | **G**：[HiaRegisterSafety.lean](../formal/HiaRegisterSafety.lean) 的 `execute_total`、`run_total`、`read_defined` 是良构直线寄存器模型定理。**P**：[hia_scalar_lowering_check.py](../hepta/hia_scalar_lowering_check.py) `verify_scalar_lowering` 检查固定无环标量函数；**S**：`_LLVM.phi_plan` 先检查全部 incoming 的支配与完整 CFG 边，再由 `execute` 同步绑定 PHI | Lean 寄存器模型不是生产 CFG/SSA 的一般精化证明。LLVM parser、Core/LLVM 两个符号编码器及 SMT 求解仍受信；有限 PHI 回归不能证明所有 LLVM 合法性 |
| 所有权、借用与资源 / owners and loans | `_BlockCheck.owner_free`、`access`、`borrow`、`transfer`、`finish`；[hia_capability_flow.py](../hepta/hia_capability_flow.py) `rename_capabilities`；VM `_Machine.new_owner`、`allocate`、`drop`；LLVM `_FunctionEmitter.operation` | **G**：[HeptaCore.lean](../formal/HeptaCore.lean) 抽象资源轨迹；[HiaCapabilityBorrow.lean](../formal/HiaCapabilityBorrow.lean) 的 `trace_compatible`、`trace_no_parent_cycle`、`trace_accessible_exclusive` 及 [HiaCapabilityLifecycle.lean](../formal/HiaCapabilityLifecycle.lean) 的模型不变量。**F**：[verify_hia_capabilities.py](../tools/verify_hia_capabilities.py)、[生命周期](../tools/verify_hia_capability_lifecycle.py)、[借用](../tools/verify_hia_capability_borrow.py) 捕获真实检查器调用并导出具体 Lean witness | 具体 witness 证明被导出的有限图/步骤，不是该程序全部输入的运行时内存安全。生产类型检查器、导出映射、动态 allocation identity/epoch、VM 与 native allocator/free 的对应均未一般证明；[witness 边界](HIA_PRODUCTION_CAPABILITY_WITNESSES.md) |
| 初始化与消除清零 / initialization | [hia_initialization.py](../hepta/hia_initialization.py) `_analyze`、`initialization_coverage`、`verify_initialization_coverage`；LLVM `_can_elide_zero_initialization` 与 `_FunctionEmitter.operation` 消费实际已验证 Core 的分析结果 | **G**：[HiaInitializationPrefix.lean](../formal/HiaInitializationPrefix.lean) `prefix_invariant`、`completed_fill_independent_of_initial`、`completed_fill_matches_zeroed` 对模型中的任意初始内存和长度成立。**S**：封闭本地 owner/标量 profile 的同根完整填充检查。**F**：实际 poison allocator/native 比较与反例，见 [初始化契约](HIA_INITIALIZATION_ELISION.md) | Core 对外仍提供已初始化 buffer；只在已支持条件下允许 native 使用 `malloc`。未证明实际循环、usize 运算、分配失败、状态映射到前缀模型，下面 12 项仍未完成；保存的 witness 不授予 elision 权限 |
| 错误、算术与 first trap / errors | VM `_Machine.operation` 按序执行 checked/wrapping 算术并抛出 `HIAProgramTrap`；[hia_translation_validation.py](../hepta/hia_translation_validation.py) `_Encoder.operation`、`validate_translation`；LLVM `_FunctionEmitter.checked_binary`、`guard`、`terminal` | **P**：固定 Core→Core 的标量翻译验证比较返回值和**第一个 trap code**；固定 Core→LLVM 内部函数检查比较值、**abort 布尔事件**和 poison。**F**：VM/native 负例。规则见 [语义契约](HIA_SEMANTICS_CONTRACT.md) | native `abort` 不返回 VM 的精确 trap code；不得把两类检查等同。返回错误值属于正常返回，仍须满足资源退出义务；不等于异常展开或外部 callback 生命周期证明 |
| 正常退出、拒绝与预算 / exit and refusal | `_BlockCheck.finish` 检查正常退出资源；VM `_Machine.tick`、`invoke`、`report` 区分正常返回、trap、`HIAProgramBudgetExceeded`；[hia_scalar_totality.py](../hepta/hia_scalar_totality.py) 的两个 totality 入口；[qualify_hia_sequential_core.py](../tools/qualify_hia_sequential_core.py) `_evaluate`、`verify_sequential_core` | **P**：每个公开标量 export 的所有类型输入均正常返回，并单独连接同一 Core 的实际 LLVM。私有函数只在实际调用条件下使用。**G/SMT**：[hia_exit_accounting.py](../formal/hia_exit_accounting.py) 与 [verify_hia_exit_accounting.py](../tools/verify_hia_exit_accounting.py) 检查数学整数账本的归纳/退出公式，另有有限反例与非空性检查 | 账本不是实际 owners/loans 的一般实现证明，数学整数没有机器溢出。程序 totality 不保证宿主内存、时间或 quota；原生程序不自动继承 VM 的 step/heap/call-depth 限制。取消为契约中的顺序协作动作，不推出抢占、线程或设备恢复性质 |
| LLVM、ABI 与实际运行 / lowering and execution | `emit_program_llvm` → `compile_program_llvm` / `build_program_native`；`_Emitter.wrapper` 建立公开包装；独立检查器读取已发出的内部函数和可达 callee | **P**：选定 LLVM 文本的值/abort/poison 检查。**F**：真实 LLVM `opt` 验证、Clang 编译、native 调用。近期 [PHI 修复证据](../experiments/hia_scalar_phi_edges_20261105/README.md) 固定在 `a3d7a12`：103 项测试、12 个 LLVM oracle 案例、384 次合法 native 调用 | [HeptaCore.lean](../formal/HeptaCore.lean) `lowering_preserves_value` 的目标是抽象栈机，不是此 LLVM emitter。LLVM 优化器/codegen、链接器、C ABI、运行库、OS 和硬件仍在边界外；跨目标 object 不等于该硬件上的执行与恢复 |

### 仍受信的连接 / remaining trusted boundaries

1. 生产前端、schema/规范化、canonical verifier 以及对象快照实现，尚无一般 source→Core 精化证明。
2. 实际 Python 控制流、owner/loan 状态和 Lean 值之间的导出/投影；具体 witness 不能证明导出器对所有输入正确。
3. Core 和 LLVM 的独立符号编码器、LLVM 子集 parser、SMT-LIB 构造、Z3 Python binding 与实际 Z3 库。
   新鲜查询和前后字节锁缩小错用证据的机会，但 hash 相同不等于语义精化。
4. Lean kernel、已允许的标准公理与固定工具链；拒绝 placeholder/自定义公理不消除 kernel 自身的可信性。
5. 初始化分析到实际 `malloc`/`calloc`、store/load、allocator outcome 和 first-trap 的连接；见下面义务。
6. LLVM 后续优化/codegen、ABI 包装、链接与原生运行环境。捕获器的 deadline/cancel/recovery
   是另一个需按精确源码资格化的宿主协议，不属于标量 totality 定理；合作式检查也不是 OS 硬超时。

修复 PHI 检查只缩小第 3 项中的一个实际缺口。它不会使 `ownership_or_resource_safety_proved`、
`native_machine_code_or_c_abi_proved` 或 `execution_authority` 变为 true。

### 初始化桥的 12 个更宽义务 / twelve wider obligations

以下是现有 [Core→model 连接账本](../experiments/hia_initialization_frontiers_20261103/CORE_MODEL_CONNECTION.md)
的压缩索引，**12 项状态均为 UNPROVED**。真实抽取入口是
[extract_initialization_obligations.py](../tools/extract_initialization_obligations.py)
`extract_obligations`；其 `check_obligation_transport` 使用同一抽取器/检查器重新构造数据，
不能作为独立证明。`extracted`、窄语法运输成功或具体 Lean 证书均不关闭下面义务，权限仍为 `DENY_ALL`。

| # | 必须连接的实际语义 / obligation | 状态 |
| --- | --- | --- |
| 1 | 真实 VM 状态/操作数到模型的投影，所有 CFG 边的同步参数绑定，精确 PHI 和 operand map | UNPROVED |
| 2 | 静态 allocation root 到动态实例及 epoch；循环重入、move 与重分配不能混为同一对象 | UNPROVED |
| 3 | 请求长度 `N`、成功 owner 长度、失败 `try_new` 的空 owner；对象上限 `2^63-1`、usize 上限、预算和拒绝分别建模，并明确 allocator outcome 的耦合假设 | UNPROVED |
| 4 | 真实 usize 到 Nat 的映射、边界谓词与 `+1`；checked/wrapping 仅在所需 guard 成立时对应模型运算 | UNPROVED |
| 5 | header seed 和直接进入 body 的 seed 分别证明；直接从 0 store 需要 `0 < N`，不能把 `N=0` 的 trap 当作成功填充 | UNPROVED |
| 6 | 每个真实 store 在正确 live owner 上实现模型 `write` 及 frame，保持执行顺序，排除 stale/wrong-root 写入 | UNPROVED |
| 7 | 两次执行的写入值序列不依赖初始字节，并追溯 incoming state；单有地址覆盖不足以推出等价 | UNPROVED |
| 8 | store/step 后确实正常完成，区分可达、trap、budget 和不终止；不能只用 CFG 可达性替代执行轨迹 | UNPROVED |
| 9 | `N=0` 从精确 allocation extent 及 `0 < N` 的 false 边推出，不能取错误 PHI 或其他长度 | UNPROVED |
| 10 | completion 图割与真实轨迹对应，覆盖所有分支，并确保 completion 发生在具体 load 之前 | UNPROVED |
| 11 | completion 到读取之间保持初始化事实及 frame；正确处理 borrow、move、drop 和新的 allocation 实例 | UNPROVED |
| 12 | 在同一程序上组合初始化独立性、耦合分配结果、首个 trap/refusal 和 owner/loan/drop 结果；source→deferred 与 backend 精化另证，不推出时间/step/quota 等价 | UNPROVED |

这份矩阵的可关闭项须由同一固定组合重新给出证据。不同分支、不同协议版本、
不同 target 或不同失败/成功运行的局部行不能拼成一次完整资格通过。
