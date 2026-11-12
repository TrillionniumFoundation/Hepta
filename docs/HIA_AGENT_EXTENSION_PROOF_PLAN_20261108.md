# 原始 select 扩展：最小证明属性与实施边界

状态：设计审查，不改变既有四项 gate，不产生新的整体证明或采用授权。

本计划中“当前 decoder”的缺口描述记录的是 `e05dbfffcfc1ccc0bb380e4b0d97ec43f251e03e` 基线。随后实现的 [CMOVNE 叶子验证](HIA_SAFE_CORE_CMOVNE_20261108.md)只扩展既有 Safe Core 的一条寄存器指令；它没有履行下面列出的完整扩展义务，也没有改变原始任务的 HOLD。

## 真实 subject 与不可改变的结论

本计划针对原 d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6 的编译器 C0、冻结 patch e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4 产生的编译器 C1。两个 canonical Core 分别为 40817012035aa8d156a0a9cf24752c0da24138ea207280b4f9fdd4cc25353850 与 10284cea893a06091e3bb1de5c9e593148915469f820993d49952386503c428b。

真实 strict worker 返回 behavior_equivalence=unknown、lowering_refinement=unsupported，hia_evaluate 拒绝 E_HIA_CLAIM_REQUIRED。隔离 Core VM 对同一 select 输入观察 C0 返回 INVALID、C1 产码421字节。有限差异观察不改写 formal checker 的 unknown；全输入相等本身不是正确的扩展目标。原 strict context 必须保留 HOLD，即使未来另建版本化扩展合同。

## 两层证明不能混淆

| 层次 | Subject | 要证明的关系 |
|---|---|---|
| 编译器本身机器化 | C1 与 Worker 产生的原生镜像 N(C1) | N(C1) 实现 C1 的 Core 语义，当前 lowering_refinement 绑定此层 |
| 编译器算法正确性 | 输入 s、其 Core S、C1 生成的程序 a | a 实现 S，新增 select 域正确性属于此层 |

一层成立不能推出另一层。单段 select 机器码正确不能自动证明整个编译器或任意输入程序。

## 最小扩展属性与必要义务

未来的 compiler-extension 属性应为独立版本，绑定 C0/C1、patch、旧/新域规范、目标/ABI、观察项、checker 和 solver 身份；不是给旧 behavior_equivalence 更换解释。

1. **域完整性：** D0 精确对应原声明的有界语法、类型、资源、效果、标识符、CFG/调用和容量规则；D1 只增加五种标量 select。独立核验实际准入与域规范一致、D0 包含于 D1。禁止 producer 自报任意前置条件、测试子集或空域。
2. **旧域保持：** 对 D0 内全部源码与原 ABI 允许的全部初态，保持结果、错误/容量行为和可观察缓冲区效果。成功旧输入可以逐字节相同产物为强目标。不得为通过证明临时排除工作区、诊断或失败前写入；只有原合同已明确的 scratch 范围可沿用。
3. **新域正确性：** 恰好三个参数、bool 条件、两个同型 u8/u32/u64/usize/bool 值及同型结果；真实 C1 产生的代码在整个合法上下文中正确选择值。需连接类型/SSA槽位归一化、帧偏移、实际输出字节和周围 CFG/调用，不以手写叶子替代真实候选。
4. **拒绝和容量：** 仍非法或超 profile 的输入保持明确拒绝；短输出/工作区、超长源码、SSA/块/指令边界和错误前输出事务性不能丢失。多遍 parsing/emission 一致性需要建立。
5. **终止与资源：** 若主张终止，需要循环/递归不变量和递减度量。VM超时不是证明，预算停止不是语言陷阱或 allocator NULL。不得把墙钟或 VM ticks 混入既有语义等价定义。
6. **编译器机器化：** 对三buffer、多函数、循环 C1 的一般 Core-to-N(C1) refinement 仍须独立建立，不能由算法层或叶子证明替代。

## 可复用的事实和核

原44函数与候选45函数中42份 canonical 同名函数逐字段完全相同；仅 f7(operation，172→175 blocks，326→329 ops)、f33(keyword，157→160 blocks，469→478 ops)改变，新增 f44(select_scalar)。共同函数可能调用改变的 callee，身份相同不是其调用闭包行为已证。

可复用 Core admission、标量 select=If 编码、solver/源码身份、六字段 proof 合同、实际产物绑定与 encoding 重发射、已有 buffer 生命周期。它们分别提供准入、局部语义、身份或执行机制，不能推得整个扩展正确。

现有优化核仅支持v1-v7，且要求相同接口/CFG/有序资源屏障。即使增加v8，本配对的 _skeleton 仍不同。需要证明旧合法token不触发新分支，再证明新分支中的内存/帧不变量；不能跳过 skeleton 或把未经证明的调用结果视为共同符号值。

## 可立即实施的独立 CMOVNE 增量

新 select 实际片段包含 TEST RDX,RDX 与 CMOVNE RAX,RCX，后者编码48 0f45 c1；当前 SafeCore decoder 未支持 CMOV。可以独立增加严格64位寄存器到寄存器 CMOVNE：只接受 REX.W、0F45、ModRM.mode=3；用旧ZF选择旧源/目的值，不改flags，正确处理寄存器别名与REX。真实合法 SafeCore subject 应验证全宽/真假条件，反条件、交换值、丢高位等给出反例，不支持的内存/宽度/条件形式继续拒绝。

每份证明只能绑定实际 subject/profile。Agent SafeCore仍拒绝borrowed/foreign入口；下层模型最多一个函数、一个借用区、16 blocks、64 ops且无循环。新增CMOV不扩大这些限制，也不关闭整个 C1 的 gate。

## 从叶子到完整扩展的最小后续工程

限定于冻结 delta 的证书驱动关系checker可以接收块/SSA对应、不变量和片段边界，再从实际 Core/bytes独立核验：词法保持、f7新增分支的旧域不可达性、f44准入到字节的关联、共同函数在已证callee合同下的封闭、动态状态数组/循环/容量/多遍不变量，以及机器片段的上下文组合。

假设旧编译器正确或假设parser不变量的条件定理必须明确留下这些未证义务，不能关闭一般正确性gate。原历史provider交互、tokens及账单同样不能由本轮重放补造。

## 只读源码依据

原 delta 交付commit6502316907b10fba822b3518d0ba2cc7417afa61；hia_agent_service.py 的 _behavior_equivalence/_hia_verify/_independent_native_refinement/_required_claims；hia_agent_contract.py 四claim枚举；hia_optimization.py schema/skeleton/Encoder；hia_proof_contract.py；hia_safe_core.py _profile/ARTIFACT_OBLIGATIONS；hia_safe_core_x64.py decode/Executor.run；原fresh-select.patch。
