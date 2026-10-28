# HIA v8：返回借用、完整 C 组件、原生生命周期与 NDU 成本实测

本轮已经把新实现推进到 [Draft PR #329](https://github.com/TrillionniumFoundation/Hepta/pull/329)，并在同一个冻结源码版本上完成真实前端、验证器、解释器、Rust 差分、原生组件、完整回归与七个实际主机的验收。**六项目标没有全部关闭：NDU 的增量价值和自动重优化的实际净收益，本轮实验都没有成立。**

本文的工程资格绑定 `5fead4df11e6157626773ea74c42a59b342f91a6`。NDU 正式实验始终绑定另一明确版本 `8b0fd11dde9f13ac784b3579ec9930ae4832784d`；后续平台修复没有改写或重跑那次测量。

**这是已验证的固定版本 checkpoint。** 封存时，远端 full workflow `40642078513` 仍在进行，本文不预先宣称其后续门通过；本地完整回归、七主机和 verified 工作流已经通过。PR 所跟踪的实际基线同期前进到 `d5a0bf0e42611309cbc6461b1a414b9f8ece254f`，产生四处真实冲突，兼容整合另行进行。这里的源码、测试和性能身份不会转移给未来合并版本。详见 [checkpoint-status.json](checkpoint-status.json)。

## 1. 身份与完成状态

| 项目 | 本轮可核对的结果 | 仍未覆盖的边界 |
| --- | --- | --- |
| 1：统一 HIA 语义入口 | 显式 Core v8 经过真实 CLI lower、canonical verify、解释执行、LLVM build 及实际动态库调用；新版本不会静默降级 | 整个源语言到 LLVM 的形式化精化定理 |
| 2：资源与 Rust 差分 | 参数来源的返回只读/可变借用、直接子借用转移、调用链、CFG 来源、组合 record 的 buffer 字段；完整账本差分与非法模块拒绝通过 | 任意借用存储/返回图、异步取消、异常展开、原生 VM 预算等价 |
| 3：优化前后行为 | 资源准入、总函数证明和功能等价证明保持独立；未知/超时/反例拒绝候选发布 | 任意资源调用变换、任意循环与后端整体正确性证明 |
| 4：有限动作 NDU | 实际原生递归 NDU、同预算强对照、完整成本账本；48 次 episode 全部完成 | **相对固定策略和简单搜索的增量价值未成立** |
| 5：C/C++ 迁移与 ABI | 完整未改写 `stb_divide.h` 的两种声明配置迁移，七个实际 host/compiler 组合通过；C++ 保留其独立资格 | 任意 C/C++ 自动重写、资源型上游完整迁移、普遍低人工成本 |
| 6：多版本与后台优化 | 实际发布、旧版本 lease、回滚、后台关闭及带身份 pin 的退役通过限定测试 | **实际重优化净收益未成立**；没有一般堆/借用/栈状态迁移或永久路径不存在保证 |

| 身份 | 精确值 |
| --- | --- |
| 本轮工程源码 | [`5fead4df11e6157626773ea74c42a59b342f91a6`](https://github.com/TrillionniumFoundation/Hepta/tree/5fead4df11e6157626773ea74c42a59b342f91a6) |
| 工程 tree | `5a5dbd5b42bb0b331a52d15e8ebf8ac5acd30a06` |
| NDU 测量源码 | `8b0fd11dde9f13ac784b3579ec9930ae4832784d` |
| NDU 测量 tree | `bac1ec8beea558537873e902ebdeb4def9626f48` |
| 原始递归框架 pin | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` |
| 冻结实验协议 SHA-256 | `bdf110209ea714c807948c5dc572636994166ac2bc52eab877bcc5bbdd3d5bc2` |

## 2. 返回借用已经走通真实语言与后端

新协议是 `hepta.hia.program.v8`。函数的 `return_origins` 指定每个返回借用来自哪个传入借用参数；标量返回位置为 `null`。当前最多返回一个 view 并可附带标量，不允许把返回借用与返回 owner 混合。

真实源代码可以写出：

```hepta
fn view(value: read Buffer<u8>, choose: bool) -> read [u8] from value effects {} {
    if choose { return read value; }
    return read value;
}
```

v8 lowering 保留 helper、`call`、`ret` 和来源字段。返回传入 view 时创建一个新的直接子借用；返回已有直接子借用时转移原来的那个子借用，避免重复记账。子借用存活期间父借用不可访问数据、结束或允许 owner 移动/销毁；子借用结束后恢复父能力。CFG 重命名不会改变参数来源。

局部 owner 逃逸、错误来源、局部中间父借用、未结束后代、兄弟能力逃逸、未调用的非法 helper 都稳定拒绝。公开 C ABI 的入口仍只允许声明的标量类型，内部 descriptor 返回不被冒充为安全的外部 C/C++ 借用协议。

```bash
python -m hepta hia lower examples/hia_returned_loans/returned_views.hepta --core-schema hepta.hia.program.v8 -o program.json
python -m hepta hia verify program.json
python -m hepta hia run program.json --function probe --arguments '[1,42,true]'
```

默认 lowering 继续使用旧 v1 契约。条件返回借用 helper 没有显式选择 v8 时拒绝；历史 Core 不能靠这个选项更换 wire schema。详见 [v8 契约](https://github.com/TrillionniumFoundation/Hepta/blob/5fead4df11e6157626773ea74c42a59b342f91a6/docs/HIA_RETURNED_LOANS_V8.md)。

## 3. 资源证据有明确分母

同版本返回借用 collector 得到 **278 份完整 Python/Rust 资源账本**：83 次正常返回、13 次 trap、182 次预算停止。正常返回的 live 计数均为零；trap 和预算停止如实记录仍存活的资源，没有把停止状态改写为取消清理成功。

**43 个不同非法模块**在正常预算和最小预算下产生 **86 次真实 Rust 拒绝**。保留了实际输入、UTF-8 字节摘要、原始失败输出和不同语言执行器的完整计数。

Linux x86-64 上另有 **17,920 次实际原生成功调用、15 次失败策略观察和 2 个编译后的错误值/缺少释放负控制**。实际对象文件、可执行文件和观察器源代码均在包内。原生观察器检查结果与真实 allocator 行为；被编译擦除的借用能力没有原生动态 loan 账本。

真实 CLI 单独运行了 6 个命令，并对其生成、封存的动态库执行 **1,024 个案例**。这个数来自 2 个非空 buffer 大小 × 256 个 byte 值 × 2 个分支选择；它没有被加进返回借用 collector 的 17,920 分母。

v8 原生资格目前限于 Linux x86-64。AArch64/RISC-V 的 v8 emission 明确拒绝；七主机的 C 迁移 Rust 路线不能替代这个限制。

## 4. 优化与运行时的接纳条件

NDU 输出仍然是建议。候选先经过 canonical 资源合法性检查，再经过所声明 profile 的新鲜功能等价验证；任一层未知、超时或发现反例，候选都不能自动成为运行版本。

本轮新增显式 `prove_total=True` 路线：在受限无环 `u8/u16` checked div/rem profile 内，对每个导出函数进行全输入无 trap 查询。只有 UNSAT 进入总函数准入，SAT 反例必须通过 canonical VM 重放；无路径、重放分歧或超时均保守拒绝。候选还需要独立的新鲜等价证明。资源函数或调用不因此获得任意重写许可。

原生退役现在将 loader handle、sealed memfd、产物身份 pin、目录身份 pin 分开记录。关闭每项最多一次，未知关闭不能重试并误伤重用的句柄；待退役资源持续占用有限 generation 容量。持有原始 inode 的 pin，避免 unlink/recreate 后 inode 重用导致新路径被误删；释放 pin 后不能重新取得旧路径的删除权。没有递归删除外来文件的兜底。

同版本组件观察了多版本和后台优化器的 **5 个 generation 退役与 7 个身份 pin 释放**，关闭时 pending 为零。全量回归还覆盖故障注入、回滚、旧版本 lease、标量状态与合作式取消。这些正确性测试中的成功发布，不能替代正式经济实验中的实际净收益。

## 5. 完整 C 组件和实际 ABI

`stb_divide.h` v0.94 来自固定上游 `003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`，完整保留 **14,507 字节、433 行**，没有修改上游函数体。两种声明配置各有 **6 个定义 + 6 个已解析原型**。主动配置外的内置测试和宏分支仍在原始文件中，但没有被算作本轮已迁移的可执行路径。

新增的 C frontend 行为包括：结构化控制流上的 definite assignment，以及以惰性分支 helper 保留的纯标量条件表达式。未初始化读取、带副作用的条件值、未声明指针/record 路径等继续拒绝。实际项目翻译不会回退成链接原始实现。

本地验收是 **21,453 个不同输入 × 2 种配置**。两种原 C 编译器和 Rust/HIA 两条生成目标路线给出 **171,624 次输入与路线组合执行、2,059,488 次普通原生函数观察**；这是含原 C 与目标函数的重复观察数，不是不同输入数。另有 **514,872 次原 C UBSan 观察、696 次解释器函数观察、48 个目标单独 trap 进程**。

Rust 目标实际读取了 allocator 计数并观察为零。HIA LLVM 目标的对应原生 allocator 字段为 `null`，没有被转换成“测得零”。零分母和不可表示的商从未送入原 C；目标程序的显式失败在独立进程中验收。

| 实际主机 | 原 C 编译器 | 迁移原生目标 | 本轮结果 |
| --- | --- | --- | --- |
| Linux x86-64 | GCC | Rust | 通过 |
| Linux x86-64 | Clang | Rust | 通过 |
| Linux AArch64 | GCC | Rust | 通过 |
| Linux AArch64 | Clang | Rust | 通过 |
| macOS AArch64 | Clang | Rust | 通过 |
| Windows x86-64 | Clang | Rust | 通过 |
| Windows x86-64 | MSVC | Rust | 通过 |

每个主机都真正执行两种配置、42,906 个输入/配置对、514,872 次原 C/目标函数观察、696 次解释器观察和 24 个目标单独 trap 进程。各平台的重复运行不被叠加成更多不同测试输入。[实际七主机工作流](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40642078526)和原始报告摘要均已独立核对。

Windows 的依赖文件按 Clang 的 Make 编码解析，保留盘符、原生反斜杠、转义空格/`#`/`$`，不再使用 shell tokenization。Rust 的三个 DLL 构建显式绑定 Visual Studio x64 linker 的路径和前后 hash，避免 Git Bash 选择 GNU `link.exe`。当前两份实际 MSVC 14.51.36260.0 的 `/?` 帮助观察返回 1100；只有严格识别的帮助身份组合可接受该状态，回执保留原值。真正编译和链接仍必须成功返回，其他非零退出不被接纳。

这个 header 的 C++ 入口仍因缺少显式 `noexcept` 被拒绝；没有修改上游声明来贴上 C++ 成功标签。同一源码的 [verified native/C++ 工作流](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40642078557) 实际运行了 **221 个唯一方法、26 个模块，零失败、错误和跳过**。这是选定回归子集，不加入完整回归总数。

其 C++ corpus 是仓库自写 scoped-ownership fixture，共 **1,121 个不同输入**。原始 C++ reference、Hepta→Rust→native、Hepta→C11/GCC→native、Hepta→direct LLVM object→native 四条路线产生 **4,484 次输入/路线观察**。每条路线有 3,180 次分配、3,180 次释放、398 次分配拒绝，最终 live=0。两个实际负控制分别检出 8 个存活分配的泄漏，以及分配/释放数量虽平衡却析构顺序错误的 trace。输入、逐事件账本、原生文件与负控制均保留。这项资格没有被表述为第三方 C++ 库的自动迁移。

该 CI 的另外 30 个 NDU episode 单独保留，6 次原生递归决策也全部 stop，原账本的 NDU standalone 总成本为 18.651066272 秒，light 为 1.699610010 秒。它不是下节 8b0 上的 48-episode 冻结实验，不与其重标或相加。CI adaptive 报告观察了人工切换/回切，测得净额仍为负；其最后快照是关闭前状态，不能充当关闭后清理证据。

手工 review 时间、agent token 成本和一般迁移成本下降均未测量。详见 [完整组件契约](https://github.com/TrillionniumFoundation/Hepta/blob/5fead4df11e6157626773ea74c42a59b342f91a6/docs/C_STB_DIVIDE.md)。

## 6. NDU 正式实验：负结果完整保留

正式设计固定为 **8 策略 × 3 分布 × 2 重复 = 48 个 episode**，每个 holdout 是 64,000,000 次串行 byte 状态递推。三个候选分别守卫分母 3、10、16，其他输入走完整 generic fallback。搜索预算 2 秒，候选测量最多 6 批，发布至少要求两批测量。它是有限阶段的合作式预算，不是硬实时保障。

实际执行了 276 个原生批次：60 校准、84 在线基线、84 在线候选、48 holdout；计时段共 **3,129,000,000 次递推调用**。每批另对相同的 65,536 个 typed 输入对完整检查，总计 18,087,936 次重复 oracle 观察。这些数不被冒充为不同输入数。

**48/48 完成，0 次发布。**原生递归 NDU 的 6 次决策全部停止，模型匹配的强算术对照也全部停止。固定策略和简单枚举真实测量了候选，但未通过包含编译和证明成本的发布条件。

下表是每个策略服务 **6 个 episode 的总成本**，不是单次延迟。直接基线不承担它不需要的搜索和校准成本；固定策略也不支付没有用到的训练准备。另一个同信息账本独立保留。

| 策略 | warm 全成本（秒） | cold 全成本（秒） | 候选测量批次 | 发布 |
| --- | ---: | ---: | ---: | ---: |
| 直接基线 | 2.715459 | 2.715459 | 0 | 0 |
| 固定 d=3 | 3.865050 | 3.865050 | 12 | 0 |
| 固定 d=10 | 3.809162 | 3.809162 | 12 | 0 |
| 固定 d=16 | 3.752032 | 3.752032 | 12 | 0 |
| 校准选择固定候选 | 4.877475 | 4.877475 | 12 | 0 |
| 简单穷举 | 5.663383 | 5.663383 | 36 | 0 |
| 强算术递归对照 | 3.631058 | 3.631058 | 0 | 0 |
| 原生 NDU | 3.637279 | 24.873340 | 0 | 0 |

NDU warm 比直接基线多支出 **0.921820181 秒**；计入原生 bridge 冷构建后多支出 **22.157880431 秒**。真实 cold build 的 **21.236060250 秒**仅按该策略的 6 个 episode 分摊，分母不是全部 48 个 episode。

候选机器码确实不同：四个实际 ELF 导出的 `calculate` 分别为 20、45、48、34 字节。hot-sixteen 校准中候选明显快于基线；但固定 d=16 的两次 episode，64M 次调用的估计毛节省为 103.808/107.264 ms，已经付出的成本为 184.357458/160.161725 ms，即使未来发布免费也不回本。因此不能把更快的局部代码或基线运行的噪声称为部署收益。

这个 NDU 接入执行确定性的有限递归效用与可行性选择；单位折扣的相同标量模型可以由简单算术直接复算。没有训练、FBSDE 学习、统计显著增量或全局最优证明。状态在 C harness 子进程内，是一个 `uint8_t`；不是同等数量的宿主 `ScalarStateSession` 提交。

原始实验只运行一次。没有按结果延长 horizon、删除样本或重新调整预算。源码依赖闭包中确有后续平台修复过的文件，因此连“后续版本的整个实验依赖未变”也不成立；本包保留原 8b0 依赖字节及逐项对应关系。

## 7. 生命周期与证据的实际限制

正式实验的 48 份关闭 snapshot 都记录原 native 资源和 96 个身份 pin 释放、pending 为空、原目录在关闭时不存在。稍后独立观察到 5 个路径以不同 inode 再次出现，内容为空。写入者没有确定；原始 metadata 与判断均保留，没有删除目录来制造“零残留”。

一次另行标明的有限 strace 诊断进行了 1 个 baseline 与 2 次实际发布/关闭，随后 99 次路径观察均未重现目录出现。27 份原始 strace 在包内。它不是第二次性能实验，没有加入 48 个 episode 的分母，也没有证明原因已解决或路径永久不存在。

原始成功 Cargo build 的 stdout/stderr 没有被当时的 builder 持久保存，这是不可恢复的取证缺口。本包保留真实命令、源码输入、工具身份、实际 ELF 与时间账本，不用重跑日志冒充原件。Bridge 的 native 回包是保存的结构化请求/响应；它不被称作未保存的原始 stdout 字节。

## 8. 完整验收与历史失败

冻结工程源码的本地综合验收 **6/6 门通过、2887 个 Python 测试、60 个 Rust 测试，零失败、错误、跳过、ignored 或 filtered**。3572 个 tracked 源文件及 244 个外部身份记录前后相同。独立审计从原始逐方法输出和 footer 重算分母，critical 模块只作为同一完整运行的子集。

最终组件 collector 的独立审计与全量审计绑定同一份报告 hash；C++/host CI、CLI 调用、组件函数观察和 benchmark batch 均不加入 Python 测试总数。远端完整工作流状态以 CI 留存的精确源码报告为准，不用旧 PR 的绿色结果替代。

| 被保留的历史版本/尝试 | 实际结果与处理 |
| --- | --- |
| 389f33b 的 full push | release 50/50，但 standalone 34/35；Lean 可执行 fixture 原地 append 触发 ETXTBSY。后续改为替换副本，原失败保留；另一同源 PR full 的通过也独立记录 |
| 8b0fd11 的七 host | 5 通过、2 Windows 在依赖捕获拒绝 |
| 322be9b | Windows 12 声明/6 函数已捕获翻译，但 Rust DLL 选到 GNU link.exe 而失败 |
| 6b005ca | 显式 VS linker 绑定阶段拒绝；原失败收据不足，不能倒填原因。组件本地通过；full 在得知还需修复后主动中断并保留 partial，不算通过或实现测试失败 |
| 613c031 | 增补诊断后真实确认帮助探测返回 1100；这次原组件仍失败 |
| 5fead4d | 修正严格帮助身份协议后，七 host 及本轮完整验收通过 |
| 322 组件外层 wrapper | 误把正确 CLI 拒绝的退出码 2 预期为 1，外层失败保留；修正 wrapper 后单独 CLI 通过，最终源码重新执行全部组件 |

## 9. 文件与复核方法

- [acceptance.json](acceptance.json)：本轮工程与负经济结果的机器可读摘要。
- [qualification.json](qualification.json)、[final-audit.json](final-audit.json)：完整同源资格与逐方法独立审计。
- [host-audit.json](host-audit.json)：七个实际 host/compiler 的源码、原报告与行为核验。
- [ndu-result.json](ndu-result.json)、[ndu-independent-audit.json](ndu-independent-audit.json)：原 8b0 实验及独立整数/成本/生命周期审计。
- [raw-evidence-manifest.json](raw-evidence-manifest.json)：全部归档成员、原始路径映射、字节 hash、必须携带集合及明确缓存排除项。
- [verify-evidence.py](verify-evidence.py)、[SHA256SUMS](SHA256SUMS)：分卷合并与校验。

归档包含 2712 个文件成员。NDU 的原 676 文件 hash 索引保留，其中 221 个原文件实际携带，455 个可再生 Cargo 中间文件明确排除；加上其依赖、工具源码、许可、独立检查与有限诊断，冻结 NDU 清单要求的 473 个 payload 文件全部携带。实际资源 VM、NDU bridge、driver、候选库、本地 C/HIA/Rust 原生文件以及选中保留的远端二进制另有报告绑定。

原始失败、精确 source publication 收据、开发 Git bundles、环境和完整启动器均保留。路径中测试用的反斜杠、盘符、空格等按组件编码进入归档，原始名称作为映射数据保留。没有纳入临时签名下载 URL、凭据配置或 toolchain/Cargo 中间缓存。

下载此目录各分卷后，可先检查而不写入新归档：

```bash
python verify-evidence.py
```

也可以创建经过完整 SHA-256 检查的原归档；已存在的输出路径会被拒绝：

```bash
python verify-evidence.py --output raw-evidence.tar.xz
tar -xJf raw-evidence.tar.xz
```

该交付证明的是所声明子集上的工程实现、实际执行和拒绝机制。绝对安全、任意 C/C++ 低成本重写、全语言 soundness、普遍超越 Rust 的性能，以及任意代码的全局最优都不在本次已证明结论中。
