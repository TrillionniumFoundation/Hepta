# Owned LLVM 首测的独立静态审查

本报告只审查冻结提交 `fa4f8209e45b98e5b1f4cf42e3c47d657d3249d3`
的源码、首测回执与静态编译结果。没有执行基准，没有新增计时样本，没有修改
两条 Rust 基线、工作负载或验收门槛。它不授予性能通过资格，也不覆盖后续 LLVM
实现变更。

## 结论与首测口径

源码与静态 IR 审查未发现三种实现的选定工作负载存在语义差异：均包含可失败的
零初始化字节所有者、相同的显式构造拒绝、移动、借用读写、逐次检查的整数累加与
释放。未发现手写 Rust 通过 wrapping
累加或删除实际分配失败分支获得速度优势。这里的静态检查和有限执行样本不是
整个语言的语义等价证明。

原始首测的 63 个样本全部保留。直接从这些样本重新计算中位数、MAD 与配对比率，
得到与原回执一致的结果：

| 工作负载 | LLVM 中位 ns/调用 | 同源 Rust 中位 ns/调用 | 手写 Rust 中位 ns/调用 | LLVM/同源 Rust 配对中位比率 | LLVM/手写 Rust 配对中位比率 |
| --- | ---: | ---: | ---: | ---: | ---: |
| full_lifecycle | 2,339.706 | 2,959.568 | 1,777.409 | 0.828595 | 1.331576 |
| constructor_error | 63.327 | 25.391 | 25.056 | 2.514606 | 2.611979 |
| two_stage | 1,682.913 | 1,553.885 | 2,889.227 | 1.090644 | 0.588606 |

`constructor_error` 的同源 Rust、手写 Rust 相对 MAD 分别为 10.516% 和 7.881%，
均高于预先冻结的 5%。因此原始状态仍为 `measurement_inconclusive`。同时保留
单项 1.20 与几何均值 1.10 门槛的失败，不能因质量不足而抹掉这些结果。
配对中位比率不是两列中位 ns 的简单商。

## 源码与工具身份

完整的字节身份、原始静态编译命令、退出状态和带原始行号的 IR 摘录保存在
`evidence/llvm-owned-static-audit-20261025/review.json`。关键身份如下：

| 对象 | SHA-256 |
| --- | --- |
| 原始 `fa4f820.v1.json` 回执 | `53da0bf43fe55e8bddb145980dc2ff2d85d2b8ae39a49d201d31ad67a61b2424` |
| 首测输入 LLVM IR | `71677363e005e4ff6a41e2152e65d8a476cf64b10d6b6f4f244ce6f3d1139188` |
| 已归档的首测优化 LLVM IR | `1ae3e34df34254d5ae204df456c91b69ba54be019ff94574bace73545d5451ad` |
| 本次同源 Rust 静态 LLVM IR | `69e9034583e3fb3125bb34170a1ef3a63963cce34c3dc25a8e997913ef1696d0` |
| 本次手写 Rust 静态 LLVM IR | `c02b975fc9739b2d51150dee2fa1cdb13ecd3daf61946a9bcd075167defabded` |

使用 `hepta.pipeline.analyze(SOURCE, receipt["reference_validation"]["path"],
native=False, crate_type="cdylib")` 再生成同源 Rust；其完整字节 SHA 与首测
`generated_rust_sha256` 一致。手写 `reference.rs` 同样与首测字节 SHA 一致。
LLVM 从原始回执的 `llvm_ir` 原样取出，不读取正在改动的 LLVM 后端来替代首测输入。

两条 Rust 路径仅执行固定 Rust 1.90.0 的静态编译：`--edition=2021`、
`--crate-name=hepta_program`、`--crate-type=cdylib`、`-C opt-level=3`、
`-C overflow-checks=yes`、`-C panic=abort`、`-C codegen-units=1`，并通过
`--emit=llvm-ir=...,asm=...` 输出诊断文件。LLVM 仅运行固定 Clang 20.1.2
的 `--target=x86_64-unknown-linux-gnu -x ir -O3 -fPIC -S`。编译器可执行文件
字节 SHA 已重新比对首测身份。具体绝对路径和完整参数在 JSON 中保留。

这些是新生成的静态诊断产物。原协议在保留身份后删除了被计时的共享库；因此本报告
不把新 IR 或汇编冒充原来被计时的二进制，也不把环境内的绝对路径当作可移植安装路径。

## 有代码证据的发现

### Rust 的分配拒绝仍存在

两条 Rust 的 `constructor_error` 汇编逐行相同。它们都调用
`alloc::raw_vec::finish_grow`，读取结果标记，并在成功分支释放数据。
`finish_grow` 保留可返回 null 的 `__rust_alloc` 调用，比较返回指针是否为 null，
再构造失败结果。容量超过 `isize::MAX` 的分支也保留。

证据为 JSON 中 `generated_rust.ll:234`、`handwritten_rust.ll:238`
的完整函数，以及 `handwritten_rust.ll:11` 的 `finish_grow`。
这里没有把 `try_reserve_exact` 换成必定成功的分配，也没有把整个构造错误路径
替换成常量结果。实际错误回传与释放流程仍在。

### `.sum()` 没有放宽溢出语义

`reference.rs:31` 和 `:57` 的 `sum::<u64>()` 在上述固定编译参数下仍生成
`llvm.uadd.with.overflow.i64`，分支跳转到加法溢出的 panic 路径。对应汇编是
加法后的 carry 检查；没有向量化的 wrapping reduction。

证据为 `handwritten_rust.ll:212`、`:521`；同源 Rust 的相应调用在
`generated_rust.ll:206`、`:498`。因此不能通过把 Hepta 累加改为 wrapping，
或者把 Rust 基线改成额外检查版本，来解释或“修复”这一性能差距。

### 构造失败路径的清零和分支存在明显差异

首测 LLVM 优化 IR `fa4f820.optimized.ll:192` 的 `constructor_error`
在成功分配后仍执行整段 `memset(size)`，之后才经过两层 aggregate Result 的
phi、tag 提取和 switch，最终释放并返回错误。该函数保留 75 行优化 IR。
当计时大小为 4,093 字节时，它清零随后不会被读取的 4,093 字节。

两个 Rust 版本都移除了此路径的大块清零，只剩最后一个字节的写入，然后释放。
这不是源码的零初始化保证被放宽；未被任何程序读取消费的写入被优化器消除了。
可失败分配、结果判断和释放仍保留。LLVM 整体 Result 合并阻碍已知成功/失败事实
向后传播，是一个具体的实现优化目标。

### 完整生命周期的额外逐字节边界分支

首测 LLVM 的 checksum 循环 `fa4f820.optimized.ll:156` 同时保留：

1. 当前索引与从 Result 提取的 Buffer 长度比较，失败时 abort；
2. 字节加载和检查溢出的加法；
3. 当前索引与原始 `size` 的循环终止比较。

两个 Rust 版本已证明循环上界与 Buffer 长度一致，消除了第一项，仍保留溢出检查。
LLVM 这里每字节增加一个条件比较/分支。初始化循环还存在相似的长度事实丢失。

建议首先使内部 Result/owner 返回值能够被标量替换和控制流简化，例如可被 SROA
处理的分字段返回存储；保留实际分配拒绝及必要 bounds/overflow 路径，验证优化后
确实消除冗余分支。不能直接删除检查或断言未证明的 alias/长度事实。

这些差异说明有真实优化空间，但静态证据不能精确分摊 2.5 倍或 1.33 倍差距。
同源与手写 Rust 的 full_lifecycle 主循环指令也非常相近，而首测时间仍不同；
代码布局、主机执行条件与其他细节尚未通过独立实验区分。本报告不自行计时来选择
更有利的数据，也不声称某一条优化必然使冻结门槛通过。

## 分配故障公平性的证据边界

原首测在四个后端各执行 196 个有限正确性输入，包括显式构造拒绝与不可能容量。
源码检查和静态 IR 支持两条 Rust 的容量与可失败分配路径一致。

但原报告的 **真实第二次分配拒绝** 来自只链接 LLVM object 的 malloc/free
观察器：7 次成功分配、7 次释放、零存活分配、1 次实际拒绝，并有删除 free 的
已编译负控制。两条 Rust 当时没有接入相同的实际拒绝观察器。不得把 LLVM 的
这条运行证据归给 Rust，也不得把容量拒绝当作已真实注入 malloc 失败。

若补充两 Rust 的 `#[global_allocator]`/System 转发观察器，应作为新的、未计时
正确性证据独立保存，保留未修改基线源码的身份，验证真实分配、实际拒绝、清理与
恢复，并设置可执行的负控制。该补充不能改写原首测或替代性能门槛。
