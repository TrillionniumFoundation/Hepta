# 全量实现与验收记录：2026-10-26

本轮交付了可执行安全核心、资源组合资格、C/C++ 迁移扩展、真实目标执行和本地模型实验接口。七项长期目标仍有未关闭项；下面将可执行实现、有限测试结果和剩余义务分别列出。

## 源码与证据身份

- 原始基线：`1b5868a4e516786c61d1aead8ac7ec0c12f28d40`。
- 最终核心源码提交：`5da30269a94057fb4abe50b51a711e91003339b6`。
- 最终编译器 SHA-256：`dbeb5311dfb81d01d8704ef26800b5672bca89976efa6b74e10a9b255efb9f97`。
- 当前原生验收目录：[`evidence/full-scale-20261026/qualified`](../evidence/full-scale-20261026/qualified)。`compiler-source.json` 列出全部 73 个编译器 Python 文件的大小及 SHA-256，并把完整 C 模块的来源清单关联到同一编译器内容。
- 性能与模型实验固定在较早的源码提交 `bf5b7fc05fd459292773d7bc67f36f60ca464f87`，编译器 SHA-256 为 `91ab73f35b5fede9582b2b1066a0f38d910426c51239fcfe557154fc3fd850cb`。之后只读审查发现并收紧了新 Core 的准入边界。实验没有换候选、重抽顺序或被追认成后续源码的结果。

GitHub 发布通过官方连接器完成。本地初始提交 `0d56303ee0459c2a1be84e5747dcc837007abba5` 与公开提交 `bf5b7fc05fd459292773d7bc67f36f60ca464f87` 的 Git tree 完全相同，都是 `375cf3044c6d1473b3cb68c36f7df84452b1730c`；作者及提交时间导致 commit SHA 不同。第二组本地提交 `43feb123dcb5d5c7c20d3e77f690a3089e0ea6a6` 与公开提交 `5da30269a94057fb4abe50b51a711e91003339b6` 的 tree 均为 `2aab8ebb9f73a86ced25957326e3647db304a65b`。原始性能报告中的本地提交号保留原样。

## 七项交付状态

| 目标 | 本轮可运行的交付 | 当前验收边界 |
|---|---|---|
| 1. 统一安全核心表示 | `hepta.executable-core.v1`；独立解释器；从解码 Core 生成 LLVM；源代码重放、类型、效应和资源检查 | 数值、控制流、Buffer、具体 Result、调用期借用形成有限闭环。泛型、存储借用、名义 ADT、并发和全部模块尚未统一进入新 Core |
| 2. 资源与生命周期组合 | 泛型所有权、共享/可变存储借用、Result 错误退出、任务传递与合作取消在一个程序中执行；地址级分配观察和危险负例 | 存储借用依赖固定 Rust 的 region/alias 检查；仅测试三个具体 Buffer 实例；取消没有时限或强制打断保证 |
| 3. 完整 C 模块迁移 | 重新实际执行上游 Ring Buffer 全模块迁移；22 个活跃声明全部有去向；另验收多配置 C 项目 | 只覆盖捕获的构建配置及支持的 C 子集；指针来源、真实分配大小、初始化、别名和外部并发仍是明确前提 |
| 4. C++ 自动桥接 | v4 闭合的 `std::size_t` 非类型模板实参；真实 `std::array<T,N>`、scoped/handle 生命周期、异常边界；Boost 回归 | 桥接继续执行外部 C++，不能据此证明库内部内存安全；N=4→8 只测实例再生成成本 |
| 5. C++ 安全实现迁移 | 完整标量值类的局部变量、for/while/do、字段更新与声明身份绑定；三路原生差分与链接来源证据 | 原始类实现不进入迁移目标；任意析构、存储引用、虚继承、异常栈展开、回调逃逸及一般资源类仍未迁移 |
| 6. 性能与硬件 | 固定协议 63 个性能样本；AArch64 真实 Hepta 模块和两个错误实现执行；Cortex-M4 启动/MMIO/IRQ 与故障控制 | 性能稳定性门未通过，结论为 measurement_inconclusive。目标执行属于 QEMU；实体硬件、DMA、GPU、设备时序尚未验收 |
| 7. 真实 Agent 实验 | 两个不同真实权重、本地推理服务、独立模型锁和 token 账本、原四 arm 隔离协议、40 格随机计划 | 最终结果与解释见实验归档。小模型生成、合法工具调用和端到端正确任务分别计数；生成日志不能替代 coding 或语言优势证据 |

## 1. 同一份核心如何被执行

新 Core 将明确的数值和资源操作放进同一结构中，例如：

```text
int.add.checked
int.add.wrap
if / while / for
buffer.try_new / buffer.load
owner.move / owner.drop
borrow.read / borrow.mut
result.make / result.match
function.call
```

独立解释器直接执行这些操作。原生入口从 Core 操作重建新的 AST，重新检查并要求精确往返一致，再交给现有 LLVM emitter。源代码只用于新鲜重放和身份校验；代码生成消费解码后的 Core。

Core 准入同时运行真实 LLVM emitter 的纯 Python 可表示性检查，避免接受解释器支持、原生后端尚不支持的操作。布尔位运算 `& | ^`、有副作用的索引，以及索引子表达式内的 Buffer/slice 访问都在建立 Core 时拒绝。需要借用 owner 计算索引时，先将索引结果存入标量局部变量，再进行索引。`Result<Unit,E>` 当前也属于拒绝的组合。

每次验证和执行都会对给定源内容重建 Core、比较完整规范化结构。修改数值、类型、效应、资源身份或 claims 后重算外层哈希，不能绕过这个检查。原生构建仍必须通过固定 Rust 的真实引用检查；静态可表示性检查没有被写成原生执行证据。

公共命令：

```sh
python -m hepta executable-core program.hepta -o core.json
python -m hepta verify-executable-core program.hepta core.json
python -m hepta run-executable-core program.hepta \
  --core core.json --function entry --arguments '[16,7]'
python -m hepta build-executable-core program.hepta -o library.so
```

解释执行另有 `--max-steps`、`--max-heap-bytes` 和 `--allocation-fail-at`。解释器预算耗尽、语言 guard trap、显式错误返回及真实原生退出分别记录，不能相互替代。

参考 [`EXECUTABLE_CORE.md`](EXECUTABLE_CORE.md)。

## 2. 正确性与资源的实际结果

| 验证 | 本轮最终候选的实际结果 |
|---|---|
| Core 固定组合语料 | 56 组输入；168 次实际 LLVM/Rust/C 返回值执行与解释器一致；2 次预期 SIGABRT |
| Core 分配错误路径 | 四条原生路径累计 5 alloc、5 free、0 live、1 次实际 allocator wrapper 拒绝 |
| 额外数值交叉审查 | 72 个函数、928 个输入；928 次解释器结果及 1,856 次实际 Rust/LLVM 调用与独立整数 oracle 一致 |
| 资源组合原始程序 | 正常、错误退出、取消三条路径输出 `136`、`1013`、`2253` |
| 地址观察产物 | 3 个具体 Buffer：3 alloc、3 free、0 live；地址复用由 generation 区分 |
| 故意遗漏释放的对照 | 返回值保持正确，但出现 3 alloc、1 free、2 live、40 字节未释放；观察产物退出 91 |
| 组合危险负例 | 2 个前端接受的借用冲突由真实 Rust 以 E0505/E0502 拒绝；4 个漏消费或重复消费由前端拒绝；非法 Hepta 候选执行数为 0 |
| 最终本地回归 | 220 tests，通过，零跳过；完整命令和原始输出见 `qualified/regression.json` |

观察器修改过生成 Rust，单独编译并单独记账。未插桩原始产物也独立执行；观察器没有冒充原始机器码。allocator wrapper 返回 NULL 属于真实原生故障注入，不能称为操作系统发生真实 OOM。正常和显式错误路径的释放观测不推导出 panic/abort 下的析构或一般取消时限。

这些结果是有限执行与反例证据；源到 Core、Core 到 LLVM、LLVM 优化器和整个语言的 refinement/soundness 证明仍未完成。

参考 [`LIFECYCLE_COMPOSITION.md`](LIFECYCLE_COMPOSITION.md)。

## 3. 完整 C 模块与迁移成本

上游 Ring Buffer 的输入保持来源锁定，捕获实际 Clang 构建配置后生成了 104 行 Hepta 实现和 169 行 ABI bridge。全部 22 个活跃项目声明的分类为：9 个函数实现、9 个原型、1 个 record、1 个前向 record 声明和 2 个类型别名。

对 8 种容量分别执行 2,048 次状态转换，共 16,384 次转换、65,544 次差分调用。检查覆盖返回值、持久状态、每一个 backing-store 字节、输出 sentinel、源输入未改变以及 backing-pointer 身份；另有 543 次零长度/空指针 slice 调用。真正编译过的错误算法实现也由完整状态 oracle 捕获。

另一项多配置 C 项目完成 1,046 个差分输入及 10 条分配故障/恢复调用。报告中的 `65519` 是注入分配失败的输入大小，绝不是失败样本数量。

迁移产物包含实际 `source.hepta`、bridge、Rust 生成实现及 native library 的构建收据。临时 native binary 已回收，生成源码和来源清单保留。没有用原始 C 实现继续承担被宣称已经迁移的实现。

这里的“完整”指列出的预处理配置内，目标模块的全部活跃声明都有去向。未列出的宏配置不会自动获得资格。对于原始 C 指针，运行时检查空值、对齐和可表示长度；真实 provenance、extent、初始化、别名和其他线程的访问仍须由调用方合同保证。

自动运行耗时、生成行数和 ABI 调用成本均有原始记录；人工审核小时数和人工维护成本保持未知。Ring Buffer 的三个短时成本测量既有较快场景，也有较慢场景，不能用其中一个比率证明全应用性能或普遍低迁移成本。

## 4. C++ 实现与桥接分别验收

完整值类迁移按 Clang 声明身份区分字段、参数和局部变量，避免遮蔽名字造成错误。局部变量须显式初始化，控制流和数值语义继续复用共同的 C lowerer。带状态的 Mixer 类在原始 C++、实际 Hepta/Rust 和实际 Hepta/C 上各执行 592 个案例，并与独立整数 oracle 比较。

目标链接的来源通过实际 linker map、符号表和只存在于原始 C++ oracle 中的 marker 检查；被替换类实现不进入迁移目标的链接。自定义析构、任意资源所有权或引用逃逸不会因为循环支持而被自动接受。

桥接 v4 的非类型模板参数采用闭合数据描述：

```json
{"template_args": ["u32", {"kind": "size", "value": 4}]}
```

它只接受范围 `[0,65536]` 的精确 JSON 整数。布尔值、浮点值、负数、任意 C++ 表达式和未知字段都被拒绝。桥接在真实 `std::array<T,N>`、可观测析构见证及显式 handle 上执行，并保留异常转换、空输出和失败 sentinel 的结果。

`N=4 → N=8` 实验改变 3 个 descriptor 值，consumer 源码修改数为 0，公开 C header 字节一致；生成 C++ 删除和增加各 26 行，native object 从 44,256 增至 44,288 字节。它测量的是闭合实例再生成成本，上游库版本升级和人工审核成本仍未量化。

参考 [`CPP_LOOPS_AND_SIZED_TEMPLATES.md`](CPP_LOOPS_AND_SIZED_TEMPLATES.md)。

## 5. 性能与目标平台

固定 owned 性能协议包含 3 个 kernel、3 个定时后端和 7 组配对顺序，共 63 个原始样本。运行前暂停了本任务自己的模型推理与并行编译。所有样本均保留，没有重跑挑选较好结果。

本次原始时间比的几何平均为 LLVM/同源 Rust `0.9633`、LLVM/手写 Rust `0.7786`，未触发退步阈值；但 4 组相对 MAD 超过预设 5% 上限，因此完整判定为 **`measurement_inconclusive`**。这些比值不是通过稳定性门后的性能保证。较早提交或单个 kernel 的优势不能补成当前候选的通过结果。

目标执行有两组当前源码的实际证据：

- AArch64：实际 Hepta 模块通过 Rust 主机参考检查、直接 LLVM object 生成、有限运行时链接和锁定 QEMU 执行。一个正常实现通过；两个故意改错返回路径的 Hepta 实现分别以预期退出码 11、13 失败，失败产物没有发布。正常运行包含 7 个 ABI 调用场景及分配器/内存原语检查。运行时仅有一个至多 4096 字节的活跃分配。
- Cortex-M4：4 个真实编译镜像、6 次 cold boot；正常镜像重复启动 3 次，每次执行 5 个外部定时器中断。错误 IRQ checksum、禁用 IRQ、漏 `.data` 拷贝三种故障均被独立 oracle 识别。

ARM64 发布物仍是 relocatable object；实际执行的是包含相同 object 的另一个链接镜像，报告明确区分这两者。两组目标执行都属于模拟器，尚未覆盖实体板卡、DMA、GPU、真实设备时序或一般平台 ABI。

工具链安装还修复了一项真实遇到的问题：Rust `install.sh` 可能在 `cp` 因空间不足失败后仍退出 0。新的安装收据逐 payload 校验文件大小、SHA-256、执行权限和 symlink 边界；相关 8 个测试含实际截断/空文件和逃逸负例。

## 6. 真实模型实验的解释原则

实验使用两个不同的 135M 真实权重、5 个任务和 4 个 arm，共 40 格预先冻结的随机顺序。模型来源 revision、权重/tokenizer hash、CPU dtype、线程、提示格式、运行时包、provider 源码及任务快照均锁定。原 namespace、文件权限、native check 和隐藏评分门禁保持不变。

原始报告和独立账本审计会分别给出：真实生成次数、合法工具调用次数、端到端完成数、是否实际进入代码正确性评分、输入/输出 token、推理请求时长、初始化/工具时长、人工介入、外部推理 API 支出和未知的本机计算币值。只有原始 token IDs 与文本以及冻结计划对应的实际调用才计入真实模型分母；测试 fixture 和合成协议响应不计入。

小模型即使产生完整生成账本，也未必能完成编码协议。没有有效工具操作或正确补丁时，不能推导出 Hepta 的 coding 优势，更不能外推到其他模型系列或更强的 coding agent。共享宿主上的推理时长波动不会被归因于编译器或语义工具。

本次 provider 的独立只读审计见 [`LOCAL_MODEL_ADAPTER_REVIEW.md`](LOCAL_MODEL_ADAPTER_REVIEW.md)。模型锁的相同线程值和实际生成配置已核对；审计器是内容与账本对应检查，不是对不受信任主机的模型执行认证。

## 继续关闭全量目标所需的工作

1. 把一般泛型、存储借用、名义 ADT 和并发协议合入同一个可执行核心，并明确错误、退出和取消的组合语义；逐步证明源到核心及后端的对应关系。
2. 扩大真实 C/C++ 模块范围，覆盖更多构建配置、资源类、异常、别名和回调，并测量真实上游升级及人工审核成本。
3. 在稳定的独占性能环境完成相同安全口径的门禁，并在实体设备上分别验收 ABI、MMIO/IRQ、DMA、GPU 和设备时序。
4. 用能实际完成协议与编码任务的多组模型重做独立语言/工具效果研究；同时保留错误率、人工介入、回归、token 和总成本，不只比较生成速度。

这四项仍作为未关闭的工程和研究义务保留，不会由有限差分测试、源哈希或桥接成功自动消除。
