# Hepta

**Hepta 是面向 AI agent 开发流程的原生系统编程语言。当前版本：0.2.0 研究原型。**

公开仓库：[TrillionniumFoundation/Hepta](https://github.com/TrillionniumFoundation/Hepta)。命令名 `hepta`，源码扩展名 `.hepta`。Python 用于编译前端；生成的原生程序不携带 Python 解释器。

Hepta 有独立语法、AST、模块解析、类型/效果/线性资源检查和 Agent 协议。默认 Rust 后端保留最终借用验证和成熟优化路径；独立 C11/GCC 后端直接从 AST 生成原生程序，其支持范围更小。两条路径的资格分别报告。

## 当前实现

| 领域 | 能力 | 边界 |
| --- | --- | --- |
| 模块与包 | 多文件 import、别名、公开性、循环检查、本地依赖、内容锁 | 无远端注册表、版本求解器或构建脚本 |
| 类型 | 枚举、穷尽 match、Result、用户泛型 | 泛型/ADT 参数为 Copy；无 trait、资源载荷 ADT 或任意生命周期参数 |
| 内存与效果 | read/mut/move、线性 Buffer/Task/TaskGroup、传递 effects | Rust 路径的最终借用检查由 rustc 执行；无全语言健全性证明 |
| 并发 | OS 线程、任务组、有界 channel、背压、协作取消与错误传播 | 每组任务准入、输入字节、队列槽预算，不等于进程 RSS/CPU/全局内存上限 |
| C 接入 | C ABI、头文件生成、探针驱动的头文件导入 | 普通原型/结构/别名/整数常量宏；复杂 C 形式明确拒绝 |
| 独立后端 | C11/GCC、独立保守借用检查、checked 运算与索引 | 本机 64-bit、标量/数组/结构/借用切片；泛型/ADT/任务运行时拒绝 |
| Agent 工具 | JSON 检查、调用图、图快照绑定的函数体修改 | 保持声明合同，不证明功能等价；合作写入者共享源码锁 |
| 形式化核心 | Lean 检查的资源/预算不变量和小型表达式降级定理 | 未证明实际编译器、FFI 或硬件对应抽象模型 |
| 跨目标 | 多目标 no_std 对象；AArch64 在 QEMU 下实际执行 | 模拟执行不等于真机、驱动或跨 C 编译器 ABI 资格 |

未支持的语法、效果、资源条款与 ABI 形式均明确拒绝。完整目标与剩余工作见 [blocker ledger](docs/BLOCKERS.md)。

## 快速开始

需要 Python 3.11+。默认后端固定 Rust 1.90.0；C 后端/互操作验证需要 GCC 与 binutils。

```sh
rustup toolchain install 1.90.0 --profile minimal
export RUSTC="$(rustup which --toolchain 1.90.0 rustc)"
python -m hepta doctor
python -m hepta run examples/results.hepta
python -m hepta run examples/groups/bounded_pipeline.hepta
```

Linux x86-64 也可以运行 `python tools/bootstrap_toolchain.py`，安装带固定官方归档校验和的工具链。安装位置在项目外，不修改系统或 shell 配置。

### 多文件与本地库

```sh
python -m hepta lock examples/packages/app
python -m hepta check examples/packages/app --locked
python -m hepta run examples/packages/app --locked
```

示例从独立 algebra 库导入泛型函数、Result 和枚举。Hepta.lock 绑定清单、依赖图及源码字节，过期锁文件会被拒绝。

```hepta
module app;
import algebra;

fn main() -> i32 effects { panic } {
    let values: [u64; 4] = [1, 2, 3, 4];
    let result = algebra::sum(read values);
    match result {
        Result::Ok(total) => {
            let checked = algebra::identity::<u64>(total);
            if checked == 10 { return 0; } else { return 1; }
        },
        Result::Err(error) => { return 2; }
    }
}
```

### 两条原生编译路径

```sh
python -m hepta run benchmarks/borrowed.hepta
python -m hepta run benchmarks/borrowed.hepta --backend c
python -m hepta emit benchmarks/borrowed.hepta --backend c --output build/borrowed.c
python -m hepta build examples/ffi/abi.hepta --crate-type staticlib --output build/libhepta.a
python -m hepta header examples/ffi/abi.hepta --output build/hepta.h
```

C 路径不调用 rustc，报告中的 rust_borrows_types 保持 not_run。默认 Rust 路径要求真实非空产物。显式工具链失效不会静默回退。

### C 头文件导入

```sh
python -m hepta import-c examples/interop/native.h --output build/native.hepta
```

命令执行真实类型/布局/常量探针，生成 .hepta 与 .imports.json。加载时核对源码身份和主机资格；缺少元数据、内容不匹配或未经重新验证的交叉目标都会拒绝。头文件事实不证明外部实现的所有权与效果。

## 并发与预算

`task_group(max_tasks, max_input_bytes, queue_slots)` 创建组内有界运行时。group_spawn 移交 Buffer，满队列形成背压；消费后 join，或请求取消并等待实际完成。GroupReport 返回准入/拒绝、输入字节、队列峰值、等待和错误信息。

预算约束单个组生命周期内累计准入任务数、累计输入长度和排队 u64 消息数，不覆盖提交前分配、worker 新分配、线程栈、运行时元数据或其他组。取消依赖 worker 合作。panic=abort 仍结束进程。见 [并发语义](docs/BOUNDED_CONCURRENCY.md)。

## Agent 接口

```sh
python -m hepta inspect examples/packages/app
python -m hepta patch examples/packages/app --request request.json --apply
```

hepta.patch.v2 绑定源码、解析后的 import 边和接口，修改一个函数体。重叠图与 v1 编辑共享按顺序取得的源码锁；提交前复核内容与路径绑定。dry-run 也必须使用请求的依赖快照。它不证明功能等价、不回滚外部副作用，也不对非合作写入者承诺全局事务。见 [协议](docs/AGENT_PROTOCOL.md)。

## 验证

```sh
python -m unittest discover -s tests -v
python tools/validate_groups.py --repeats 3 --output evidence/groups/native_validation.json
python tools/benchmark_suite.py --output artifacts/representative-benchmarks.json
python tools/bootstrap_verification.py
python tools/release_check.py
```

完整验证还需要固定 Lean 和 QEMU，见 [安装与资格说明](formal/README.md)。报告绑定源码、工具链和产物，区分前端检查、原生执行、模拟执行、外部假设及未完成资格。

当前快照的全部验收门槛、源码身份和逐项证据链接在 [release-validation.json](artifacts/release-validation.json)；报告保持完整生产目标未闭合的标记。

性能报告保留全部样本和回退。sum/copy 与另外四个算法具有独立手写 Rust 基线；局部机器码一致不能扩展为全语言保证。Agent 评测器的可信夹具与真正多模型实验分开计数，oracle 解不能当作模型生产率证据。

## 文档

- [核心语义](docs/SPEC.md)
- [ADT、Result 与泛型](docs/ADTS_GENERICS.md)
- [模块与包](docs/MODULES_PACKAGES.md)
- [有界并发](docs/BOUNDED_CONCURRENCY.md)
- [C 接入与独立后端](docs/C_INTEROP.md)
- [性能方法](docs/REPRESENTATIVE_BENCHMARKS.md)
- [Agent 协议](docs/AGENT_PROTOCOL.md)
- [Agent 评测器](experiments/agent_eval/README.md)
- [版本与后端兼容性](docs/COMPATIBILITY.md)
- [剩余 blocker](docs/BLOCKERS.md)
