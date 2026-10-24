# Hepta

**Hepta 是面向 AI agent 开发流程的原生系统编程语言原型。**

本工程实现了严格解析、类型与效果检查、线性资源检查、Rust 后端验证与代码生成、C 头文件导出，以及带源码/接口身份的语义修改接口。名称由用户确定为 **hepta**；命令名为 `hepta`，源码扩展名为 `.hepta`。

这是 **0.1.0 研究原型**。Python 只用于 bootstrap 编译前端；生成的程序是原生二进制，不携带 Python 解释器。固定 Rust 1.90.0 后端负责最终类型/借用检查与机器码生成。项目没有将全语言健全性、普遍优于 Rust、所有平台 ABI、真机硬件资格或 agent 生产率记为已验证。

## 快速开始

需要 Python 3.11+、固定 Rust 1.90.0。C 互操作验证还需要 GCC、binutils；所有前端代码只依赖 Python 标准库。

已有 rustup 时：

```sh
rustup toolchain install 1.90.0 --profile minimal
export RUSTC="$(rustup which --toolchain 1.90.0 rustc)"
python -m hepta doctor
python -m hepta run examples/parser.hepta
python -m hepta run examples/ownership.hepta
python -m hepta run examples/tasks.hepta
```

Linux x86-64 也可以使用随工程提供的固定校验和安装器，将工具链安装在项目外的独立目录：

```sh
python tools/bootstrap_toolchain.py
```

该命令访问官方 Rust 下载地址，校验工程内锁定的 SHA-256，安装 rustc 与指定 target 的标准库。它不修改系统目录或 shell 配置。具体编译器路径由命令输出；也可以用 `--rustc PATH` 明确选择。显式路径失效不会静默回退。

## 一段 Hepta 程序

```text
pub fn sum(input: read [u64]) -> u64
effects { panic }
resources {
    heap_allocations = 0;
    may_block = false;
    may_suspend = false;
    may_spawn = false;
}
{
    let mut result: u64 = 0;
    for i in 0..len(read input) {
        result = wrapping_add(result, input[i]);
    }
    return result;
}
```

索引保留安全检查，前端保守记录 `panic` 效果；后端可以消除已证明多余的检查。整数普通算术的溢出检查在优化构建中仍然启用，明确需要模运算时使用 `wrapping_add/sub/mul`。

## 已实现的纵向样例

| 样例 | 实际验证内容 |
| --- | --- |
| `examples/parser.hepta` | 无分配的小端二进制解析器；短输入与有效输入均运行验证 |
| `examples/ownership.hepta` | Buffer 创建、读借用、所有权移动与显式释放 |
| `examples/tasks.hepta` | 真正的 OS 子线程、所有权转移、join 与协作取消后等待完成 |
| `examples/ffi/` | C→Hepta→C 双向调用；多种结构体按值传参/返回 |
| `benchmarks/borrowed.hepta` | 安全切片 read/mut、栈数组和独立 Rust 正确性对照 |
| `benchmarks/kernels.hepta` | 可导出 C ABI 的无分配 sum/copy，与独立 Rust/C 基线比较 |

任务 profile 当前限定 `Task<u64>`；worker 接收 `take Buffer<u8>` 和 `read Cancellation`。任务句柄必须在所有正常退出路径上消费。`cancel_and_join` 请求取消并等待，**不承诺取消时限，也不证明任意 worker 会终止**。

## 命令

```sh
python -m hepta check examples/parser.hepta
python -m hepta inspect examples/parser.hepta
python -m hepta emit examples/parser.hepta --output build/parser.rs
python -m hepta build examples/parser.hepta --output build/parser
python -m hepta build examples/ffi/abi.hepta --crate-type staticlib --output build/libhepta.a
python -m hepta header examples/ffi/abi.hepta --output build/hepta.h
python -m hepta build benchmarks/kernels.hepta --crate-type obj --no-std --output build/kernels.o
```

`check` 默认调用真正的 Rust 后端，并要求获得非空 metadata。`--frontend-only` 是明确降级的检查方式，报告标记为 `frontend_only`，借用验证仍为 `not_run`。`inspect` 返回真实签名、effects、资源条款、符号范围、调用关系及检查结果。

`patch` 支持一次编译单元内的函数 body 替换，要求源码和接口 SHA-256 都匹配；候选程序通过完整检查后才能 `--apply`。见 [协议说明](docs/AGENT_PROTOCOL.md)。该机制保持声明的接口/效果/资源合同，**不自动证明功能等价**。

## 重跑验证

```sh
python -m unittest discover -s tests -v
python tools/validate.py --bench --output artifacts/native-validation.json
python tools/abi_fuzz.py --output artifacts/abi-matrix.json
python tools/release_check.py
```

后两类原生验证需要相应系统工具。交叉对象编译需要安装该 target 的 Rust 组件。验证程序区分主机执行、交叉编译、外部假设与未完成资格，报告绑定实际源码和工具链。

被测 sum/copy 函数与独立手写 Rust 的机器码逐字节比较保存在 `artifacts/native-validation.json`。这个结果只适用于报告中的函数、目标、工具链和编译参数，不是整门语言性能的证明。

## 工程结构

- `hepta/`：词法/语法、AST、语义检查、Rust 后端、CLI、agent 协议。
- `tests/`：正反例、真实原生测试及独立协议审查回归。
- `examples/`：可运行样例与 C 互操作。
- `benchmarks/`：独立基线、驱动及基准方法。
- `tools/`：安装、ABI 矩阵与发布快照验证。
- `docs/SPEC.md`：当前实际实现的语义和限制。
- `docs/BLOCKERS.md`：阶段完成条件与仍开放的发布门槛。
- `artifacts/`：落盘的执行证据。

完整生产语言的剩余工作保留在 blocker ledger 中。任何未支持的语法、效果、资源数值预算或 ABI 形式都会拒绝，不会默认为已经验证。
