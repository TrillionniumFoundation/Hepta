# HIA 编译器与自举增量审计

基线为 `807bbc4ce64b80d34b3102c774daf35e454d04be`。本次检查实际源代码、编译路径、工作区写入者和原生执行记录；没有把生成源码、固定点或局部形式化模型升级成全产品资格。未发现适用的 `AGENTS.md`。

## 实际边界

| 位置 | 实际行为 | 尚未闭合 |
| --- | --- | --- |
| `pyproject.toml` 的 `hia` 入口与 `hepta/cli.py` | 普通命令由 Python CLI 装配，默认 build backend 为 `native` | 十五 action 全原生入口 |
| `hepta/hia_program_native.py` | Python 实现直接 x86-64 指令及 ELF object 编码 | 默认完整 direct emitter 的 HIA 替代 |
| `hepta/hia_program_selfhost.py` | 显式选择并封存 HIA frontend/compiler executable，原生输出有限 primitive Core v8 ELF object | 完整 Core 支持域、输入检查、发布和进程管理仍有 hosted owner |
| `tools/qualify_hia_selfhost.py` | B0 由 Python checker/direct emitter 和 GNU ld 生成；后续由先前 HIA image 编译源字节 | seed 与独立观察器是明确的信任边界，固定点不是全语言正确性证明 |
| `hepta/hia_agent_service.py` 的 `_compile` | 普通 Agent 编译仍调用 Python direct emitter | service 路由与既有安装身份不能仅靠删除模块迁移 |
| `formal/README.md` | Lean 证明限定的抽象资源与表达式模型 | 未证明实际 checker、完整 Core、allocator/FFI 和 machine backend 的语义对应 |

当前 HIA 源码是真实 scanner/parser/checker/x86 emitter；Python authoring generator 生成的文本也真实参与后续自编译。二者都不能推出普通 CLI、十一工具服务和耐久效果已经原生化。

## 本次原生编译器优化

`tools/generate_hia_selfhost.py` 与生成的 `examples/hia_bootstrap/selfhost.hepta` 同步修改：

- 每个函数原来的 2,048 次循环、4,096 个八字节 strided fill，改为两个现有受检查 bulk fill，覆盖当前函数的 name table 和 SSA table。
- `loan_access`、`loan_borrow`、`owner_free` 仍逐个检查所有可能存活的 SSA 身份，但上界使用当前函数已 intern 的身份数量。
- 1 MiB workspace、2,048 SSA capacity、所有借用拒绝规则、cold 的 180 秒及 cleanup 的 3 秒限制均未调整。

安全性理由来自实际写入者：`read_value_name` 为当前函数产生连续身份并增加 count；`define` 是 SSA type 的非零写入者，写入类型和 block origin；每个函数先清空 type table。未 intern 的槽位 type 为零，无法通过 `loan_live`。名称表以 size 为零判空，空槽位的旧 source offset/index 没有活语义。bulk fill 所覆盖的两个完整私有区间均未进入相邻表。

## 实测与证据

最终 HIA 源 SHA-256 为 `e93976f99e38be69b8f8dab9e362d238b6d19bc5fc72061cec0610a37bfe55e2`；生成器 SHA-256 为 `f39282e56d1ff88a0a056180fb3b88e34554ccfc12bb9bad4b132c613f5f5689`。

`compiler-differential.json` 保留全部 600 项比较：300 个不同程序，包括函数/SSA 名称、hash collision、满表/超界、CFG、非首 entry、公开 exports、allocator、borrowed loans、owned buffer、chain、跨块 owned/chain flow 及原拒绝输入。每个程序分别使用全零及 `0xA5` 初始 workspace，执行修改前/后的实际原生编译器，比较完整 1 MiB 输出字节与全部公开 workspace header 字段。600/600 一致。修改后编译器用同一源码再次自编译，两个输出 image 完全相同。

该次比较中 compiler native 时间总和为 8.487824586 秒与 7.539536119 秒，after/before 为 0.8882766；这是这一组有限程序在该主机上的观察，不能推成完整 cold 时间改善或性能保证。15 项 scanner/name source tests 在 106.070 秒完成，零 failure/error/skip。

原始编译输入、输出、receipt、固定点 image、修改前后源码、测试日志及复现实验脚本保存在 `compiler-differential.tar.xz`；`compiler-differential-archive.json` 记录每个成员的长度和 SHA-256，并在删除本任务临时副本前从压缩包逐成员回读验证。

比较所用旧 B3 是基线超时 cold 中已经产生的原始 image；该 cold 整体并未通过。以上是组件观察，`cold_qualification_performed=false`、`all_input_equivalence_proved=false`、`whole_native_delivery_qualified=false`。完整冻结源码仍须执行其自身验收，不能用这些局部结果替换失败记录或完成整套旧 owner 的移除。
