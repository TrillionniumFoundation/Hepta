# Hepta 统一源码：最终执行读出

公开源码：[PR #552](https://github.com/TrillionniumFoundation/Hepta/pull/552)，提交 `7a12975aaf19f7e910d44dc26d02589f321aa368`，tree `059a5923f91de5a70dcea66f650bea5ee9ab4bd5`。
原始证据保留在本包，未公开上传到GitHub。SOURCE.json列出已公开的65个变更文件的逐字节身份。

## 验收结果

| 检查 | 本轮实际结果 |
| --- | --- |
| 整合回归（193模块） | 1656/1656 执行；FAIL=0，ERROR=3，SKIP=0；passed=False |
| 可信核心 | 269/269；无跳过，源码与测试身份未漂移 |
| Rust Core | 121/121；无失败或忽略 |
| 选定程序证明 | 两export各量化全部2^64输入，共4 UNSAT；2个SMT查询独立重放 |
| Lean限定模型 | 16条记录、15个唯一定理名；5个负kernel控制拒绝；272对VM观察一致 |
| 原始Rust NDU/独立DP | 最终公开源码18/18模型与完整winner集一致，不代表经济优势 |
| GSL双版本迁移 | 4,992正观察、14,976 scalar调用，原始输出独立复算一致 |
| JSON双版本恢复 | 146 worker；28 caught exception、6真SIGABRT、34新请求重建及后续执行 |
| 本机和目标 | x86-64真实native；AArch64为QEMU，不视为物理设备资格 |

这是既有整合验收计划及双方新增模块的193模块范围，不代表仓内每个历史测试或完整release矩阵。
这些测试组有重叠，不相加为独立样本总数。全回归的完整计划、实际测试身份和原始错误均在
`evidence/full-regression-7a12975/`；不删除环境错误、跳过或改变门槛来生成绿色结论。

## 性能与成本：负结果保留

- LTO v1正式观察27/30比较通过，Rust9/10；总门槛false。
- Rust PGO v2正式观察25/30通过，Rust8/10；总门槛false。
- PGO只使用注册训练轴；准备实际8.408895009秒。两组各运行一次，未选优重跑，26,706项独立复算通过。
- 两组性能及NDU economics源为662f05d；其完整Git tree与公开7a12975完全相同。公开提交只改变发布元数据，未重跑挑选样本。
- NDU 12/12 episode与192正确性/allocator观察通过，但策略期invoke=0；对fixed服务成本比1.615/2.090/2.130，总收益未成立。
- 三类bridge及stream真实构建、搜索、准备、校准、完整load和最终身份核对成本分别记录；人工、能耗和完整生命周期成本不填零。

## 远端CI配置修复

公开实现7a的旧workflow已通过210项Core一致性，但新增trusted suite因默认Rust1.95/旧Clang++产生1 FAIL+2 ERROR。
独立[PR #553](https://github.com/TrillionniumFoundation/Hepta/pull/553)只修复该workflow的工具链选择；实现、测试及实验协议未改。
原始远端日志和新运行状态均在`evidence/ci-original/`中，原失败不抹除，不用本地绿色替代新远端结果。

## 当前严格边界

P0–P7完整目标仍开放：全量回归必须按实际错误判定；一般生产type/resource soundness、跨模型总精化、
物理多平台ABI、独立真实应用性能、完整生命周期NDU净收益、未见真实Agent任务与生产外部副作用恢复尚未成立。
Agent零生成preflight的编译器/native控制通过，app-server startup仍因EROFS失败；未产生模型或任务请求。
受控进程故障、QEMU和限定数学模型均按各自范围计量。

## 结构与复核

- `evidence/FINAL_READOUT.json`：最终来源、精确回归结果及各独立读出索引。
- `evidence/performance/`：两份唯一正式campaign、全部尾样本、raw profiles/binaries及独立算术读出。
- `evidence/formal/published-final/`：公开源码上的首次新鲜证明、Lean原始执行、SMT查询和来源锁。
- `evidence/abi-final/`、`evidence/migration-final/`：实际native/目标与双版本迁移/恢复记录。
- `evidence/ndu/`：真实Rust来源/构建、原始负结果、成本模型与最终运行。
- `evidence/agent/`：只允许initialize/initialized的客户端探针与原始启动失败。
- 其余root日志和开发RED/GREEN均保留原来源，不代替最终结果；原先错误的短SHA调用也明确保留。
- `environment/`：实际执行脚本与四个既有native桥的环境映射；工具获取在各原收据中。
- `PAYLOAD_SHA256.json`：本包全部载荷的字节数与SHA256。诊断运行时缓存和启动原配置未归档。

以每份RESULT/qualification/readout的source、mode、status和claims为准；退出0或scoped通过不构成production授权。
