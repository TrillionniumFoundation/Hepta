# 逐实际模型配对审计与输入绑定补强

## 交付结论

源码补强提交：`5a196faab0c0a302c9d6d5b81b9fc03945bdebe1`。在原 `b89e881` pilot 数据上增加一次独立离线审计，**14/14 个实际提交给 NDU 的模型，重放 beam 后完整候选计划与原生选中首动作均一致**。原模型中的成本、状态、预算、elapsed、目标和观测摘要保持逐字节相同，仅请求 mode 改为 beam。

这证明的是“每个实际 NDU 模型的 matched-model counterfactual”。原在线 beam arm 仍使用自己的校准、elapsed 和状态，因此不能把本结果改写为原来两个在线 arm 每一请求的 model 或已物化候选必然相同。原 pilot 的服务耗时、输入、协议、输出及结论均未改写，未重跑任何 HIA 工作负载。

14 次中12次选择原生计划，其记录的宿主选中动作与原生动作相同；另外2次双方都弃权，宿主按既有规则回退 direct。两条弃权发生于 stable-n1048559-r1 的 step0、phase_shift-n1048559-r0 的 step0。所有相关 episode 总耗时低于预算，不是超预算导致的回退。

## 独立费用

| 观察 | 时长 |
| --- | ---: |
| 原 campaign 已记录墙钟 | 2.114788649 s |
| 新 post-audit 墙钟 | 1.132828571 s |
| 其中14模型重放与比较 | 0.195985602 s |
| 两个已测工作区间之和 | 3.247617220 s |
| 再分摊一次完整历史桥构建 | 95.694932592 s |

新审计计入读取原始输入、原始帧验证、14模型重放、日志、原生桥启动/关闭以及最终源码/工具/输入检查；解释器/import启动、最后报告序列化和后续证据整理不在此计时内。两个区间之和不是两次运行之间的现实经过时间。不能把原各策略反事实独立部署分摊再全部相加。人工、能源、环境获取及完整依赖闭包仍未闭合，**P1保持未关闭**。

## 原 pilot 身份边界

旧驱动只要求注册时 tracked status干净，并核对选定源码 inventory前后。它没有最终完整 Git状态、HEAD/tree观察；protocol解析与文件hash是分开观察；没有统一 planner/manifest/Python/Clang后检，也没有 registration/frozen-training后检。原精确 ELF仍有封存和hash校验，构建器保留自己的编译器/验证器检查。

这些缺口不能通过事后报告或本次审计回填。新源码为后续统一运行增加：含untracked的完整Git状态；开头、holdout前、审计后、关闭后四次源码和工具绑定；协议原始字节与注册hash对应；实际执行planner及编译器回执必须匹配注册；registration、冻结训练、kernel的前后检查和保留异常历史；输出目录必须在冻结checkout之外。4个针对性回归全部通过。

上述绑定仍是可信主机上的检查点观察，不宣称防御两次检查间修改后恢复，也不宣称完整Python包、loader、libc和主机的传递依赖闭包。统一campaign必须在无人推进HEAD的独立worktree运行。

## 前置提交

`b47` 到 `cd5361b` 的相关运行时差异只有 `hia_ndu_dynamic.py` 的 preparation-aware gate。需要 `d236c807329570fe6e95fedf362b96589e47fb8d` 与协议文字修正 `09dc91a8d506d64aecacea16202e30f6e182bb48`；HIA前端、LLVM、封存器、既有dynamic runner及Rust adapter无其他差异。旧26MB证据不是源码依赖。

## 证据

- `summary.json`：审计状态与分开的费用。
- `audit.json`：14个模型逐项候选/首动作hash、原始输入绑定、源码及工具前后观察。
- `execution-selection-scope.json`：12个非弃权动作与2条宿主回退。
- `matched-beam.jsonl.gz`：全部14次真实原生桥请求/响应及生命周期记录。
- `MANIFEST.json`：证据成员hash与运行任务身份。

审计源码 commit为5a196fa，tree为`6a15d3c3157f3650bf0f3318341c7f5a4d636850`，前后完整status为空。运行 job `1a1aa00bb82-fc05-3b12` 以exit0完成，原始输入与工具hash前后相同。验证范围和统计以 [summary.json](summary.json)、[audit.json](audit.json) 与 [execution-selection-scope.json](execution-selection-scope.json) 为准。
