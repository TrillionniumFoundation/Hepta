# Agent 实验最终结果：原记录与故障续行分别保留

本轮实际覆盖 **32 个主实验计划格**与**8 个独立升级计划格**。主实验通过 5/32，升级通过 0/8。两模型的原科学门槛均未通过，不能据此宣称 HIA 的开发效率或维护成本全面优于 Rust。

完整覆盖包含原登记之后增加的故障续行；它没有把原始未完成状态改写为完成，也没有重试任何已经 attempted 的格。模型真实答案、预算超时、拒绝、错误及所有原始成本全部保留。参考答案仅用于 native controls，不计为 Agent 成功。

最终两家系分别完成 32 项主任务 native controls 与 16 项升级 native controls，合计 96 项参考对照通过；这些对照的执行成本包含在各阶段墙钟中，但没有加入 32/8 的模型成功分母。首次加载失败及开发阶段的额外对照另外保留。

## 主实验：四个任务 × 四种接口 × 两模型

每格一次提交、512 输出 token 上限、180 秒 completion timeout；每个任务沿用 77 个冻结原生测试输入。`full_context` 与 `edit_query` 使用同一语义任务。成功仅表示通过本次有限输入验证。

| 模型 | arm | 成功/计划 | 实际 attempts | timeout | 已知输入 | 已知输出 | 总 tokens |
|---|---|---:|---:|---:|---:|---:|---|
| qwen_coder7b | hia_full_context | 0/4 | 4 | 0 | 3004 | 261 | 3265 |
| qwen_coder7b | hia_edit_query | 2/4 | 4 | 0 | 1446 | 227 | 1673 |
| qwen_coder7b | rust_full_context | 2/4 | 4 | 0 | 1270 | 116 | 1386 |
| qwen_coder7b | rust_edit_query | 1/4 | 4 | 0 | 1109 | 179 | 1288 |
| granite2b | hia_full_context | 0/4 | 4 | 1 | 3238 | 1536 | null；已知下界 4774 |
| granite2b | hia_edit_query | 0/4 | 4 | 0 | 1725 | 555 | 2280 |
| granite2b | rust_full_context | 0/4 | 4 | 0 | 1519 | 248 | 1767 |
| granite2b | rust_edit_query | 0/4 | 4 | 0 | 1285 | 440 | 1725 |

输出未知时，已知输出仅累加收到并验证的 response 计数。总数保持 `null`；已知下界不能用于声称成本更低。输入 token 则从每次真实 transport 中的 token ID 恢复。

### 任务级足迹

| 模型 | 任务 | HIA full | HIA query | Rust full | Rust query |
|---|---|---|---|---|---|
| qwen_coder7b | capacity_roundup | 响应拒绝 | 响应拒绝 | 原生结果错误 | 原生结果错误 |
| qwen_coder7b | tagged_octet | 原生结果错误 | 通过 | 通过 | 原生结果错误 |
| qwen_coder7b | epoch_delta | 溢出陷阱（未成功） | 原生结果错误 | 响应拒绝 | 通过 |
| qwen_coder7b | weighted_minimum | 原生结果错误 | 通过 | 通过 | 原生结果错误 |
| granite2b | capacity_roundup | 预算超时 | 响应拒绝 | 响应拒绝 | 响应拒绝 |
| granite2b | tagged_octet | 响应拒绝 | 响应拒绝 | 响应拒绝 | 响应拒绝 |
| granite2b | epoch_delta | 响应拒绝 | 响应拒绝 | 响应拒绝 | 响应拒绝 |
| granite2b | weighted_minimum | 响应拒绝 | 响应拒绝 | 响应拒绝 | 响应拒绝 |

## 升级实验：单独的 8 格分母

两个任务分别是长度接口扩宽并更新位布局，以及带容量约束的双返回值窗口接口升级；每个候选必须同时替换 provider 与 consumer。每格至多两次提交、每次 1536 输出 token、180 秒 timeout。只允许编译/公开三例反馈；110 或 160 个隐藏输入只在公开验证通过后运行一次。

| 模型 | 任务/语言 | 结果 | attempts | 自动第二次提交 | hidden 验证 | 总 tokens |
|---|---|---|---:|---:|---|---|
| qwen_coder7b | wire_length_v2_hia | 预算超时 | 1 | 0 | 未进入 | null；已知下界 867 |
| qwen_coder7b | wire_length_v2_rust | 响应拒绝 | 2 | 1 | 未进入 | 1173 |
| qwen_coder7b | bounded_window_v2_rust | 响应拒绝 | 2 | 1 | 未进入 | 1311 |
| qwen_coder7b | bounded_window_v2_hia | 预算超时 | 1 | 0 | 未进入 | null；已知下界 706 |
| granite2b | wire_length_v2_rust | 响应拒绝 | 2 | 1 | 未进入 | 1417 |
| granite2b | wire_length_v2_hia | 响应拒绝 | 2 | 1 | 未进入 | 3766 |
| granite2b | bounded_window_v2_hia | 响应拒绝 | 2 | 1 | 未进入 | 2687 |
| granite2b | bounded_window_v2_rust | 响应拒绝 | 2 | 1 | 未进入 | 1695 |

响应封装或字段拒绝不能解读成程序已经被证明语义错误；预算超时也不等于语义错误。所有这些格仍是原计划分母中的未成功格。没有人工修改任何模型答案；人工及工具开发时间未计量，不写成零。

### 失败原因与验证次数

**qwen_coder7b**：主任务 native 候选验证 13 次；升级 native build 0 次、公开 native 验证 0 次、hidden 验证 0 次。

- `E_BATCH_STUDY_ALTERNATIVE`：3 次。
- `E_UPGRADE_RESPONSE_FIELDS`：4 次。
- `timed out`：2 次。

**granite2b**：主任务 native 候选验证 0 次；升级 native build 0 次、公开 native 验证 0 次、hidden 验证 0 次。

- `E_BATCH_STUDY_FIELDS`：2 次。
- `E_BATCH_STUDY_SITE`：9 次。
- `E_HIA_EDIT: invalid JSON: HIA JSON preflight: duplicate decoded object key`：2 次。
- `E_HIA_EDIT: invalid JSON: HIA JSON preflight: expected object field name`：1 次。
- `E_HIA_EDIT: invalid JSON: HIA JSON preflight: unterminated JSON string`：1 次。
- `E_UPGRADE_RESPONSE_FIELDS`：8 次。
- `timed out`：1 次。

## 原协议状态与补充覆盖

| 模型 | 原 primary | 原 upgrade | 主任务续行 | 升级续行 | 主格覆盖 | 升级覆盖 | 原 gate |
|---|---|---|---|---|---:|---:|---|
| qwen_coder7b | completed | incomplete | 无 | 有 | 16/16 | 4/4 | failed |
| granite2b | incomplete | completed | 有 | 无 | 16/16 | 4/4 | failed |

Qwen 的原升级首格 timeout 后，独立工具只补原顺序中未启动的三格；Granite 的原 primary 第四格 timeout 后，另一个独立工具只补剩余十二格。已开始的格一律跳过，绝不以‘没有完整 response’作为重试理由。两个续行工具均有独立源码/计划/身份绑定、单一输出目录与失败控件；它们明确属于登记之后增加的故障处理。

## 实际成本：阶段计时与外层进程计时分别列示

下表单位为秒。原 primary 与 upgrade 的阶段计时包含在原两阶段总进程内，不能把父区间与子区间重复相加。续行 run() 区间从入口到末端身份检查，尚未包含最终 JSON 写入；Bash outer real 另含 Python 启动/import 与最终写入。

| 模型 | 原 primary 阶段 | 原 upgrade 阶段 | 原两阶段 run | 原进程 outer real | primary 续行 run / outer | upgrade 续行 run / outer |
|---|---:|---:|---:|---:|---|---|
| qwen_coder7b | 542.211 | 202.381 | 757.756 | 766.019 | 未执行（不适用） | 416.214 / 416.352 |
| granite2b | 339.722 | 574.507 | 918.428 | 921.595 | 459.672 / 459.815 | 未执行（不适用） |

实际 completion 请求共 **50** 次，收到完整 response **47** 次，包含四次格式 probe。已知输入 **25387** tokens，已验证的已知输出 **6803** tokens；**3** 次输出 usage 不完整，所以整体 output/total tokens 保持 `null`。每次请求、失败原因、token ID 与成本源文件 SHA 均可在配套 JSON 中追溯。

另有首次运行的两次加载 OOM（发生在任何 completion 之前，不能写成模型 0/20）、零 generation 的 no-repack readiness、两模型下载与存储切换、各次归档/成员核验开销。它们在配套 JSON 的 runtime/dependency/archive 记录中独立保留，没有从本轮工程成本中删去。`LLAMA_ARG_REPACK=0` 的变更发生在任何模型答案前，所有实际 server PID 均保留白名单环境证据。

## 结论范围

Qwen 的 HIA query 确有通过隐藏输入的真实维护响应，但四题门槛及 token 非劣条件仍未通过；补充覆盖不能把失败门槛改成通过。本轮只有四个既有两 helper 任务、两个有限双文件接口升级和两个固定量化模型，运行在共享 CPU 环境中。它不是一般工程项目、所有模型或人工维护成本的证明。

原始证据保持字节不变；超过发布接口限制的 archive 只能以可重组、SHA 可核对的无损分片发布，不能重打包后冒充原档。配套 `AGENT_FINAL_RESULTS.json` 保留全部原始报告、transport、源码和归档 manifest 的精确身份。
