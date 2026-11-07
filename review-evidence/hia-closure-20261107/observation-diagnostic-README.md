# 原始 hia_read 观察失败：只读诊断

## 结论

原 job `1a1b5bcfe89-12894-d3` 的保留权威状态是 `succeeded / exit_code=0`，原 stdout 完整、持久、已确认发布。正式 HIA 入口仍返回 `HIA_OBSERVATION_UNAVAILABLE`。这是未闭合的产品观察问题，不能据手工恢复的 report 宣告 HIA 已采纳成功。

**可排除这份 73,616 B 输出触碰固定大小上限。具体失败子阶段仍未证实。** c81 的 `hia_provider::execute` 将 `observe_terminal_output` 的全部 `Err` 合并为一个错误，并丢弃原 cause。当前没有失败调用内部的初末 envelope、SSH 错误或分阶段计时，不能把约 20 秒总耗时直接认定为某个超时。

本次只读取本地既有证据与精确 commit 源码；没有任何远端调用、重试、新 job、evaluate 或生产修改。

## 已核验的原件

| 项目 | 结果 |
|---|---|
| runtime 源码 | `c81a938150d2e533843a42af77739cb888812338` |
| Hepta 源码身份 | `894d2dfce54ff25271b8de2c18c902394484d5cc` |
| host / job | `x230 / 1a1b5bcfe89-12894-d3` |
| launch nonce | `ac50f92801e2dac54c9bd528ce2a8ee1` |
| request SHA | `0e83f089de97b9efb48b44224852cc0b47ce6e927c29ca9c47d09b491fb45b4a` |
| stdout / stderr | `73,616 B / 0 B` |
| stdout SHA | `d011d55eac1cb727ea7182561d89a2b957e64abcd891d3b7f0182dbec5fa27d9` |
| report / response | JSON 完整；worker `complete=true`；领域 `status=completed` |
| content | UTF-8 正好 65,536 B；剩余 8,080 B 是序列化报告及转义开销 |

按 c81 `native_observation_wire::terminal_proof` 规则核验了状态、nonce、exit、timeout/cancel、publication protocol、output complete/durable、每个 stream 的 seen/stored、truncated/errors/synced 和 publication time。保留状态没有 `status_authoritative` 字段；c81 仅拒绝它显式等于 `false`，所以缺省不是本次规则拒绝原因。

5 个保留页都通过 c81 `decode_page` 与 `collect` 的 cursor、size、hex 长度/字符、完整定长页、EOF 和拼接规则，范围为 `0→16384→32768→49152→65536→73616`，stderr 始终为空且 EOF。页拼接与另存完整 output 的原始字节逐字节相等。

原 HTTP wire 3 与 10 的 hia_read arguments 相等；按 c81 的 canonical worker request body 重算 SHA 与原 request SHA 相等。report 的 request/profile/catalog/worker/backend pins 和 artifact 绑定均与保留身份一致。输入、完成 response、unknown response 通过 c81 内嵌 catalog 的 Python JSON Schema 校验。这里是离线复核，并非执行 Rust validator 或补发 live authority。

`diagnostic.json` 记录全部原件与 10 个被审查源码文件的 SHA、每页 SHA、完整计时和边界。它没有复制 73 KiB 内容。

## 源码所限定的失败区间

`src/mcp/hia_provider.rs::execute` 先取得原 operation，然后调用 `native::observe_terminal_output`。只有此调用返回 `Err` 才发出当前错误。若真正进入 `validate_report` 后发生报告/schema/pin 拒绝，代码应返回 `HIA_REPORT_INVALID`；这不是现存响应。

`src/native_observation.rs::observe_terminal_output` 的错误可能来自：第二次原请求查找与 envelope/record 绑定、初始 terminal witness、长度或内存分配、分页 transport/解析/身份/长度、最终请求查找，或最终 terminal proof 与初始 proof 不一致。现存失败响应无法区分这些原因。

尤其需要区分：第一次内部 status 暂时不可用可产生 `Ok(None)`；最终复查 status 暂时不可用会使最终 proof 不等于初始 proof，进入当前通用 Err。已保留的成功 status 和串行页不能证明失败观察中的那两次内部 status 都成功。

## 大小与时间边界

| 边界 | c81 值 | 对本次的含义 |
|---|---:|---|
| HIA worker 总 stdout+stderr | 524,288 B | 73,616 B 明显低于上限 |
| SSH 每 stream capture | 8,388,608 B | 单页序列化输出远小于上限 |
| runtime 原始日志页 | 16,384 B | 正好 5 页可完整读取 |
| collector 窗口 | 4 页 | 本次为两个窗口 |
| direct SSH 同 host 连接 | 2 | collector 的四个 future 可能在 transport 层排队 |
| 可选 pool 同 host session | 2 | live 是否启用未核实 |
| Python read / wait=0 status | 15 s / 10 s | deadline 包含其排队、编码和 transport；不是整个 HIA 调用总预算 |
| system jobctl read | 20 s | 实际分支未从保留 envelope 确认 |

collector 使用 `tokio::join!`，等待窗口内所有 future 后按 offset 顺序处理；任何一个页错误会拒绝完整收集。`observe_terminal_output` 没有自己的聚合 20 秒超时。

两次原 HIA 观察总耗时为 **20.288207833 s**、**19.808248667 s**。两次之间，原 process_wait **1.305245583 s**，5 页串读分别 **1.235314583、1.215053791、1.242305541、1.214732875、1.228939375 s**。这些说明原数据当时可通过串行原生观察取得；尚不能证明并发 collector、SSH 容量、registry 查找或 final proof 哪一个失败。没有充分证据直接增加 timeout、调大上限或降低并发。

## 最小修复建议与可复现接受条件

1. 在保留原 HIA `unknown` 与 `observe_original` 行为的同时，保留 typed failure substage。为 request lookup、binding、initial publication、page transport/decode、final lookup/publication 添加静态阶段标签。外层不能再用完全丢弃 cause 的 `Err(_)`。
2. 失败也记录 monotonic 分段耗时、页 window/offset/limit、已观察字节数，以及原 host/job/request SHA 与已有 nonce。当前 `NativeOutputObservationTiming` 只在最终成功时构造，失败成本无法归因。对外可只显示固定 stage/code；详细诊断进入既有受限审计/证据渠道，避免将 remote stdout 或 request stdin 原样拼进公共错误。
3. 离线注入 reader 回归：以此次 `73,616+0 B`、5 页、2 窗口为 fixture，覆盖成功、单页 timeout、malformed cursor/hex、final lookup failure、final proof mutation。断言每个失败均保留原身份、具体阶段与成本，并且没有调用 start/launch；保留现有完整性与最终复查拒绝规则。
4. 修复候选通过 runtime 的正式 build/test 门禁后，只对这一原 hia_read request 做观察重放，比较原 terminal identity 与字节 SHA，确认从相同原 job 得到领域完成结果。这个未来接受动作仍需实际执行；本次没有执行。

不应因手动拼出了 report 就绕过 HIA 授权边界、重开 evaluate、换 key、移除 final publication 检查，或把 P1 记为完成。
