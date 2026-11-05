# Safe Core 证明研究交付：v7–v12

## 交付包的实测恢复

本包已保存 81 个明确证据根中的 **1,076 个原始文件，共 180,913,620 字节**。43,044,898 字节的 gzip 包分为 55 片；归档外层退出 0，墙钟为 12.290305314 秒，其中已经包含独立恢复的时间。

另一次公开包搬移控制将 55 片及四份恢复文件原字节复制到全新目录。独立进程先确认原 evidence 绝对路径的两次文件打开被拒绝，再仅使用新目录恢复全部 1,076 个文件；实际恢复器没有尝试读取旧 evidence 路径，控制外层退出 0、墙钟为 3.439235259 秒。这使用 Python 文件打开审计控制，不声称操作系统沙箱隔离。具体回执为 `PUBLIC_PORTABILITY_RESULT.json` 和 `PUBLIC_PORTABILITY_GUARDED_RESULT.json`。

归档 SHA256 为 `7e6158c32a31f86fd5ed86fcb0250f1e26c7c03f7de968c9350252139891e3fa`。这些成功结果只说明交付字节与搬移恢复经过实测；下面的原证明失败结论保持不变。

## 结论与最终源码

最终源码固定在 `5ee6d8fec0e5c72d87a36dbed60789de211abf1b`，完整 Git tree 为 `d47a711461dc66d4606bdc9659203889e205d6c7`。本轮实现了真实的证明生成、验证算法和消费者证明修复；桌面上的完整证明验收仍未关闭。

v12 的 11 个全新 Lean 阶段均在原来的单进程预算内通过，但完整资格命令在 **600 秒外限退出 124**。随后单独运行的证据重放退出 0，验证了保留的源码、产物、清单与回执；它没有重新运行 Lean，也不改变原资格命令的失败结论。12 项生产精化义务全部仍是 `unproved`，权限仍为 `DENY_ALL`。

同源码树在 GitHub CI 环境中的成功观察由独立 CI 证据包提供。该环境的结果与本地的 600 秒失败分别保留，不能互相替代。行为组合、AOT、NDU 和 Agent 实验也有各自的测量边界，本包不授予那些轨道证明资格。

## 实际实现与证明范围

本轮依次处理了证书复用和打印调度、消费者对原 `Raw` 相等判定的归约失败、`ChangedByte` 拒绝证明的大公共前缀、`WrongArm` 原命题的证明、真实源码读取闭包，以及 Python 构造和验证中的重复字符串扫描。最后两版主要改动如下。

- **v11** 为原有任意位置的 `def ` / `theorem ` 字面量查找建立候选位置索引，再做完整字面量匹配；规范且不重叠的证明段一次拼接，特殊交叠情况保留原算法行为。原先接受和拒绝的边界继续受差分控制约束。
- **v12** 仅对精确内建字符串、整串匹配的无空白 ASCII 十进制列表使用快速解析，返回新的列表；其余输入完整回到原解析器。`Raw` 字符串分支先验证精确内建类型，再做字节转换和允许字符筛查。子类仍保留旧属性读取顺序与错误行为，没有缓存可变 AST 或接受结果。

所有实际候选仍经过原有源码逆向、旧验证器、实际字节重哈希和依赖绑定。两个旧的 reference / actual-recovered 验证门都保留，并有分别注入故障的控制。最终绑定 258 项仓库源码输入、780 项 Lean 支持输入及固定 Lean 二进制。11 个注册阶段、每进程 60 秒、启动窗口 540 秒和完整命令 600 秒均未放宽。

生成材料保留 **7,685 个定义、4,215 个 transport 定理和 2,975 项辅助事实**，没有删减原 subject 的多重出现。最终 11 个阶段的 subject 数依次为：

`102, 256, 444, 735, 1057, 807, 1297, 1297, 1297, 75, 1`

这些研究材料包含抽象模型定理、针对已选程序的源码/序列化/抽取连接检查及拒绝证书。它们没有证明完整语言、所有真实编译器路径、任意 C/C++ 输入、并发资源安全或任意机器码语义。源码控制和有限输入对照也不能替代这些尚缺的定理。没有因为某个阶段通过而放宽后续门槛，没有新增 unchecked axiom 或 `native_decide` 信任。

## 历次完整验收的真实终态

| 版本 | 测量源码 | 完整命令的结果 |
|---|---|---|
| v7 | `3f0ef24a89bdce70dfa5f5a5ac5d62d5faa6b0cd` | Part02 触及单进程时限；后续阶段未执行。 |
| v8 | `0ab0c441d9d115f9288f18707a117506369b93ff` | 前九阶段通过；消费者出现真实 elaboration 错误和错误恢复 `sorryAx`，随后超时；最终 WrongArm 未执行。 |
| v9 | `2d964d27b068b3eb0b19e72ea4132eefd12d4360` | 前十阶段通过；WrongArm `process_failed`。未进入完整最终重建与重放。 |
| v10 | `b47ce924c5941b42448e9da0b07a2bcedaf75d1f` | 11 个新 Lean 阶段通过，完整命令外层 600 秒超时；之后另次重放通过。 |
| v11 | `0c8a91003aee2732308bb654d0e1f941ae561728` | 11 个新 Lean 阶段通过，完整命令外层 600 秒超时；之后另次重放通过。 |
| v12 | `5ee6d8fec0e5c72d87a36dbed60789de211abf1b` | 11 个新 Lean 阶段通过，完整命令外层 600 秒超时；之后另次重放通过。 |

各版阶段结果只归属各自的完整运行，不跨版本拼接成一次成功。未执行的阶段没有被计作通过。同一冻结源码没有为了获得更好时间而反复重跑资格命令。

## v10–v12 时间分解

下表只用既有原始回执计算，单位为秒。`capture` 是进程捕获器记录的经过时间，包含调度等实际影响，**不是纯 Lean CPU 时间**。

| 既有回执可以支持的区间 | v10 | v11 | v12 |
|---|---:|---:|---:|
| qualifier 起点至第一个 started 检查点 | 75.776569598 | 63.738214092 | 59.736175151 |
| 11 个 capture elapsed 合计 | 297.798510028 | 312.228743474 | 317.554485787 |
| 11 个 cleanup 合计 | 0.293489502 | 0.246403855 | 0.351822316 |
| 十个相邻 started 区间扣除前一 capture/cleanup 的混合开销 | 109.192339928 | 112.051490141 | 109.800511053 |
| 最后 started 至内层 RESULT、扣除末 capture/cleanup 的混合尾部 | 75.809270877 | 65.128716041 | 63.118076555 |
| 内层 RESULT 的 wall | 558.870179933 | 553.393567603 | 550.561070862 |
| 完整资格命令的外层 wall，三次均退出 124 | 600.079463180 | 600.047503236 | 600.049994673 |
| 之后独立证据重放的 wall，三次均退出 0 | 73.055962129 | 55.874570337 | 61.189014082 |

`started` 检查点位于第一次 state 检查之后、第二次 state 检查与实际 spawn 之前。因此表中的间隔混合了身份检查、文件读写、清单核验和阶段重放等成本，不能把它们全部称作 identity 耗时。最后一个混合尾部还包含最后阶段的管理工作与提交前重建。外层与内层的计时起点不同，其差也不是内置重放的精确时长。

v12 对比 v11，capture 增加 **5.325742313 秒**、cleanup 增加 **0.105418461 秒**，其余内层时间减少 **8.263657515 秒**，因此内层总时间只减少 **2.832496741 秒**。这些数字给出准确的账目分解，没有证明各变化的单一原因。

v12 的另一次固定 old→new 成本对照只测了 `prepare` 加一次 `reconstruct`，两者之和为 **133.057458747 → 109.174032726 秒**。这是一组预定顺序、每臂一次的诊断。完整成功路径还需要内置证据重放中的第二次 `reconstruct`，以及完整运行中的重复外部身份检查和证据读取。已有纯 Python profiler 不覆盖整个资格命令；不能把上述诊断节省量直接当作完整命令的保证。

静态控制流表明，生成内层 RESULT 前有 48 次 `External.check`；完整成功路径后续还要执行三次。本地超时发生时，后面三次究竟完成了多少，没有独立时间回执可精确判断。没有据此补造每次重哈希或内置重放的耗时。

精确纳秒值、66 份阶段回执的 SHA256、完整/内层/独立重放回执引用与计算说明位于归档内：

- `evidence/proof-timing-decomposition-v10-v12-r1.json` — SHA256 `74af39a16afe16d14d437d955a93dbc0eb5cb2073b7f8d353eb8399e97811476`
- `evidence/proof-timing-decomposition-v10-v12-r1.raw.json` — SHA256 `0c6d1d0a0c59d20cfa343de391a54f3c4a1327e01cb629477edfd29dee4cc14a`

## 控制、失败与更正如何保留

v12 第一遍完整 49 项控制实际得到 **48 项通过、1 项诊断快照序列化错误**。错误发生于给含非 ASCII 字符的元数据制作快照；失败源码、原始日志和恢复说明都保留。随后只修正该测试快照的 JSON 序列化，完整 49 项控制通过；固定 ID 清单及其承诺不变。它包含原有 46 项控制和五份真实输入的旧/新完整验证器对照，各输入实际命中 502 条快速解析 RHS。

较早的冻结包装器失败、WrongArm 负控包装器错误和更正说明，以及三次只留下空输出目录的诊断，都保留原件。后三次另从原 Runtime 找回完整 request、stdout、stderr、exit，共 12 个文件；没有重新执行这些诊断来代替旧失败。

CI 历史闭包修复保留了精确恢复来源、45 个历史文件的字节绑定、207 项普通测试、705 项隔离测试及 74 组精确 ID 清单的对照及实际 207+16 项本地控制。该本地控制驱动没有执行其余 73 个隔离组。后续 GitHub CI 的全量观察由单独的 CI 交付包记录。

## 尚未关闭的 12 项生产义务

| 义务 ID | 当前状态 |
|---|---|
| `environment_phi` | `unproved` |
| `dynamic_owner` | `unproved` |
| `allocation_extent` | `unproved` |
| `finite_integer` | `unproved` |
| `direct_body_seed` | `unproved` |
| `store_write_frame` | `unproved` |
| `value_schedule` | `unproved` |
| `normal_completion` | `unproved` |
| `empty_extent` | `unproved` |
| `trace_edge_cut` | `unproved` |
| `post_completion_frame` | `unproved` |
| `observational_boundary` | `unproved` |

`actual_core_bridge_proved`、`all_edge_transfer_proved`、`body_prefix_refinement_proved` 和 `python_exporter_refinement_proved` 也仍为 false。本研究链没有授予 production/native admission、初始化省略、配额等价或性能资格。

## 最终 v12 的直接证据定位

以下均是归档内的原始文件，JSON 数字不会经过 JavaScript 重新序列化。

| 文件 | SHA256 |
|---|---|
| `evidence/proof-candidate-integrated-v12-r1/SOURCE.json` | `6074c21f913f8253bfdcadb2d079df720e5170753402aa8abfc55fe1e1e0d0ea` |
| `evidence/proof-acceptance-integrated-v12-r1/RESULT.json` | `496981fa6a5bc1b2d0c8259bcfb325f3035f35839bc825d29f64a7ea2e3b868f` |
| `evidence/proof-integrated-v12-r1/RESULT.json` | `7bd76924b97877929b3264c91b7c0d7cb5c33b9a465327c7662f4dcbc9d28341` |
| `evidence/proof-independent-replay-integrated-v12-r1/RESULT.json` | `4b7e34acafb06193b9af3ea89c9225a88371460a0eda8e2d16d1ed4e54b8290c` |
| `evidence/proof-candidate-integrated-v12-r1/TERMINAL_OBSERVATION.json` | `c7b5de3e0e1a5e5f91c6bbba8f865926a1df353a3c4a1266e7ebc7aef4ec4f24` |

## 归档范围与恢复

`PLAN.json` 列明输入根和已知哈希锚，`INVENTORY.json` 列明全部实际文件与 SHA256，`PARTS.json` 绑定顺序分片和整个压缩包。显式根内保留全部原始普通文件及空目录，包括历版和最终版 `.olean`、生成的 Lean 源码、失败日志、控制回执、剖析数据、源码补丁及 bundle。原始纳秒整数保持原文件字节；新派生说明用十进制字符串保存纳秒。

在保存这些元数据、`RESTORE.py` 和全部分片的同一目录执行：

```sh
python3 -B RESTORE.py restore PARTS.json restored-proof-evidence
```

恢复程序在全新目录重组分片、校验压缩包、实际解包并逐文件回读核对哈希。它不执行归档中的代码、不启动 Lean、不改变证明资格。归档操作自己的成功回执只说明交付字节恢复成功。

工具链安装、仓库对象库和其他轨道的实验不重复装入这个包。Lean 4.19.0 及其支持文件由保留的身份/锁定记录绑定；源码 bundle 可能需要各自注明的公开或此前交付的 Git 先决提交。因此本包提供完整的明确范围内原件与字节恢复，不声称在任意新机器上无需外部依赖即可重新完成证明。
