## 当前结论：整套全 HIA 原生交付尚未闭合

继续执行“全量审计 → 使用 HIA 重写完整生产职责 → 同源冷构建与完整原门禁 → 默认/安装/连续性验证 → 删除旧生产整套”。**whole-native=false；默认未切换，旧生产整套未删除。**

产品分支仍为 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`，本 PR 保持 draft。本轮源码在独立可复核候选中开发，不能将组件开发通过等同于本 PR HEAD 已包含并通过整套改动。

最新[审计提交 1040e87](https://github.com/TrillionniumFoundation/Hepta/commit/1040e87e97d7166524ae5670f609acbf1ff661a2) 保存 119 个新文件，所有先前 23 个审计子树与产品源保持不变。入口为 [README](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/README.md) 和 [逐文件索引](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/INDEX.json)。此前 PR 正文逐字保存在 [previous-PR889-6768.md](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/handoffs/previous-PR889-6768.md)。

## 全量审计的真实范围

完整 Git 基线为 3153 文件；197 个生产 Python 模块、378 个工具模块和 setup.py，共 576 条源码路径、20 个业务家族。所有路径的 Git 元数据与固定审计匹配；重点当前源有逐字复读，其余分类有固定完整审计来源，未冒称本轮重新逐行证明全部模块。[完整审计](https://github.com/TrillionniumFoundation/Hepta/tree/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/FULL-REMAINING-AUDIT.md) / [结构化清单](https://github.com/TrillionniumFoundation/Hepta/tree/1e47764e0d5d0577330029ea4029a6a83dcac2b1/review-evidence/hia-native-rewrite-v78-source-owner-custody-20261112-dda7/FULL-REMAINING-AUDIT.json)

已有 HIA primitive Core、VM、静态预算、堆/nominal 等能力不因仍保留独立参考实现就被重复算作未迁移。HIA 策略控制与固定 CPython 支撑是两个不同完成条件；现存宿主支撑仍是实际生产依赖。

## 已实际通过的独立组件范围

| 范围 | 实际结果 | 资格边界 |
|---|---|---|
| Core/Plan 结束处理 R5 | [43262435705](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43262435705)：原 60、124（23＋51＋50）、44 全通过，外部真实帧控件另 5 项 | Core 原独立 3184 文件；保全部编译/组限额 |
| Byte R5 | 同 run 的独立 Byte job：原 25、整体发射 4、原调用者 29 全通过，外部真实帧控件另 5 项 | 3179 文件、原 CoreR3 依赖范围；不能转移给新 Core/Proof 联合 |
| Proof 新恢复 R2 | [43265223561](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43265223561)：85 组件＋原 40 调用者全部通过；16 模式、284593 次机器返回、原 8 策略入口 0 | 3201 文件；格式检查通过、源码/输入守恒；未继承丢失的本地 64 项资格 |
| NativeBuild | [43253621060](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43253621060)：25＋原 114 全通过；3812409 次实际帧命令、旧 writer 0 | 3203 文件独立开发源；不是当前联合冷构建资格 |
| Emitter R4 | [43231246218](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43231246218)：完整 116 全通过 | 原 15＋51＋50；旧 R1 两个生命周期失败原件保留 |
| Verification R6 | [43250927176](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43250927176)：12＋2＋43＋48 全通过 | 3186 文件独立范围；含 default replay 修复 |
| Emission R6 | [43220160251](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43220160251)：52＋12＋16＋16＋48 全通过 | 完整原调用者、生命周期与实际 CPython 3.14 范围 |
| CLI3 / CallArena | CLI [43210729090](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43210729090) 原 39；CallArena 原 22＋新增 4 实际通过 | 微基准和局部通过不能消除原预算失败或替代联合资格 |

各组有重叠，不相加为整套独立分母。未匹配当前源码的保留编译器均明确标记 DEVELOPMENT。完整历史组件原件在 [v78 组件审计](https://github.com/TrillionniumFoundation/Hepta/tree/e7ecd135b5f97204292de2b61e6875ffadba1c58/review-evidence/hia-native-rewrite-v78-component-custody-20261112-dda7)，本轮新增在 [shared-finish](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/shared-finish)、[proof](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/proof)。

R5 修复的具体问题是：调用者处于外层异常处理器时，原 finish 使用环境异常状态，导致成功的显式持有帧未立即退役。新实现使用本次调用的 completed 标志，保真实异常、take 中断、未确认提交及不重放行为，没有额外返回值别名改变析构时点。未把继承关系当成 Emitter/Verification 在新联合源上的完整执行证明。

## 联合源码：原失败保留，后继正在执行

- 先前 3181 文件的源码候选 [43240090419](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43240090419) 已实际完成 82 生成器、原 764 个有序测试与格式检查；这是它自己的旧范围。
- 联合 R1 [43263350672](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43263350672) 在原 Core-only 文档路径检查处失败，尚未运行生成器或测试。窄修仅改变 .py.txt 文本 fixture 的文档表达，共 +28 B。
- 联合 R2 [43264682454](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43264682454) 的 88 个生成器通过；826 loaded/start/terminal 次序全部一致，825 success、1 failure，0 error/skip/xfail/xpass。原 764 次序和新增 62 次序都保留，原组 981.766/1800 秒。实际生成源为 3239 文件、115 差异路径，tree `aa32ea9110b9b50e5840392324b7ffbcf86d0f45`。**整轮仍 FAIL。**
- 已冻结的 Proof 联合后继 [43271704649](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43271704649)，head `a652ab05a4bd19d8239e691624c2dcb10f4db73c`，最后核对仍在 source generation。作者源 3255 文件/129 路径，89 生成器、171 selectors、860 测试（保原 764 次序＋96）。尚无后继源码、当前冷构建或整套机器 PASS。

R2 唯一失败来自未修改的原 checker 库存断言。CallArena 给 Core 原语引入 hia_machine_transport，原清单尚把它放在 MECHANISM。完整模块只有物理分配和 CPython 方法名称元数据，没有项目相对导入、selector 或 Code 业务策略。后继按实际闭包将该现有模块移入 CORE，合入 Proof 后为 **Core47＋MECH19**；全散列并集不减、每次当前字节读取不变、原断言不改。[决策原件](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/CORE-TRANSPORT-CLOSURE-DECISION.json)

后继还补入 NativeBuild 必需但冷源清单遗漏的原 test_hia_machine_lowering_edges.py，并检查全部九类 builder 的 required/owned source 闭包，保留原 114 方法和限额。源码门禁通过后，将把实际生成的完整源码写入独立真实 Git 提交并全回读，再从同一提交执行冷构建与原 native/full 门禁。[失败与后继原件](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/joint-source)

## Proof 恢复、执行环境与后续新源码

执行环境断开后本机执行不可用；Git 和真实 Actions 仍可使用。此前本地 Proof 的完整 3202 源码包/64 项原始结果未完整上传，计算出的未获 ACK 对象不当作已存在。新 R2 资格重新建立：R1 的 85＋40 已通过但四个 EOF 空白导致整轮失败；R2 只各去掉一个末尾 LF，AST（含位置）与全部原测试/限额相同，随后整轮通过。HIA、2511 指令控制表和实际镜像都与旧目标逐字一致，不恢复或继承丢失的 64 项结果。

服务 Evaluation/Adoption/Lease 首版已保存 22 源文件，拥有七个完整方法及 _value_observation、_connection_arguments。首次真实 [43273754998](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43273754998) 在任何生成器启动前被 harness 的名字解析式拒绝：式子漏接收 sha256 中的数字。完整 88 项原生成器清单正在精确适配；Source/Native/原 48、35、48 三组均 **NOT_EXECUTED**，不能标成业务失败或通过。原 report、日志及作者源保持原样。另发现需要验证 helper 在 image admission 前被替换/删除的时序，正建立原行为反例与固定初始 facade 锚点修复。

公共前端已冻结 exact4b 的 28 份源和官方 CPython 四文件，正在独立作者 11 个 assembly 函数、_reject 支持与 verify_program 路由。namespace 分开，避免两个模块的 _reject 混用。现有 bounded frontend 与四镜像 normalization 未覆盖完整公开域；JSON provider、实际活跃 C/Python 栈、正则引擎等仍显式未闭合。[源码冻结与分析](https://github.com/TrillionniumFoundation/Hepta/tree/1040e87e97d7166524ae5670f609acbf1ff661a2/review-evidence/hia-native-rewrite-v79-proof-finish-union-20261112-dda7/p1-inputs)

## 原始阻塞与最终晋级条件

原产品 [43197399906](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43197399906) 的 source 663 执行含 1 个缺 jsonschema error；原 native 的 namespace35/ledger48 各有三项失败：expired evaluation、reference loop budget、native timeout 超原 5 秒。原 nominal377 的 2258.701 秒对外部 1800 秒组限额仍是具体风险。后续两例只证明未启动 native 时可被预算拒绝，不能证明实际 timeout/reap 修复。原六个失败与未到达的后续断言/组均保留。

删除旧生产整套前仍需全部完成：

1. 当前联合源码真实 Git、全部生成/源码覆盖/库存和原有测试完整通过；各公开策略与传递依赖完成 HIA 迁移，保原输入域、错误次序、alias、生命周期、部分效果与 unknown。
2. 同一源码的 B0/B1/B2/B3、M1/M2/M3、两个固定点与所有 family 冷构建；180＋3 清理、外层 240 秒保持。每个 owner 绑定该源码、真实 image/manifest/checker/captured/held/resources，兼顾安装目录。
3. 原组件、原调用者、wheel/worker/隔离，编译 20 秒与普通组 1800 秒保持；原 27 retained 组加完整未过滤 discovery，5400 秒保持。旧 v10r2 的 121 文件已恢复，但其 5f7/旧库存/未执行 HOLD 不继承成新资格。
4. 实际消除原六个预算失败与 nominal 风险；完成余下 worker/public action、进程监督/对象/映射/工具身份、独立 SafeCore/scalar/translation/search、编辑/增量/其他后端、长期状态机和宿主运行时依赖。
5. 实际默认选择无旧策略回退，验证真实 DB/slots/leases/重启恢复及回滚连续性；之后删除旧生产实现，最后清洁安装全量复验。独立 oracle、审计历史和原失败原件不能冒充或掩盖生产依赖。

## 原件保管的准确边界

本轮只读产物核对没有重跑业务或改原结论：

- Core R5 原 ZIP 60640033 B/3485 outer 成员，Byte R5 22748189 B/1224 outer 成员，全部 SHA/CRC 通过；原 manifest 3465/1204 项及 155/92 文本成员全部匹配。[43269767079](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43269767079)
- NativeBuild 原 ZIP 22483410 B/1168 outer 成员全部 SHA/CRC 通过，先前完整 32 个文本均匹配。[43260801976](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43260801976)
- Proof R2 原 ZIP 91672293 B/1348 成员全部 CRC，source tar 的 3201 个文件字节/Git/POSIX mode 全部核对。[43267019251](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43267019251)
- 联合 R2 原 ZIP 92730326 B/592 outer，加内 EVIDENCE.zip 584 项全部 CRC；原 REPORT/SOURCE-PACKET/826 stderr 均与完整日志恢复字节一致。[43272281464](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43272281464)

Git 已保存本轮源码包、完整已选文本、原日志、逐项身份与全 ZIP 核对记录。未明确保存整包二进制字节的 ZIP 仍以 Actions artifact 为完整二进制存储边界；没有把文本子集改称完整 ZIP 永久归档。原直接 binary→UTF8 fetch 失败和此前缺失的单次读取响应保持如实标注。
