# HIA 原生重写 v79：Proof 恢复、结束处理与联合源码审计

## 当前结论

整套原生闭合仍为 **false**。产品分支仍是 `4b19af89a766593f7d5f1cc2db256e81aba7afcb`，PR 889 保持 draft。本次审计提交保存新的源码、原始通过与失败记录及独立复核结果；它不修改产品分支，不激活默认选择，也不删除旧生产实现。

完整范围审计沿用前一审计提交 `1e47764e0d5d0577330029ea4029a6a83dcac2b1`：真实 Git 基线 3153 文件，197 个生产 Python 模块、378 个工具模块与 setup.py，共 576 条源码路径，20 个业务家族。详细剩余范围在前一叶的 FULL-REMAINING-AUDIT.md/json。已有 HIA 原语、Core、VM、静态预算与堆/nominal 能力不因仍有参考实现就被重复计算为未迁移；固定 CPython 支撑仍是实际生产依赖。

## 新增实际执行结果

| 范围 | 真实执行 | 结果与限制 |
|---|---|---|
| Core/Plan 结束处理 R5 | run 43262435705，job 131336994971 | 原 60、124（23＋51＋50）、44 三组全部通过，另有 5 个外部实际帧控件；独立 3184 文件，tree 1fe9c231a9c394264a5231a81e8648279ed18688 |
| Byte 结束处理 R5 | 同 run，job 131336994282 | 原 25、整体发射 4、原调用者 29 全部通过，另有 5 个外部实际帧控件；独立 CoreR3 依赖范围 3179 文件，tree 291a2cc8351257c56d6ca75ccd282242ef0985fe |
| 新恢复的 Proof R2 | run 43265223561，job 131346866857 | 85 组件与原 40 调用者全部通过；284593 次真实 HIA 机器返回，16 模式，原 8 策略入口 0；3201 文件完整守恒 |
| 联合源码 R1 | run 43263350672 | 文档路径被原 Core-only 检查拒绝，在生成器和测试前失败；原 569 字节错误保留 |
| 联合源码 R2 | run 43264682454 | 88 生成器通过；826 loaded/start/terminal 次序完全相等，825 success、1 failure；原 764 次序与新增 62 次序均保留，整体仍 FAIL |
| Proof 联合后继 | run 43271704649，head a652ab05a4bd19d8239e691624c2dcb10f4db73c | 发布时 source generation 正在运行；冻结作者源 3255 文件、129 路径，89 生成器、171 selectors、860 原定测试。尚未取得本候选源码或当前冷构建资格 |

这些组有重叠，不能相加作为整套独立测试分母。各组件采用明确记录的开发编译器；它们的通过不转移成新联合源码、当前源码冷构建或最终默认交付的资格。

## 结束处理修复

Core、Plan 与 Byte 的原 finish 用调用者可见的异常状态决定成功帧是否释放。当调用者位于外层异常处理器中时，成功的显式帧也会被错误保留。R5 在每次调用内部记录 completed，成功返回时立即退役；失败的 take、真实异常和已产生实际提交但确认丢失的情况继续保留错误及不确定状态，不重放。

原行为和修复后行为都保留。没有增加一个额外的返回值局部引用来改变析构顺序。Emitter 与 Verification 的继承关系经过源码复核，但本次 Core/Byte 执行不能代替它们在新联合源码上的完整调用资格。

## Proof 恢复与原失败

旧执行环境断开前的完整本地 Proof 候选和 64 项原始结果没有完整上传，不能恢复成已存在的 Git 对象。本轮以已保存的精确源码重新作者并执行新的候选。新的 85＋40 资格独立建立，未继承丢失的 64 项结果。

R1 的 85＋40 已通过，但原 git whitespace 检查因四个文件多一个末尾 LF 返回 2，整轮 FAIL 保留。R2 只修这四个 LF，原 AST（含位置）、原测试定义和限额不变，之后整轮通过。

生成的 HIA 为 346808 B，SHA256 `20415328e0b1b86069be3da960efd17416d97cbc3812ee422af97da9b266e72c`；控制表 75768 B/2511 指令，SHA256 `437dde3b20de2925c162fecb47eb03e6e61898a117c4ac2a886f9673e324e86a`；机器镜像 283246 B，SHA256 `3b2f96169a6f657b3ef96e95bba8d899eb544ddabf7a1ccf47ebb5f189a58c89`。这些字节与旧目标逐字一致。原生镜像的直接 UTF8 fetch 失败原文保留；完整镜像从 base64 包装和真实 ZIP 核对，不声称直接二进制 UTF8 回读成功。

## 联合源码的真实缺口及后继修复

R1 只修改文档中 .py.txt 文本 fixture 的路径表达，共增加 28 B；没有改 checker 断言。R2 真实生成后是 3239 文件、115 个差异路径，tree `aa32ea9110b9b50e5840392324b7ffbcf86d0f45`，root 根据全量元数据重算 Git tree 并逐项核对差异源码。

R2 唯一失败来自未修改的原 `CheckerDependencyIdentityTests.test_reviewed_inventory_covers_verifier_imports_and_explicit_selectors`。CallArena 为 Core 原语新增了对 hia_machine_transport 的真实导入，而该模块仍登记在机制清单。完整复核确认它只有物理分配、分配失败/生命周期支撑和 CPython 方法名称元数据，没有相对项目导入、selector 或 Code 业务策略。后继按真实依赖把这个现有模块从 MECHANISM 移到 CORE；不复制分配器，不隐藏导入，不改原断言。合入 Proof 三个机制文件后是 **Core 47＋机制 19**，全散列并集不减少，每次调用仍按原顺序读取当前字节。

另一个实审缺口是 NativeBuild 必需的原 test_hia_machine_lowering_edges.py 没有进入冷构建 SOURCE_FILES。后继补原路径，并对全部九类 builder 的 required/owned source 库存建立完整闭包控件，保留原 114 调用者全文与限额。先前失败没有被重标成功。

## 原始产物复核与存储边界

- Core R5 原 ZIP 60640033 B、3485 outer 成员全部 SHA/CRC 通过；原 manifest 的 3465 文件及完整 155 个文本成员均匹配。
- Byte R5 原 ZIP 22748189 B、1224 outer 成员全部 SHA/CRC 通过；原 manifest 的 1204 文件及完整 92 个文本成员均匹配。
- 上述只读复核 run 43269767079 使用两个独立 job；0 项目/业务测试重跑。26 个文本传输块已从 Git 完整重建并核对。
- 原 NativeBuild 实际 25＋114 的 ZIP 22483410 B、1168 outer 成员全部 SHA/CRC 通过；之前完整保存的 32 个文本文件均与原 ZIP 对应。只读复核 run 43260801976。
- Proof R2 原 ZIP 91672293 B、1348 成员全部 SHA/CRC 通过，源 tar 内 3201 个源码文件的字节、Git blob 和 POSIX mode 全部核对；独立复核 run 43267019251。
- 联合 R2 原 ZIP 92730326 B、592 outer 成员与内层 EVIDENCE.zip 的 584 成员全部 CRC 通过；REPORT、SOURCE-PACKET 和原 826 项 stderr 与已保存日志中恢复的字节完全一致。只读复核 run 43272281464；原 826/1 FAIL 不变。

完整 ZIP 保留在原 Actions artifact 及相应只读副本。本叶的 Git 文件包括完整已选文本、源码包、原日志、逐项身份与全 ZIP 复核记录；除明确保存的镜像包装外，不冒称已经把所有二进制 ZIP 字节永久存进本叶。

## 正在执行的后续源码工作

Evaluation/Adoption/Lease 已保存独立作者版本：七个完整服务方法，加 _value_observation 与 _connection_arguments；第二版 22 源码路径已逐字核对。它覆盖预算剩余时间、reference/native 次序、成本账本与测量发布、采纳校验及 lease 调用，新增 float literal 扩展局限于这个 owner。该作者快照尚无真实生成或测试结果，原 48/35/48 组将分别执行。

公共前端已保存 exact4b 的 28 份源码、原见证与官方 CPython 四文件。下一独立 owner 是 11 个 assembly 公开策略函数、必要的 _reject 和 verify_program 路由。既有 bounded JSON frontend 与四镜像 normalization 不等于这层完整入口；公共 JSON provider、真实 C/Python 活跃栈、正则引擎和独立错误构造等依赖仍明确未闭合。源码冻结与只读分析不构成新原生资格。

旧 v10r2 retained harness 的 121 文件已完整恢复并逐项核对。旧输入钉 5f7 和旧库存，因此下一执行需要明确的新 source commit pin、追加的测试库存及新增 owner 组；原 27 组、未过滤 full discovery 5400 秒、普通组 1800 秒、编译子进程 20 秒、cold 180＋3/外层 240 秒均保留。旧 v10 未执行与已记录 HOLD 不会转移成通过。

## 最终删除前仍必须完成

同一实际源码提交上的当前冷构建、各 owner 原组件与调用者、installed/wheel/worker 隔离、全部 retained/full 组、原六个预算失败以及 nominal 时限风险都仍需实测。余下生产策略、进程与长期状态机、独立证明/搜索引擎、其他公开后端与宿主运行时依赖也仍需重写和验证。默认选择、真实数据库/slot/lease/重启恢复连续性完成之后，才能删除旧生产整套，再做清洁安装复验。

本叶只追加审计证据，所有先前审计子树保持逐项相同。
