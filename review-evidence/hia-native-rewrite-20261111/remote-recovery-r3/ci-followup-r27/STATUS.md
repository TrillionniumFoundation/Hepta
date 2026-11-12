# HIA 全量重写：第 27 轮提交与实际状态

整套状态仍为 **OPEN / HOLD**。原始全量 ROG 的 4,157 项测试中有 187 个错误、1 个失败、18 个跳过；这份提交没有把局部通过改称为整套闭合，也没有删除生产旧实现。语义对照固定在 `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`，本轮回读的 main 为 `5831f52fada45e076f8f68f198a15c0585e6104f`。

## 已实际执行的结果

| 部分 | 实际结果 | 权限与范围 |
| --- | --- | --- |
| 第 26 轮提交源码语法门 | 120/120 AST 通过 | 只证明清单内 Python 作者工具语法，HIA 生成、B3 和 native 数均为零 |
| 第 25 轮默认 Core native | 冷自举 11/11，语言覆盖 1,242/1,242，通过 | 该次提交的实际独立运行；原始完整日志保留 |
| 第 26 轮默认 Core native | 冷自举 6/11，失败 | 原始日志保留；本轮不借用此前原因，等待其 owner 原件回读 |
| 第 22、24 轮冷自举原件回读 | 两次均为原 180 秒期限耗尽；34/38 阶段完成 | 已完整核对原始文件、580 份导出源码及 34 个阶段归档；均确认进程树清理完成 |
| Worker 默认 DataJSON 固定原生入口 | 142 cases，114 个实际 ELF 进程；另有 28 private cases / 81 controller entries | 固定入口范围，尚非普通 Worker 全路径 |
| Worker 初始化顺序 | 142 cases / 4,130 native entries 通过 | 19 个 typed peers 仍是外部语义边界 |
| Worker 初始化值 | 117 cases / 875 entries 通过 | 其中 633 次实际 Graph wire；Store 仍在外部边界 |
| Worker 原件恢复 | 1,660 个归档成员、8,965,311 字节及 5 个精确原源通过回读 | 只读证据，零新 native |
| E 公共服务开发构建 | 2 次新 B3 完成 | 零语义入口；独立完整边界诊断进程在 90 秒 CPU 限制被终止，无输出，未通过公共命令 |
| DMS 旧原件 | 28 项 VM 测试中 test26 的 3 个子项失败 | 预期 REFUSED，实际 GROW；原 1,584 次 VM / 390 次 synthetic ACK，零 B3/native/OS |
| Map 旧原件 | 24 VM + 24 paired 测试通过，918 VM / 459 native | synthetic ACK 范围；没有实际 OS，不能代表 Store |

第 22、24 轮的后四项均是 names / exports 的原编译器与修改后编译器对照。冷自举曾通过，也仍出现原限时内失败，故不能宣称自举已稳定闭合。第 23 轮完整 reader 的 job 已成功，但 root 两次读取其完整日志遇到传输关闭；目前只记录 job 结论，不推断尚未拿到的 owner 原文。

## 本轮具体修复

1. 对象快照量测中的两处布尔 `not done` 被原 Builder 拒绝。仅改成等价的 `done == False`，同步对象前缀、静态影响分析和新普通补丁构建的精确依赖。
2. 汇编 syntax/render、公共发布 presentation、服务 controller 和 ELF 作者工具中原 Builder 不支持的 break / UnaryOp(Not) 改为等价 flag、return 或布尔比较；临时目录 cleanup 的状态参数显式从 u32 扩到 u64。全部旧测试及限制保留。
3. ELF builder、test、CI 和 assembly generator、CI 的传递源指纹一起更新；原来的四处缺右括号修复保留。
4. memory lease 的无效 load 作者调用改为原工具支持的 u64 字节读。
5. 新 DMS5 在需要执行真实 FSTAT 的新 inode attach 前执行序列溢出检查。缓存 attach 不消耗 FS 序列，保持原行为。原 28 测试体逐字保留，并新增第 29 项缓存 attach / 首错误检查。
6. 新 DB2 给原状态比较增加明确 u32→u64 转换，保持 32 项 VM 和 32 项 paired 测试；失败归档根修为真实工作根，避免原失败被归档器再次遮蔽。
7. Worker Maps3 仅将原工具不支持的 `not found` 改为等价布尔判断；仍使用原四组测试和原资源限制。

这些是 **新修订源码**，提交时执行计数为零；修复正确性由后续实际 CI 决定。旧失败日志原样保全。

## 新增的原生语义连接

### 普通补丁准备

新 HIA 叶子完整接管原 `_prepare_program_patch`：在真正原 Core 与 request admission 之后，执行精确旧 hash 检查、全部编辑的原顺序诊断、四种编辑及保持插入顺序的完整候选输出。它输出完整原生候选或原始错误 UTF-8 字节，不通过 host reason 映射生成业务错误。

计划 206 项测试，176 次独立原函数准备对照，覆盖全部 22 个错误载荷、错误先后顺序、Core 1–8、三种接口策略、Unicode / -0、所有缓冲区边界，以及准备成功但后续应被函数数、8 MiB 字节或 262,144 节点限制拒绝的候选。它不提前窃取后置 Core / interface 检查，也未声称完成整个 patch 命令。

### Worker pure peer 连接

新连接把实际 HIA sequence → pure request / issued handle → maps / values → HIAWIR01 串起来，重新编译四个 HIA 子核。独立原构造器的完整 trace 和部分属性作为对照。15 个效果 peer 仍在外部边界；本修订仍限制为同一不可变已发行 Graph。跨 Graph 的原生导入与 registry 正在独立实现。

### 六角色 DB / shared FS / DMS / map / memory 连接

新固定执行器连接六个真实 HIA 角色与 HIA packer，纳入 memory2 / DMS8 / DB2 的最新源码。计划 33 项完整控制和 18 项物理测试，覆盖外部 POSIX / SQLite 冲突、hardlink inode、unix-excl / deferred close、DMS map、四组实际 strace 故障，以及单列纯 abort cleanup。原始六角色 trace 每次入口的完整 input、output、workspace 与返回值均以 VM 回放；旧四角色 replayer 原文保留。

这仍不是完整 unixOpen / findReusableFd、31 SQL 或普通 Store 的闭合证明。

## 本轮验证与留存

新增 159 项明确源码清单；75 个 workflow job 均要求实际 Ubuntu 24.04 / x86_64 / ubuntu24 镜像。调度标签为 ubuntu-latest，但执行域检查失败会直接停止。只选择有新修复或新连接的目标，本轮不继承旧通过计数。

原 B3 的 10 秒 CPU / 20 秒 wall / 256 MiB、1 MiB output / workspace，原作者生成和 native 进程限制均保留。真实物理测试的 900 秒是聚合外层期限，单个进程仍有原限制与真实 wait4 / kernel receipts。没有通过扩大语言容量、跳过旧测试或提高原生限额取得通过。

本目录保留完整源交付 manifest、原始 job logs、第 22/24 轮关键原 JSON 与完整可还原 reader 日志、新原补丁完整作者源。所有原 JSON 用原字节保全，避免超过 JavaScript 安全整数范围的 u64 被重新序列化。

## 仍须闭合的生产路径

- 普通 CLI 的完整 assemble / render / verify / edit / compile / publication 与失败顺序。
- 一般 Core 原生机器后端的全部版本、函数容量、类型、控制流、内存、资源、调用、导出、机器规划、x64 与 ELF；bootstrap 编译器的子集上限不能替代普通语言。
- 普通 patch 的新 Core 复核、接口策略、实际 receipt 与完整命令连接。
- Worker 跨 Graph registry、效果 peer、11 个业务工具和普通安装入口。
- Store 的完整文件打开 / 复用、31 SQL、事务、日志、视图、提交及真实恢复行为。
- 冷自举在原 180 秒内的完整稳定运行、原始全量 ROG、独立最终打包、安装后空环境执行与去除旧运行时依赖。

只有这些生产路径和整套独立门闭合，才进入删除旧整套。当前删除数为零。
