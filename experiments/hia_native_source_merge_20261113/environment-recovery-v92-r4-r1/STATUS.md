# HIA 原生重写：环境中断后的恢复检查点

时间：2026-11-13 02:56 UTC。当前仍未达到“全套 HIA 原生闭合”。PR #888 保持 open/draft，head `acffa9262f31d073f8f0a6f0201eae201039f619`、base `5831f52fada45e076f8f68f198a15c0585e6104f`；没有合并、切换默认实现或删除受支持的旧实现。

## 已确认的开发和验证状态

| 范围 | 已确认 | 仍未完成 |
|---|---|---|
| 当前 v92 源码 | SOURCE129 的完整129方法、72命令通过；原标准CI source job541方法通过 | 当前native job第42步失败，具体原因待原件分析；第43步跳过 |
| CLI 原生运行基础 | r4b有限范围8 runtime +10 lifetime通过，48 HIA returns /11 C pump | 完整17 callers、46 trace，CALL/SEND/UNPACK和CPython所有权仍开放 |
| SQLite varint | HIA算法生成器、ABI、固定字节运输桥、测试源码及两版SQLite C参考完整保存 | Source8预定8方法/191边界值/1618 VM returns尚未执行；数据库引擎、事务、WAL和恢复尚未实现 |
| Full32 | 已定位旧Rust supplier的self-update失败；r5增加--no-self-update的源控制通过 | 实际supplier修复、完整32 gate与当前源码安装恢复尚未通过 |
| CI证据读取 | R4请求完整保存；此前SOURCE20的20方法实际通过 | R4实际reader在环境中断后的状态、下载字节、guardian、ECHILD及FINAL均未知 |

这些范围不能相互替代。源码方法通过不等于当前原生、安装、默认入口或完整重写通过。

## 环境中断和恢复边界

R4外层wrapper在02:33 UTC被调用一次；02:33:41仍在运行。之后工具连接中断，环境被报告为不可用。原始receiver是否已经exec、owner是否启动、实际GET次数和结果未被读到，因此全部保持UNKNOWN，而不是失败、成功或超时。

02:53 UTC执行环境重新可用，原workspace仍在，但原/home/agent和/tmp运行目录未出现。对旧session73219的一次只读查询仍返回transport disconnected。新环境中的进程或ECHILD不能证明旧owner收束。未重放旧reader，没有声称旧文件永久丢失。

原SOURCE20 R4的成功是断连前完整读过的实际结果；其6533字节Root读回记录SHA256为`ddc8637b69b2f318c47e71f9df31dfe79f4bb0aa8c57b3ec1681734601b02b95`。本检查点只保存已知事实和校验信息，不从记忆伪造缺失的原始运行文件。

## 已保存的完整源码和静态诊断

- [SQLite source-only PUBLICATION_HOLD](https://github.com/TrillionniumFoundation/Hepta/commit/7ab75efecb5f00e49fb6b455d7dc119fcddd34e6)：39路径、742478字节、37个独立完整blob；Root独立重算完整4164叶树和commit。原48路径发布中未确认的写入边界继续保持UNKNOWN，未重复POST。
- [CLI CALL部分源码恢复](https://github.com/TrillionniumFoundation/Hepta/commit/9618ca9eba7ca6bdf65c55847ccc24c2f254aa50)：8路径、41572字节；完整CALL C源18885字节与原哈希一致。Root独立读取全部8体和6942叶树。此提交明确为未执行的部分恢复。
- [step42静态诊断地图](https://github.com/TrillionniumFoundation/Hepta/commit/2924975f3849ea86a5294fa2d6c5fb7cde723567)：完整116方法顺序、owner及错误输出路径、构建归属定位。它是静态地图，不是失败原因或实际通过证明。
- [R4完整冻结请求](https://github.com/TrillionniumFoundation/Hepta/commit/0b5bf069d8a1c6509cf1421897553bbf99efce72)：51新路径、1078284字节；全部49独立体和4430叶树经Root读回。

本检查点将39个SQLite证据路径和8个CLI恢复路径按原path/mode/blob引用到静态地图分支，保留全部4432原叶。它不合并产品源码分支，不重新上传这些47个原blob。

## 恢复后继续开发

保留workspace中仍有与R4逐字相同的34份输入和CLI六份基础源码。新源码工作可从这些真实保存的输入继续。缺失的GIL后继、CALL生成器和SQLite执行控制必须明确作为新revision编写，不能宣称恢复了旧原件。新SOURCE8须完整冻结和独立审阅后才执行，旧计划的执行次数仍为零。

优先事项是：取得原CI第42步实际错误并修复根因；完成CALL/SEND及完整CLI语义；执行SQLite varint的首次完整源码和原生资格验证；闭合数据库持久性、solver/proof、Rust/build、Full32及安装恢复。全部原入口的替代和恢复验证通过后，才进入旧实现清理。

## 全量清理仍未满足的事实边界

完整pure v92 Git树有4125叶，其中生产Python模块176个、2737307字节。全仓另有131个.hiaasm、12个.hia和48个Rust文件，这些数量包含多种仓库用途，不能作为迁移百分比。先前独立完整读取的是1686个物理资格输入、40890650字节；其余2439叶不冒称已逐体重读。

受支持的旧实现仍是未完成部分的功能来源，故本检查点不会将删除它们记为完成迁移。此前清理的仅是具备完整逆向恢复证明的重复运输副本，未删除旧产品实现。
