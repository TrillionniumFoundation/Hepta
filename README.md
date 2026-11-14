# HIA 原生重写进度 — v143

冻结时间：2026-11-14 12:13:48 UTC。前一提交：`579d76ed8e0a96b7046cfd57554cfc108cfa5138`。完整历史见 [STATE.json](STATE.json)。

**整套 HIA 原生资格尚未闭合，旧生产实现未删除。** 原测试、断言、燃料、期限及历史失败继续保留。

| 范围 | 本次状态 |
|---|---|
| Inspect drive R3 | 独立3188文件实际物化；两次生成及原check全部PASS |
| R3 Source18 | 18方法、36事件、21子测试PASS；两owner完成180+3／ECHILD；Root完整证据核对通过 |
| R3 Native17／VM12 | 唯一session5079仍运行；执行端报告1编译及17Native方法通过；VM尚未启动、无最终资格 |
| CLI op10 | 12组新控制＋原Source18、保留3和CLI43，18阶段／76方法计划审查完成；未绑定、未执行 |
| u32入口布局 | 原20检查、24编译、32invoke、8原1M燃料参考、4ELF复现具体方案冻结；未执行 |
| namespace fresh诊断 | 单次原current_sources观察器和监督器已编写；未调用产品，原期限失败未解决 |

## 实际完成的修复

新的 Inspect drive 仅在真实 pending 存在且尚未执行时调用原 service，再交回原 drive 完成真实 ACK。原 service、step、finish、ContinuationFrame 和测试均未修改；新增调用帧的可观察性边界保留。

当前源码树为 `b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96`。Root完整核对生成阶段81证据、Source18的55份attempt／outer文件，以及三棵源码树的所有字节、模式、七项stat和路径集合。全部3188个新inode独立且nlink1。参见[生成终态](inspect-drive-r3-root/ROOT-DRIVE-R3-GENERATION-TERMINAL.json)和[Source18终态](inspect-drive-r3-root/ROOT-DRIVE-R3-SOURCE18-TERMINAL.json)。

Native／VM计划继续使用同一runner，Root对155份描述符、17＋12原ID、编译器／运行时、三树及外层启动器完整逆投影核对通过。运行尚未结束：七个Native组由执行端报告全部通过，包含原cross-frame失败项；原make_catalog在首个VM owner前反复对完整INDEX进行逐帧哈希。仅根据已存在索引的长度和帧数核算，约有348.59GB索引输入进入pin，SHA256与SHA1合计约697.18GB。没有为这个估计额外重放哈希或基准。第09目录创建不代表VM已经执行；先前阶段表述已纠正。此中途状态不能当最终Native／VM资格。

旧R2的11 PASS／1 ERROR、未运行项、nonce4 unknown退役和完整原件保管均保留。

## CLI与编译链的后续边界

[CLI控制合同](hia-inspect-cli-controls-r2/CONTRACT.md)要求正向真实经过六映像CLI、op35、op10与Inspect HIA，真实机器进入数大于零且旧Python策略体调用数为零。丢失返回只能在真实调用及六缓冲区完整捕获之后注入，不能伪造成功或重放策略。binder须先消费同一R3真实Source18、Native17、VM12全部PASS，才生成独立3191文件闭包。

新增三个适配器目前由完整外层源码闭包绑定；原六映像manifest自身未包含它们，support contract也未再生。未来current_sources会纳入三路径并拒绝旧声明。当前设计仍是开发资格；原CLI43嵌套子进程保持原脚本，不能声称已选中新的私有op10。

u32入口布局使用实际R19加五个u32文件的3180谱系，仅从原完整归档提取所需18文件。显式source投影完整逆向恢复原函数，保留20检查和原1M参考燃料；不能替代ordinary、R8、aggregate140或最终当前源码cold。

namespace诊断只计划调用一次原current_sources，不缓存源码摘要、不裁剪闭包、不替换读取或哈希提供者。回调记录实际事件、序号、长度和时间；路径根据固定源码顺序及调用后验证映射推导，明确区别于直接观察。观察开销计入，源码保护检查会预热文件系统缓存；证据保存失败会继续尽力保全剩余终态并报告失败，不重调产品。

默认CLI／Worker／Service／Store、安装链和相邻运行时仍需继续替换与验证；以上有限结果不能触发旧生产整套删除。
