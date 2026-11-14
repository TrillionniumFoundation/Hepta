# HIA 原生重写进度 — v144

冻结时间：2026-11-14 13:39:26 UTC。前一提交：`5ecafbb86dc79514a73efdf6fddaae5f3b9ac708`。完整字段、谱系与历史失败见 [STATE.json](STATE.json)。

**整套 HIA 原生资格尚未闭合，旧生产实现未删除。** 本次取得新的有限组件结果，也保留了真实阻断。原测试、ID、断言、燃料、期限和失败原件均继续保留。

| 范围 | 本次实际状态 | 资格边界 |
|---|---|---|
| Inspect drive R3 | 两次生成、一次check、Source18、Native17、VM12全部通过；Root完整核对证据与当前三棵源码树 | VM只重放明确选定的12帧；四次丢失返回的未知所有权隔离保留 |
| u32入口布局 | 原20检查通过：24编译、32invoke、8个原1M燃料VM参考、8链接、4ELF；Root全量原件核对通过 | 显式源码投影，未执行原ordinary unittest方法；ELF内部workspace未观察，未获得当前源码cold资格 |
| CLI op10 R3 | Source18与7次编译通过；第一个新控制在setUp定义准入处ERROR，立即停止 | 5个owner完成原180+3和ECHILD；后13阶段、retained3、CLI43未启动，新op10正向资格未取得 |
| namespace单次fresh诊断 | 独一CI调用一次原current_sources，1551文件全部fresh读取；Root原ZIP与事件核对通过 | 原NativeNamespace 35项仍为32 PASS／3 FAIL；270.75ms包含观察开销，不能当优化收益 |
| PatchResult策略 | 11个新增源码已作者；Root发现exact slice常量未覆盖，在生成前阻断 | HIA、ports、data均未生成，新Source／Native／VM未运行；最小后继尚待完整审查 |
| u32 R8大小与打包 | 19个作者对象由Root完整远端读回，具体执行计划冻结 | 零新编译、零打包；须满足严格ELF大小上限后才可进行一次HIA打包 |

## Inspect drive 的实际闭合范围

R3只在真实pending已发出且尚未执行时调用原service，再交回原drive完成真实ACK。原service、step、finish和ContinuationFrame不变。同帧重入仍拒绝，独立帧可以进入；额外Python辅助调用帧的可观察性边界保留。

当前独立3188文件树为 `b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96`。唯一Native／VM运行session5079以0退出，外层730.344秒，其中原catalog构造在各180秒owner之外。Root核对61495条完整证据、13586次实际机器调用、34081个唯一完整缓冲区、12个真实Native／VM六缓冲区比较、22组源码保护记录及当前三树的全字节、模式、七项stat和路径集合。完整结果见 [Native与VM终态](inspect-drive-r3-root/ROOT-DRIVE-R3-NATIVE-VM-TERMINAL.json)。

没有宣称全部13586次调用都经VM，也没有宣称未知所有权全部退役。此前把第09目录出现描述为“VM已经运行”的中途说法已纠正。原catalog重复哈希的成本未通过缓存、裁剪、重试或加预算规避。原R2的11 PASS／1 ERROR及未知退役原件保留。Source18完整原件已封入Git；Native／VM的179份压缩分片本机已完整复原校验，远端运输尚未全部闭合。

## CLI op10 的实际失败与修复方向

旧绑定计划为26,454,315字节，超过原执行器16MiB输入上限。R3把全部61,550条前驱记录按原顺序分成四份不超过8MiB的索引，主计划降为25,729字节。Root逐条核对原件，逆向恢复旧计划全部字节；原10项控制保留，实际R3 executor、support、tests三个执行路径均绑定。没有删前驱、加上限或改变18阶段、76次方法调用、7次编译和预算。76是调用次数，包含重复保留项，不能当76个不同ID。

实际session45546只运行一次，38.688秒后退出1。Source10、Source8、六映像构建、Inspect构建四阶段通过。第五阶段 `test_actual_record_and_hia_op10` 在setUp调用 `issue_preselected_inspect_record` 时拒绝真实 `function_signature`，报 `ValueError: selected function is not the frozen policy definition`。没有进入该测试体，没有自动重跑。见 [失败核对](inspect-cli-op10-r3-root/FAILURE-TERMINAL.json)；131份实际attempt／outer原件，加7份Root记录，均可由 [完整失败原件](v144-custody/op10-r3-actual-failure-CAPSULE.json) 复原。

执行后的独立compile-only诊断发现，Python3.14编译上下文造成原signature的248字节code与模板244字节code及异常表不同：原模块有 `import copy`，被动模板没有。源码或AST相等不足以证明code对象相等。R4最小候选仅补齐这次模块setup import，继续严格比较全部原字段；额外import hook、异常、引用及traceback影响明确记录。候选尚未物化新3191文件树，尚未进行新产品执行。

三个CLI适配器由完整外层源码树绑定；旧六映像manifest本身未包含三路径，support contract也未再生。原CLI43嵌套子进程不能被描述为已选择新私有op10。当前结果仍为开发范围。

## u32与namespace的边界

u32入口检查使用实际R19加五个u32文件的3180文件树 `4c62be4ed66ff107fa6f88c6131313a354868bd9`。Root核对830份原件、173,880,184字节、77个调用索引项、154事件及32次完整六缓冲区观察。8个原VM参考在首次Native调用之前完成；原四次0644到0700的ELF chmod来自原函数，捕获时模式与执行时模式明确区分。冻结runner的SyntaxWarning保留。该投影不能替代ordinary、R8语义、aggregate或最终current-cold。

R8计划保留原20秒、10 CPU秒、1MiB跨度。三映像frame允许R8最大558,378字节，而4096对齐后的ELF只允许557,376字节。相对旧562,746字节需减少5,370字节；历史6,600字节保守估计保留。若真实编译产物不满足两项边界，必须拒绝打包。原R5生产读取器source pin不放宽，生成ELF只保存0644且不执行。

namespace唯一CI为run43595690951／job132449559860，固定R20源码3177文件。Root核对原ZIP27成员、四次完整源码快照、22,820事件／11,410成对区间、1551个实际fresh读取和1823次保护。原current_sources一次测得270,752,930ns；保护、读取和LINE区间有嵌套重叠，不能相加，也不能推断未观察版本的期限余量。没有摘要缓存或闭包裁剪，原E_HIA_BUDGET未修复。公开保管保留产品ZIP全部27成员、130份普通原件及两份明确标注的非秘密响应投影；带临时凭据的两份原始响应仅保留本机。

## 新策略与生产调用链

PatchResult owner准备降低完整 `apply_program_patch` 与 `_check_patch_interface` 原体，保持两次验证、prepare顺序、接口比较、回执字段顺序和业务receipt中的 `native_executed: false`。既有selected_prepare_patch及Agent mode2字节引擎不变。四值解包端口只处理原UNPACK的有限形状。

Root在固定3.14.4下只compile完整模块，没有执行项目模块或策略体，就发现原 `changed[:8]` 的co_consts含exact slice，作者比较器未覆盖而必然拒绝。旧R1／R2／R3源码、控制与失败前检保留在 [Patch作者原件](v144-custody/patch-author-r1-r2-r3-CAPSULE.json)。slice后继递归比较start、stop、step，保留未知类型拒绝和全部code字段；原10个Source方法全文保留，另加一个窄控制，尚未执行。生成器最终缺失／漂移检查已补齐；R4新目录与旧硬编码名称不一致也在执行前发现，R4.2精确单字面量修正已作者，仍待Root核验。

生产调用链审计区分真实范围：hepta-runtime固定默认头有22个Rust工具handler；125个handler属于固定PR121头，不能写成默认主线数量。两个native-local示例尚未替换公开Rust调度。HIA工具链仍跨Rust调度、durable owner、Python Worker、Service及sqlite3；这些层已有可选HIA owner，但默认入口、资源闭包和进程／存储链尚未整套闭合。见 [生产调用链](production-next-boundary/CALL-CHAINS.md)。

本次实际读取主线头为 `f33d8da316de8fdf27b504371f1a5310997ff548`。固定谱系测试不自动转移为该主线或后继源码的全量资格。继续修复并实际验证CLI、PatchResult、R8和namespace，再完成当前源码cold、安装链和全部默认生产入口；这些条件闭合后才执行旧生产整套退役。
