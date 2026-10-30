# PR405 已有研究增量：原始身份核对与严格缺口

本文件是2026-10-30新增的只读综合，不是恢复的历史记录，也不改写候选147台账。资料容器为公开PR405提交 `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`、tree `30c20454c3e08990a7995306f31ff21acad182f4`。实验仍绑定各自原始源码。当前PR410 `e0b9012a249167b5bc5b0f3bd243899344621080` 的工程测试是另外的实际执行，不能继承这些旧模型/计时结果。

本次读取两篇指定文档、40个原有Git对象和9个源码/目录对象，核对对应Git blob身份；从已经公开的压缩包只读提取311个相关原始成员。没有重跑模型、native样本、求解器或性能计时。这个零新增实验调用只描述本次只读核对，不描述整个开发会话；同时进行的P3原生资格及代理工作也不是零成本的P5对照。

## 可以更新用户原表的事实

| 阶段 | 可确证增量 | 严格条件仍开放的原因 |
| --- | --- | --- |
| P0 | 405已有typed assembly、有限源码/local View和显式历史适配进入现有standalone verifier/runtime；本轮P3安全收敛又修复了规范源码路径与实际读取的绑定，并在公开e0b实际通过177方法 | legacy Rust/C/direct-owned-LLVM仍明确列为不同路径；foreign/tasks/更一般stored reference的源码组合仍有限；不能据有限路由把全工程写成单Core已关闭 |
| P1 | 现有有限owner、loan、结构化取消/继续等实现与具体资源账本证据继续有效 | 任意一般内存/provenance、递归ADT、全量部分初始化、逃逸/外部生命周期、任意异步取消与错误恢复仍须独立实现和验证；外部C++故障仍有不可恢复位置 |
| P2 | Rust显式候选、精确请求/映像绑定与当前整合代码资格取得独立工程增量 | Python生产权威不变；shadow比较、原始Copy-record候选或一次同树运行均不等于生产切换资格 |
| P3 | 本次规范源码两次读取、terminal symlink拒绝、保留目录FD发布等安全组合已经实际闭合并保留red/green | 这是strict scalar C importer的有限来源完整性修复；一般callback、重入、线程、外部生命周期和完整C++ ABI未被该测试覆盖 |
| P4 | 旧研究保留4TU C迁移、真实nlohmann升级和有限C++ live-destination move assignment等较新证据；后者原报告两配置各789 native case并记录196648KiB资格峰值RSS | 完整历史库/全部构建配置、人工迁移与维护成本、一般C++行为等价仍不成立；资格耗时和资格进程RSS不等于最终应用开销 |
| P5 | 现在有独立冻结源60df上的新模型资格3/3，以及完整16单元主试验14/16成功、23次真实generation；旧40次/0成功不能作为所有后续实验的唯一描述 | HIA两臂各3/4，Rust两臂各4/4；这没有建立HIA优势。当前e0b未见真实工程任务效率、后端/缓存控制、完整人时/货币成本资格仍未完成 |
| P6 | round4已有实际post-exec进程VmHWM、112个原生样本、真实PGO训练/profile-use重构建、P95/P99和准备成本 | all14仅4通过，strong10仅2通过；完整净收益多项为负。无代表性未见应用总体、物理板卡/设备协议、WCET与完整RSS资源上界；`no_change`不变 |
| P7 | 精确原始源/工具/产物、正负结果与只读审查被保存；本次补充了它们与405的差异映射 | 源码→Core→各后端的完整refinement、checker实现对应与全语言健全性证明仍未完成；有限审查和CI不能替代这些证明 |

27项原严格关闭文本和8项普遍性false没有修改。本文件没有把任何广义阶段标成CLOSED。

## P5：3/3、14/16和23分别是什么

原始执行提交为 `60dfedc626b7ce3feaaa87ac16d711fe0cc8e9d3`，公开源码提交 `37d3a317b77aeac8f42b8a727f0f123b4a46e49f` 与其tree `6add0d477bf92c3980110b50a6b1675306175c99` 相同，commit身份不同。实验协议先登记，实际模型任务随后发生。原始 `RESULT.json` 和 `FREEZE.json` 的SHA256与公开summary逐字一致；23份保存的transport stdout解析后逐项等于其EVENTS记录，各有一次真实turn.completed。

| 范围/臂 | 单元 | 成功 | 实际请求 |
| --- | ---: | ---: | ---: |
| 前置资格 |3|3|3|
| HIA full |4|3|6|
| HIA node |4|3|6|
| Rust full |4|4|4|
| Rust node |4|4|4|
| 主试验合计 |16|14|20|

主试验失败的两个单元都是`saturating_score`，各用完3次公开修复；没有进入native/hidden。所有失败保留在分母中。资格加主试验是23次请求，不是23个主单元，也不是23个成功任务。

从23份真实CLI事件重新相加：input385335、output8540、reasoning1456、cached input224000。cached是input的子项；input+output+reasoning395331仅为原协议的保守计费，不是独立确认无重叠的精确token总数。两个准备请求另列，其中一个usage缺失；完整服务成本、人工工时和货币成本仍未知。原QUALIFICATION票顶层requests=0是主试验前live snapshot，不能覆盖票内3个实际请求或最终23个请求。

两条HIA失败涉及合法比较opcode名称披露不足。**这只是旧试验冻结接口的诊断。405已经存在 `hepta/hia_opcodes.py`、schema中的instruction_catalog和 `docs/hia-opcode-catalog.v8.json`，不能继续把“目前没有catalog”当成当前缺陷。**也不能据目录已经补齐就宣称旧失败被修复成成功；没有重跑同一任务或改写旧结果。

另一个独立round4三臂研究仍是：Qwen1.5B完整12/12、成功0/12；Granite2B只尝试3/12，因基础设施错误失效并停止，不能写成有效0/12。两者合计23个completion请求、15个完整响应、7次超时、1次基础设施失败；完整output/total token未知。本次没有把独立CI复制的旧pending文本当成今天的现场状态，也没有凭启动控制推断复制实际成功。

证据：`evidence/hia_eight_delivery_20261030/{SOURCE_PUBLICATION,FRONTIER_SUMMARY,FRONTIER_ACTUAL_AUDIT,FRONTIER_LIFECYCLE_AUDIT}.json`；`raw-frontier-evidence.tar.xz` 中 `agent-frontier-study/{FREEZE.json,run-01/RESULT.json,run-01/*/attempt-*/transport/stdout.raw}`；round4的两个原始MODEL_RESULT及独立RESULT。

## P6：真实RSS与PGO已经有记录，整体性能资格仍失败

原始strong benchmark基线是 `0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997` 加当时的工作树改动；135条实际源码SHA256绑定才是精确运行身份，不能把基线SHA当成干净冻结提交。原始report SHA256为 `3077ded0984956b129fcad3b416062176085f634d88e139149ee2269c33d1ce0`。

本次逐项核对112个sample JSON与原始report，以及每个sample指向的真实命令stdout和observation。该共同native driver读Linux `/proc/self/status` 的VmHWM，另存 `getrusage(RUSAGE_SELF).ru_maxrss`。两种数字不同，不能混用。以下是7组原始样本中的VmHWM KiB（min/median/max）：

| 内核 | HIA narrowed | Rust O3/LTO |
| --- | --- | --- |
| full_lifecycle |844 /848 /848|1000 /1024 /1052|
| packet_xor |912 /916 /920|1060 /1080 /1108|

它们包括共同harness、加载器、运行库和所载backend，且只适用于这两个有限内核；不是owner payload、整个服务RSS或一般内存优越性证明。RUSAGE字段在这些样本中为95108–96132KiB，原样另存，不用它替换已登记的post-exec VmHWM口径。

PGO有4次实际训练调用（C/C++各两个内核）、真实instrumentation构建、两次llvm-profdata merge和两次profile-use/full-LTO重构建；其命令均返回0。四份profraw和两份profdata的实际归档字节/hash都与原build记录一致。它不是仅在名称中加了PGO的比较。

总体结果仍是112样本/1536正确性观察的质量门通过，14比较仅4通过、strong10仅2通过。full_lifecycle相对C++ PGO/LTO的batchP99达到3.043377倍。候选准备6.736501785秒，原HIA0.771358725秒，额外5.965143060秒；原研究完整已测区间37.125838604秒，含PGO训练/重构建，但缺工具获取、完整依赖和人工成本。更快点估计不能替代登记的置信/尾延迟门槛。

C++ move-assignment资格报告中的196648KiB通过归档原始67MB报告的SHA256与顶层costs字段回读确认；这是迁移/资格流程的进程和子进程峰值记录，不能移作迁移后应用RSS。

证据：`experiments/hia_optimizer_eval/round4_20261030/{REGISTRATION,PROTOCOL,READOUT,ROOT_NUMERIC_AUDIT}.json`；`trial01.tar.xz` 中的 `strong-benchmark01/{report.json,sample-*.json,driver.c,c_profiles/*,cpp_profiles/*}`；C++ `native-qualification01.tar.xz` 的 `assignment-qualification/qualification.json`。

## 净收益与NDU结论保持原样

八项交付研究的四臂warm归属总成本：fixed27.809215321秒、greedy28.429366716秒、DP28.318381481秒、native NDU28.877934407秒。16个policy episode和6个opportunity control已运行，340个输出正确；所有policy阶段都选base且候选build为0。四个完整trace机会差值均为负。原历史21.387330636秒build被明确单列；它不是本轮新cold build。32个已存native决策与独立DP一致，只说明这个模型中的一致性；NDU没有取得额外优势。

round4会话实验确有320次native回复、10个会话全部完成：旧/新完整已测成本25.201670787/24.929801855秒，降低0.271868932秒。这只支持有限传输会话开销改善，不能覆盖编译闭环对强固定/DP的负结果。

同一round4 owner队列复测：baseline7.977006673秒、完整已测部署12.926983109秒、净收益−4.949976436秒，自动选择0/3；72分配/72释放、close后live0。正确值、完整本地成本账和资源平衡不等于经济性通过，也不等于完整社会/工程成本已知。

## 旧研究为什么不能自动资格化405或e0b

本次把原始精确SHA256集合逐项与405 Git原字节比较：

| 原研究源码集合 | 绑定数 | 与405相同 | 与405不同 |
| --- | ---: | ---: | ---: |
| Frontier真实模型冻结源 |181|165|16|
| round4 strong benchmark |135|98|37|
| round4 C++ assignment显式绑定 |17|16|1|
| round4小模型研究 |31|19|12|

没有缺失路径。详细差异和两边hash在 `existing-study-readout.json`。即使少数路径相同，也不能借此跳过当前源的独立任务/性能资格；405又是e0b的父源，e0b具有额外变更。

## 下一项具体P0代码工作：returned-call进入局部View

现有 `tests/test_hia_source_local_views.py` 明确把下面组合列为拒绝边界：

```hepta
struct View<'a>{data:read 'a [u8],tag:u64}
fn view(b:read [u8])->read [u8] from b effects{}{return read b;}
fn f(b:read [u8])->u64 effects{}{
    let v=View{data:view(read b),tag:7};
    return v.tag;
}
```

这是本次静态定位，不声称已在本核对阶段执行或证明该程序全部前置合法。后续工作的第一道控制必须分别建立parser/checker、Resource IR和当前HIA lowerer的真实结果。

可复用的现有入口已经明确：`resource_lowering.call()`把borrowed-call origin保留在返回loan；`resource_ir.call()`用返回loan保守覆盖整个入参区域；`bind_view`保留其精确permission/pointee；primitivev8的call/loan机制已经有父loan栈。剩余source adapter在构造局部View时要求恰好一个direct loan且没有borrow_parents，因而把这两个已存在profile隔开。

最小候选范围是一个显式、有限的前端profile，沿用现有checker和v8：把返回call的完整父/子loan责任转交局部View，在shared Copy、exclusive move、CFG重命名、词法scope结束和提前返回时正确维护与结束。不能只删除guard；所有者的drop/重借冲突必须直到最后别名结束才解除。应保留多存储loan、嵌套View、参数/返回逃逸和外部生命周期拒绝，不引入新Machine或新语义Core。

主要落点：`hepta/hia_program_source.py` 的 `_Value`、`call`、struct构造、`end_local_views`、scope/CFG状态；现有Resource IR和primitive Core继续承担独立拒绝。原有profile默认行为必须保持，新增范围必须显式。实际Python/Rust/direct-LLVM结果、loan/owner账本、取消/预算停止前缀及非法提前drop/双重end/逃逸反例，均属于后续实现资格，不能由这份静态设计提前宣告通过。
