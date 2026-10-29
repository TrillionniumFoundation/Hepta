# V10 终态独立审查：负资格不允许启动 main

**决定：DENY main for this completed negative qualification。** 冻结来源
`11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0` 的真实资格为 **0/3**。
三个任务各进行了三个已记录生成请求，不能达到预登记的 fresh 3/3 门。
单候选停止规则保持生效；本次审查不授权新提示、重复资格、附加候选或主实验生成。

实际 RESULT SHA-256：
`9d528ebfdfa5e6f0e748f625a6364cbbe8786ffd54f55ab8bb3f335d50905b94`。
实际 main 拒绝回执 SHA-256：
`eab246d0a582e920af789ac67608374d8255af2392de33c8cdf3959322579fe8`。

## 与独立成本审查的分工

本次检查来源和已审 capacity 的身份对应、资格推导、真实 main 拒绝、九个生成请求的
完整消息／模板及调用顺序。SSE 重建、usage、tokens 和 wall time 由另一个独立审查包
处理，不把本次 gate 审查再算作一轮模型运行或成本实验。

审查只读取 58 个 JSON，并解析固定源码 AST。资格记录中的 185 个来源映射、prompt
映射、protocol、模型及工具身份均与已经独立审查的 V10 capacity 对应；七个关键实现
文件另与当前文件和冻结 Git blob 比较，内容一致。本次没有再次读取 2.5 GB 模型来
重算权重 hash，模型／工具的初始与结束身份按 producer 原记录和 capacity 对应核对。

## 九次实际生成没有发生模板或历史改写

逐次对照了 cell request、engine 的 `template-NNN.json`、`preparation-NNN.json` 和
实际 `transport-NNN.request.json`。九组原始 messages 完全一致，服务器观察到的完整
渲染、guard expected prompt、preparation 和 transport 中的 rendered prompt 也一致，
均逐字匹配固定官方模板的 plain user/assistant 分支。

每个任务的 initial message 与其已审 capacity 中的原始任务提示相同。六次 repair
都保留了上一份完整 `response.text`；反馈消息由固定 REPAIR 文本和所保留的公共
feedback 构成。没有自动合并前次 edits、截断代码、移除公共案例或补写模型答案。
真实 preparation 均为 fits；最大实际 input 加完整 1536 输出 reserve 为 **4479/8192**。

此前已记录 actual GGUF 模板全文与官方模板全文不同。此次九个真实生成请求继续
通过逐请求严格相等检查，**没有观察到模型或 repair 历史触发模板改写拒绝**。
因此不能把这轮负资格归因为已经发现并被 guard 控制的模板全文差异。
这仍不证明两个模板对任意未来消息等价。

## 资格推导与实际拒绝顺序

按照冻结资格定义，三个 Rust-node 任务必须在原预算内均满足 correct、status correct、
terminal hidden 已执行和完整 usage 等条件。本次三个 cell 的 correct 全为 false，
hidden_evaluated 全为 false；由实际 cells 独立推导 eligibility=false，与 RESULT 一致。
19 个人工 reference 和 95 个 tokenizer 控制不参与这个成功分母。

真实 main 命令返回码为 1，trace 中的失败是
`E_TOOLSTUDY_NO_QUALIFIED_MODEL: fresh Rust node qualification did not pass 3/3`。
静态 AST 对应位置为资格检查第 76 行、首个输出 mkdir 第 80 行、engine 构造第 133 行。
实际被拒绝的 `/tmp/hepta-next-agent-v10-main-refused-01` 目录不存在，原始回执记录
main cells、model requests 均为 0，并与同一个 RESULT 和 capacity SHA 对应。

资格 engine 的初始与结束模型／运行时身份记录一致，owned engine 已退出；审查时
未发现该 owned model process 仍在运行。本次资格总共九份模板、九份 preparation、
九份实际生成 request，不存在将 capacity 或另一轮资格请求混入本轮分母的记录。

## 保留的边界

本次 reviewer 的 model、tokenizer、native、compiler 和测试执行均为 0，没有导入
生产评估模块。结果支持实验协议的停止和拒绝行为，不证明模型普遍不具备编程能力，
也没有产生 HIA 对 Rust 的成功率、token、开发时间或维护成本优势证据。
它是可信编排下的来源与原始记录核验，不是物理宿主 attestation。

独立审查首次执行通过，REVIEW SHA-256 为
`b39e93991bc49f79a00b13677d41c8afb82d110438f460d660bfb7b0b0e4a300`。
原始 producer RESULT、main 拒绝、owned-exit、实际审查脚本、日志及机器回执位于
`experiments/hia_next_safety/toolstudy_v10_review_20261029/terminal/`。
