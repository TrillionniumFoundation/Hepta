# V13 实际模型、完整费用与主试验拒绝

实现：`953fa62dee5aa563551d57b1374ab95b6d548b45`；tree：
`aa0683509a02ca97e4e0c1dd723e4047f50d81b3`。

19/19 容量参考控制、95/95 独立 CLI token-ID 比较通过；容量阶段模型
生成请求为零。三个基础 Rust-node 校准任务都实际提交三次，最终 **0/3**。
九次模型输出满足公开 JSON/category/type envelope，实际 HTTP schema 和
返回 GBNF 均为 node-before-changes。七次真实编辑节点重叠、一次编译类型
错误、一次运行结果错误仍阻止任务完成。独立 peer 还保存了每次重叠的
实际 span witness，以及错误运行的原始输出与预期值。

实际用量：输入 **21,577**、输出 **1,659**、总计 **23,236 tokens**；
unknown usage、人工答案修补、hidden evaluation 均为零。模型回答未改写。
主试验 CLI 实际返回 rc1 / `E_TOOLSTUDY_NO_QUALIFIED_MODEL`，拒绝发生在
引擎构造前，main 目录未创建、16 格 HIA/Rust 主对照完成格数为零。
不能从校准失败推断 HIA 与 Rust 哪个开发工作流更好。

本轮修复的是 V12 实际 decoder 把 changes 排在 node 前的问题，并增加
公开类别/类型约束和通用诊断。提示与 decoder 的变化已经在 V13 协议披露。
任务、模型、预算及 3/3 门槛仍冻结；这是同任务自适应跟进，不是独立新任务
holdout、公开预注册或 AI 开发优势证明。

## 包与读回

`p7-v13-20261030.tar.xz` 共 **3,960,360 字节**，SHA-256：
`8d7aa5853078c5602fc308ac2eb819b2ed5b409866a42b25f4497441c224a901`。

`p7-v13-20261030.manifest.json` SHA-256：
`9f43be4d257f4a0acbddba6fef73cd4d530f708af66e696130fec68f1246aebe`。

实际有界读回验证了 **1,417 个成员、103,012,055 字节原始内容**，没有
解包执行程序，没有新模型或 native 测试。原始源码库存每阶段 6,907 文件；
235 项 profile source bindings、40 个 runtime payload pins、真实请求、
SSE、token 用量、公开 schema、HTTP 字段顺序与返回 grammar 均核对。

在本目录用 Python 标准库独立读取：

```sh
python3 -B verify_evidence.py \
  --archive p7-v13-20261030.tar.xz \
  --manifest p7-v13-20261030.manifest.json \
  --archive-sha256 8d7aa5853078c5602fc308ac2eb819b2ed5b409866a42b25f4497441c224a901 \
  --manifest-sha256 9f43be4d257f4a0acbddba6fef73cd4d530f708af66e696130fec68f1246aebe \
  --output verification-local.json
```

读回只使用相邻文件与上述外部摘要，不访问原 workspace、网络、模型或编译器。
它验证留存字节与内部一致性，不认证历史执行真实性，不签发代码准入权限。
GGUF、系统运行时和工具链二进制不复制进本包；原 pin/acquisition 记录保留。

## 记录关系和费用

`SUMMARY.json` 是本次已完成三阶段的实际摘要，原件也包含在包内。
`P7_PEER_REVIEW.json` 是独立标准库原始记录审查；审查脚本与完整回执在
归档的 `context/compiler-independent-review/`。`VERIFICATION.json` 与
`operation-verification-001/` 是实际完整归档读回结果。

| 实际阶段 | 外层秒数 |
| --- | ---: |
| 容量控制 | 95.149394835 |
| 模型校准 | 538.952711871 |
| main 准入拒绝 | 5.579925408 |
| 归档创建 | 24.055684617 |
| 完整归档读回 | 0.586903743 |

各自内部测量属于嵌套区间，不相加。独立 peer 外层 0.453373759 秒、内层
0.403788869 秒也属于嵌套。准备摘要脚本首次因缺少括号而产生 SyntaxError，
原脚本与实际工具观察保存在 `summary-attempt-001/`，首次精确耗时未知；
只修复外部汇总器后，第二次摘要生成成功，实测 0.074651110 秒。模型、
协议和正式原始记录没有改变。完整人工/agent 开发与审查费用仍未知。

`PACKAGING_RECEIPT.json` 的状态描述打包刚完成时尚未读回的历史状态；
后续成功由独立 `VERIFICATION.json` 记录，没有回写旧回执。原 `3533b95`
仅有计划、零容量执行和零模型请求，其三份文件作为历史保留；旧 V11/V12
结果继续保留在父交付的各自证据目录中，没有改标为 V13 成功。
