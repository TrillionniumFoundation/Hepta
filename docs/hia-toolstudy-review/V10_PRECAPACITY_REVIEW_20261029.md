# V10 独立生成前审查：只允许零生成容量阶段

审查来源为 `11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0`，tree 为 `66ff2c9ff5292be55791b9f1a184a7f64bc3942f`。对照来源是未修改的 V9 `ef9fbafabe9db52a5e59220f1738d5842ac164cc`。本次没有发现需要阻止所注册容量阶段的实质问题。

**决定：ALLOW 仅限 zero-generation capacity。** 执行仍以 V9 已完整结束且其 owned process 已退出、协调者完成磁盘与唯一固定权重获取并释放运行窗口为前提。**qualification 和 main 保持 HOLD。** 需要取得新来源的完整 19 行容量与 reference 结果、95 份独立 CLI 对照、模型/工具/来源身份和进程退出记录后，另行决定是否允许资格生成。

## 独立核对的方法与范围

审查者只读取源码、JSON、日志和 Git 对象；没有导入生产评估模块，没有重跑 producer 测试，没有执行 tokenizer、native build 或模型。185 个 producer 来源绑定均与当前文件 SHA256 和冻结提交中的 Git blob 逐字一致。与 V9 比较只有 14 个新增文件；所有既有源码、协议和历史结果未改。

producer 的提交后测试记录为 54/54，0 skip，返回码 0；日志 9,960 bytes，SHA256 `2be8732ede06ec403f9a5729c5cca41941f2fd8be72e686492d56dd2b00dff4f`。本次核对了原始日志、receipt、source/tree 和全部依赖，而非把独立静读写成一次新的测试运行。

## 实验内容与接受边界

- V10 直接从 V9 重导出 `prompt`、`messages`、`render_nodes` 与 `REPAIR`，没有重定义或补充任务文本。producer 对 19 组实际 initial/query 和 repair message 构造的相等性控制保留在其日志中。
- 资格和主实验 runner 相比 V9 只有两个 import binding 变化。原来的 budget、validation、reference 和实际结构化编辑 session 被继续使用；没有新的答案生成器、目标节点提示或 host 修复逻辑。
- 新 engine subclass 只实现构造与 `request` 包装；原有 `generate`、JSON decoder、采样、SSE 保留、tokenize 和每次完整上下文检查均由原实现继承。
- runtime、四臂、任务、generation/history/native budgets、primitive conversion profile、hidden seed/cases、decoder、cell order、advantage/capacity gates、公共反馈、rollback、tool scope 与 timeout 政策与 V9 相同。模型、官方模板及其来源是明确的新绑定。
- qualification 仍需相同三个 Rust-node 任务全部正确、完整 usage、稳定身份与 terminal hidden/resource gate。跨版本 capacity/qualification 不能满足新的 schema、source、protocol、model 和 capacity digest 检查。main 的这些检查先于 engine 构造。
- 同一 cell 的 hidden evaluation 后直接结束，不再生成修复请求。完整模型答案保留；只允许既有规则对公开诊断文本限长，不能截断代码、移除公共案例或拼接自动答案。

## 模板拒绝的时序

官方 tokenizer_config 原字节与独立来源包 `63349b2836fe53c162c377a773e9785431eaa156` 一致。允许的 plain user/assistant string 分支去掉 Qwen2 自动 system 前缀，其余消息与分隔符按官方模板保持。

每一次真实 `/apply-template` 返回后，新 wrapper 在模型 generation counter 增加、tokenized completion payload 构造和 `/completion` 提交之前比较完整渲染结果。无论匹配与否都保存 request、观察到的 response、expected prompt 和判断。模板或 receipt 写入错误会阻止继续生成；不存在默认模板 fallback、消息补写或输出改写。新增构造失败路径关闭已取得的 owned engine。

静态/mock 控制覆盖匹配的完整初始与 repair 消息、不匹配拒绝及保留、构造 metadata 失败清理。实际模板行为尚未运行；静态通过不替代新容量阶段的真实验证。

## 独立 tokenizer 控制的来源

本次另外通过官方 GitHub 接口读取了固定 llama.cpp commit `620d2225cc436ab0b001e3200e590e3b286ef9ab` 的 source blob。三份原始文件与 producer 保留的源码，在 Git blob、SHA256 和字节数上全部一致：

| 路径 | 固定 Git blob |
| --- | --- |
| `tools/tokenize/tokenize.cpp` | `77b33c4a465779f75c06130939902c816d88aa6e` |
| `common/arg.cpp` | `8b302d5d77f0af164dd1aa57b64322a0e92aec7b` |
| `common/common.h` | `2cd6e2ec9858a91837746b8c392d59fbd2e18829` |

源码表明 tokenizer 模式显式将 parse_special 默认设为 true；stdin 默认处理反斜杠转义。新增 `--no-escape` 因而用于保持完整 JSON/code prompt 的输入字节。reference 输出用 `--no-bos`，rendered prompt 使用模型默认 BOS 行为；服务器分别使用 add_special=false/true。该 profile 不删除、插入或重标 token ID 来制造一致性。

每行有 1 个完整 reference response 和 4 个完整 request renderings 的 CLI/server 对照，合计 95 个，包含实际初始、两个 repair 和 reference-history 容量控制。超时、错误返回和 ID 不匹配保留各自输入摘要、stdout/stderr、原始 IDs 与成本并拒绝；完整条件要求 19 行、95 项全部匹配以及稳定来源、工具和模型、owned process 退出、0 generation。此增加只扩大模型适配验证，不改变题目或生成预算。

两个预构造 repair 容量案例及 allocation envelope **不证明任意生成历史都能取得三次机会**。实际 generation 前仍完整 tokenize 当前请求并预留全部 1536 输出；溢出终止 cell，保留已有成本。这一点与 V9 一致。

## 结论的实际边界

本次没有运行选定 GGUF，没有独立证明其量化重建来源，没有取得 V10 容量/资格成功，更没有得出语言或 Agent 效率优势。文件身份是当前可信实验编排中的来源记录，不是对恶意操作系统或物理宿主的 attestation。旧 V8/V9 结果及其成本不被重评。

注册停止规则仅允许这一个候选。若完整 fresh qualification 失败，保留成本且 main 不启动；本审查不授权继续调任务提示、重复相同候选或再筛模型寻找赢家。

机器可读独立记录及已核对的 producer 原记录位于 `experiments/hia_next_safety/toolstudy_v10_review_20261029/`。`PRECAPACITY_REVIEW.json` 的原始 SHA256 为 `1acfecebf7837ea7c622f438080f2d85062621e52531cf79d11b6fd3062def28`。后续容量审查应另存新记录，保留本次发生在任何新生成之前的范围与决定。
