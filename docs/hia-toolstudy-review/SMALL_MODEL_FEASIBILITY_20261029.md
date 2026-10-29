# 唯一后续模型候选：Qwen3-4B-Instruct-2507

## 结论与范围

2026-10-29 的只读研究支持将 **Qwen3-4B-Instruct-2507 / Unsloth Q4_K_M** 作为一个新的、独立预注册研究候选。协调者已选定此唯一候选；本报告不授权下载、装载或生成，也不授权在失败后继续调题目提示或筛选另一个模型。V9 保持原来源、原结果和全部成本。

候选依据是公开官方模型卡、量化发布者仓库、固定 llama.cpp 源码和资源约束。研究没有读取任务参考答案或根据具体正确编辑选择模型，没有下载权重、调用 tokenizer、编译 native 或提交模型请求。官方基准不能证明它在当前任务、Q4 量化、greedy 解码或 1536 输出预算下优于旧 7B；该问题必须由新资格阶段回答。

Qwen 官方卡将本模型定义为 4B、仅 non-thinking 的指令模型，并报告 coding/tool-use 改进。其原生上下文为 262,144；8192 是合法的较小上下文配置。官方推荐采样参数和 16,384 输出长度，与研究固定的 greedy/1536 条件不同；本报告不改变研究预算，也不把较长的建议输出误写成运行时最低要求。[官方模型卡](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507)

## 固定的获取与身份信息

| 项目 | 固定值 |
| --- | --- |
| 原模型 | `Qwen/Qwen3-4B-Instruct-2507` |
| 本次官方 config/template revision | `cdbee75f17c01a7cc42f958dc650907174af0554` |
| 量化发布者 | `unsloth/Qwen3-4B-Instruct-2507-GGUF` |
| 量化仓库 revision | `a06e946bb6b655725eafa393f4a9745d460374c9` |
| 唯一目标文件 | `Qwen3-4B-Instruct-2507-Q4_K_M.gguf` |
| 目标字节数 | **2,497,281,120**（2.497 GB；约 2.326 GiB） |
| 目标 SHA256 | `3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597` |
| 许可证声明 | 原模型与量化仓库均为 Apache-2.0 |
| 公开性 | 本次 Hugging Face API 返回两仓库均 `private=false`、`gated=false` |

[固定 GGUF 下载 URL](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/resolve/a06e946bb6b655725eafa393f4a9745d460374c9/Qwen3-4B-Instruct-2507-Q4_K_M.gguf)；[发布者固定模型卡](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/blob/a06e946bb6b655725eafa393f4a9745d460374c9/README.md)；[公开 LFS pointer](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/raw/main/Qwen3-4B-Instruct-2507-Q4_K_M.gguf)。研究只读取该 pointer 的三行元数据，没有读取其引用的权重对象。API 与 pointer 的字节数及 SHA256 一致。

只需单个目标 GGUF；不需要下载整个量化仓库、F16 权重或视觉 projector。现有 b11669 已在环境中，报告不要求下载另一套运行时。官方 config/template 的小文件已保存在来源包中。

量化发布者在其卡中声明上游为 Qwen/Qwen3-4B-Instruct-2507。固定 revision、公开发布者和目标 SHA 提供可检查的下载身份；**本次没有重建量化过程，也没有证明该 GGUF 恰好由上表中的官方 revision 生成**。该官方 revision 用来固定本次取得的 config/template，不能充当未取得的量化构建证明。实际下载仍需校验完整字节数和 SHA；随后还要核对嵌入模板、模型架构和 tokenizer 行为。

## 官方模板与现有实验的实质差异

固定 [tokenizer_config.json](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507/raw/cdbee75f17c01a7cc42f958dc650907174af0554/tokenizer_config.json) 为 **9,377 bytes**，SHA256 为 `a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3`，Git blob 为 `51c1be0d9192e7f6e6596de71d0f07d58fbc32ac`。保留的小文件已按 Git blob 与官方 API 逐字校验。

现有 V8/V9 的 `plain_qwen_template` 会自动插入 Qwen2 默认 system 段；本模型官方模板在消息不含 system 且没有工具定义时不插入该段。对研究允许的纯字符串 user/assistant 消息序列，模板仍按原顺序输出角色、正文和 ChatML 分隔符，最后追加 assistant generation prompt。因此，最小前瞻修改是新研究的 plain renderer 去掉自动 system 前缀；题目 initial、messages、历史、反馈和正确性门保持 V9 完全一致。单纯替换 GGUF 路径并复用旧容量结果不成立。

实际 GGUF 模板尚未读取；原模型官方模板并不自动证明发布者 GGUF 中嵌入的模板相同。新容量阶段必须使用独立 owned server 的实际 `/apply-template` 输出，并与冻结的官方模板规则及独立 tokenizer IDs 对照。不匹配时保留成本并拒绝，不重写模型输出或静默替换模板来通过门。

## 固定 b11669 的静态兼容证据

官方 [b11669 release](https://github.com/ggml-org/llama.cpp/releases/tag/b11669) 对应 commit `620d2225cc436ab0b001e3200e590e3b286ef9ab`。Ubuntu x64 CPU archive 为 17,851,611 bytes，发布 SHA256 `cf07c1c112d709bd67e522017471de57ed0ec8bea031d732c5422351c07f65ac`，与已固定的运行时身份一致。

本次直接读取该 commit 的 [qwen3.cpp](https://github.com/ggml-org/llama.cpp/blob/620d2225cc436ab0b001e3200e590e3b286ef9ab/src/models/qwen3.cpp)：36 层、hidden size 2560 明确选中 4B 类型。模型 dispatch 的 `LLM_ARCH_QWEN3` 构造该实现，CMake 将 `models/*.cpp` 纳入编译。[官方 server 文档](https://github.com/ggml-org/llama.cpp/blob/b11669/tools/server/README.md) 支持 CPU、显式 context 和 GGUF 自带聊天模板。

这是版本与源码层面的必要兼容检查；尚未证实选定 GGUF 能在当前固定二进制中成功装载、完成 JSON grammar 生成或通过实际模板/IDs 校验。没有为了取得兼容结论调用运行时或升级版本。

## 8 GiB 环境的资源估算

[官方 config](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507/raw/cdbee75f17c01a7cc42f958dc650907174af0554/config.json) 给出 36 层、8 个 KV heads、128 head dimension。单序列、8192 tokens、K/V 均 F16 时，原始 KV 元素占用为：

`2 × 36 × 8192 × 8 × 128 × 2 = 1,207,959,552 bytes = 1.125 GiB`。

加上量化文件大小，两个主要组件约为 **3,705,240,672 bytes / 3.451 GiB**。这是组件估算，**不是峰值 RSS 上界**；没有包括计算/批处理缓冲、图和 tokenizer 分配、库、allocator、操作系统与其他进程。8 GiB 共享 cgroup 不能理解成 8 GiB 空闲内存。

2026-10-29 04:06:51 UTC 的只读观测为 cgroup 上限 8,589,934,592 bytes、当时 current 8,287,039,488 bytes、`/tmp` 可用 1,814,286,336 bytes；V9 当时仍在运行。磁盘可用量小于新权重。协调者负责在 V9 退出后安排磁盘和单模型资源窗口，本报告没有删除、迁移或并发加载权重。正式资源准入必须基于届时环境及实际装载测量。

## 新研究的冻结边界

新研究只允许模型身份与其官方模板/tokenizer 适配这一项预先声明的变化。四臂任务内容、公共反馈、hidden 隔离、实际编辑接口、decoder、接受门、8192 context、1536 输出、greedy/seed、线程数、最大提交与 repair 预算沿用 V9。模型卡建议的采样 recipe 不得被静默引入。

顺序为：冻结新来源及身份 → 独立静审 → fresh 19-row 实际容量与 reference 控制 → 独立核对 → fresh 资格 → 只有资格达到原门槛才能主实验。不能继承 V9 容量或资格；若本候选失败，保留全部请求和成本，不调整题目提示、扩大预算或继续换模型筛选。

原始公开元数据、固定官方小文件、源码证据和机器可读范围在 `experiments/hia_next_safety/small_model_feasibility_20261029/`。其中 `FEASIBILITY.json` 区分已读取的身份信息、推导的组件内存和未完成的实际验证。本成果不构成模型成功、语言比较、性能或全局安全结论。
