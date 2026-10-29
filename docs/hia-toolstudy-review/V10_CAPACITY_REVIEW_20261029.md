# V10 实际容量独立审查：允许 fresh qualification

**决定：ALLOW fresh V10 qualification；main 继续 HOLD。** 许可仅适用于冻结来源
`11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0`、其固定模型与工具身份，以及本次完整
capacity SHA-256 `28a6461f287b473b3c7e0683fb638c1504d913440940741a229e57b35fab79d6`。
模型必须重新完成预登记的三个 Rust-node 任务，全部通过 public、resource、terminal-hidden
门且具备完整成本和稳定身份后，才可能获得主实验资格。本次审查不修改此前任何失败结果。

## 实际证据与独立核对

Producer 的零生成容量记录位于 `/tmp/hepta-next-agent-v10-capacity-01`。
19/19 个真实 reference 控制和 95/95 个独立 CLI/tokenizer 对照已完整结束，generation 为 0。
容量阶段 wall time 为 **68.212309461 s**，其中 CLI 调用记录合计 **38.050519589 s**；
后者已经包含在前者内，不能再次相加。Reference 是人工工程控制，不计模型正确任务。

独立审查脚本没有导入生产评估器，没有重新执行模型、tokenizer、编译器或 native 产物。
它读取 463 个 JSON，流式重新计算 53 个不同路径的文件身份，包括固定模型、运行时、
编译器和原生可执行文件；185 个绑定源码逐一与当前文件、冻结 Git blob 和保留 snapshot
核对。首次完整审查退出码为 0，没有失败审查尝试或随后修改 producer 结果。

| 核对内容 | 实际数量与结果 |
| --- | --- |
| 原始 registered rows | 19，ID、顺序及 task/arm 对应一致 |
| 不变的任务输入 | 19 组 query、initial messages、reference 与 V9 逐项一致 |
| 公共执行观察 | 54，stdout、逐行观察值、expected 和资源/VM gate 相符 |
| 终端隐藏观察 | 472，stdout、逐行观察值、expected 和资源/VM gate 相符 |
| 原生二进制 | 19 个 ELF，其路径、大小、SHA-256 与实际构建记录一致 |
| HIA 中间产物 | 8 个 object、8 个 Core，实际文件及编译绑定一致 |
| CLI 原始 IDs | 95，stdout 重新解析所得 IDs 与 server IDs 逐项相等 |
| 完整模板渲染 | 76，每次 request、observed response、expected prompt 和容量记录一致 |
| 来源及工具身份 | 185 个源码三重核对，模型和运行时初始/结束身份相同 |
| 生成与退出 | 无 transport generation 文件；producer generation 为 0；owned PID 已不存在 |

95 项 CLI 分别来自每行一个完整 reference response 和四个完整 request renderings。
审查还核对了 `--no-escape`、reference 的 `--no-bos`、实际输入 UTF-8 摘要、CLI return code、
原始 stdout/IDs、特殊 token 政策和每次成本；没有删除、插入或重标 token ID。

初始最大 **2783 tokens**；完整参考答案最大 **1059 tokens**；实测 repair 加完整输出
reserve 最大 **5023**；登记分配包络最大 **7263/8192**。所有请求保留 **1536** 输出容量。
这些登记控制和包络不证明任意后续模型字符串都能获得三次机会。每次实际 generation
仍完整渲染、tokenize 并检验上下文上限；溢出须结束该 cell 并保留成本，不能截断答案。

## 实际 GGUF 模板与官方文件并非全文相同

实际 GGUF 嵌入模板有 4051 个字符，固定官方模板有 2630 个字符。嵌入模板增加了
`last_query_index` 以及 assistant reasoning／`<think>` 内容处理分支；这不是仅空白差异。
来源文件和实际运行时属性分别保留了各自的真实模板身份。

本次许可依据是注册 plain user/assistant 请求的 **76 次实际完整渲染** 均与官方 plain
分支逐字符一致，以及冻结实现会在 **每次 generation 提交之前再次强制同一检查**。
它不是对两个模板在所有输入上等价的断言。若后续模型文本含 `</think>` 等内容而触发
嵌入模板改写历史，原 guard 必须保留差异并在 `/completion` 提交前拒绝；不允许移除
标记、补写消息、换模板或自动修复模型答案来继续该次请求。独立记录包含精确模板 diff。

## 退出、成本与信任边界

Producer 的服务调用记录为 101 次 health（其中启动未就绪 100 次）、1 次 props、
76 次 apply-template、190 次 tokenize。启动未就绪是保留的真实轮询，不重标为实验失败；
其后的非 health 服务请求全部成功。没有 completion 请求或生成 transport 文件。
Producer owned-exit 回执与 reviewer 当前 `/proc` 检查都未发现该 owned PID 仍在运行。

固定模型取得单独记录 **57.295566572 s**、2497281120 bytes，SHA-256 为
`3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597`。
下载成本不属于上述容量 wall time；参考控制、资格和主实验也各有独立成本范围。
这不包含完整工具开发、模型训练或人工审查成本。

本审查只支持可信实验编排内的来源、身份、原始观察和成本一致性，不是宿主硬件 attestation、
对恶意内核的保证、语言健全性证明或模型效率优势。选择这个候选是此前失败后的前瞻跟进，
不能把结果视为无选择偏差的模型样本。保持原单候选停止规则和 fresh 3/3 资格门。

独立回执 SHA-256 为 `fd3a86b57e0798e71ea4796fba7ff65153d37b4bcb4e7cf6a46bb35188915fb9`。
机器可读记录、实际审查脚本、原始 producer capacity/取得/退出回执与模板差异位于
`experiments/hia_next_safety/toolstudy_v10_review_20261029/capacity/`。
