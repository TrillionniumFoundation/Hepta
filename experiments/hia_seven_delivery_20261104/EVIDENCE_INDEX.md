# 证据索引与恢复范围

日期：2026-11-04。本索引中的原始材料固定于 [证据提交 84c65f560452c34f2b65439070adb08bab33cd14](https://github.com/TrillionniumFoundation/Hepta/commit/84c65f560452c34f2b65439070adb08bab33cd14)，证据树为 09ef2c134843a844359b2e91a4b1f9953f65b2d9。该提交承载审查材料；它不是一次新的测量源码身份。

以下七类主要材料及第八节 Agent 材料均已读取其确切版本的目录、README、manifest 或脚本接口；所指 blob 在上述提交中保持一致。原始测量提交、GitHub App 发布投影和证据提交分别保留。恢复文件、核对哈希和重新执行实验是不同操作；本文只转录已经发布的恢复／核验命令，不承诺在任意机器上独立重放所有实验。

## 1. 主要材料总览

所有目录链接固定到上述证据提交，避免后续分支移动改变本索引所指材料。

| 材料 | 用途与主要来源 | 完整性边界与读取入口 |
|---|---|---|
| [完整组合 r1/r2/r3](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_composition_20261104) | 三轮组合的原始测量、失败、注册、31 条命令回执、AOT、NDU、迁移与生命周期结果；三轮使用不同冻结提交 | 每轮 1431 个归档成员、1693 个仅索引项、27 个独立 gzip 成员；读取各轮 MANIFEST.json、INVENTORY.jsonl.gz、RESTORE.txt |
| [原始源码历史与独立 AOT](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_source_history_20261104) | 保存真实本机提交历史，以及单独在 8ce43b8d 上执行的 AOT 原始档案 | 两个 Git bundle 都有 f2b76f5 前置对象要求；AOT 档案没有删除成员；读取 README.md、SOURCE_HISTORY.json、MANIFEST.json、AOT_MEMBERS.json |
| [最终源码的原生 CI](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_native_ci_final_20261104) | 17 个实际宿主 CI 产物；对应最终发布投影 e3b380bd 和树 9530e9fe | 2133 个成员中完整保留 1983 个 UTF-8 文本／源码成员；150 个原生二进制仅保留原始尺寸和哈希 |
| [最终 CI 总验收](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_final_ci_20261104) | 八条最终工作流的终态；1781 项回归及 562 项安全边界测试的原始结果 | 完整保留两份 JSON 回执及回归日志；其他 ZIP 成员只保留目录元数据，不将该选择性档案称为所有原始 ZIP 的完整副本 |
| [旧版 CI 失败](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_ci_failure_review_20261104) | 9435f048／原始 98bdbe9f 上的失败回归与后续失败步骤 | 保留完整结果 JSON 和测试日志；原始 ZIP 身份记录于 MANIFEST.json，后来的修复不覆盖本次失败 |
| [准备与集成控制](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_preparation_20261104) | 离线依赖缺失、依赖准备、GSL 控制修复、旧／新 factorial 接口及身份检查的过程记录 | 26 个原始流或报告逐个 gzip 保存，包含空流；不是某一个后来干净提交的完整组合验收 |
| [独立 Safe Core 证明研究](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_safe_core_transport_delivery_20261104) | 独立源码 ce1dd749 的证明准备、诊断、完整 r5 失败和源码测试 | 23 个保留根目录的审查材料；37 份 .olean 内容只列索引；不是成功的独立二进制证明重放包 |

共同来源映射见 [PROVENANCE.json](PROVENANCE.json)。最终汇总同时见 [RESULTS.json](RESULTS.json)；具体实验终态以相应原始 RESULT、验收回执与工作流终态为准。

## 2. 完整组合：原始结果、外层观察与 NDU 成本

### 源码身份

| 轮次 | 原始测量提交 | 对应 Git 树 | 验收边界 |
|---|---|---|---|
| r1 | 87106dd3f965de88cfa11616d2e9c63ac3baa5a3 | 60a75bf87cca191aa932e2d83bf8bb65141f089a | 核心测试出现 1 项跳过，零跳过门槛失败；其他阶段原始结果仍保留 |
| r2 | 98bdbe9f859b5caf95356fbfb1254448d9b583d0 | 514b607bd5661abe5ac516ee77d80638c939749c | 当时声明的组合通过；更广 CI 随后发现旧源代码回执兼容错误 |
| r3 | 3707b871ecbe563233ee9a3b69299fc627408936 | 9530e9feccf0077696d2e94746fda6bfb6854417 | 扩展后的冻结组合通过；AOT 和 NDU 的负面研究结果仍保持原样 |

每轮的 MANIFEST.json 记录确切源码与包生产器身份。三个 manifest 的 SHA256 分别为：

| 轮次 | MANIFEST.json SHA256 |
|---|---|
| r1 | ec9524e8ee05736d88fd107aa334a895cf48c6e6830fac59c1f67dee08e29154 |
| r2 | 4fd7fcc89ad71c2685d947bb79c41d6ff5358157b59f728617a491142552e9d7 |
| r3 | 9f1e997b15e72eeba24ecde7df87c1de4e1dad41f0d0f2ffa14285108c59114b |

### 保留内容与遗漏项

每轮保留全部 31 条命令回执、原始测量流、报告、注册、日志、生成的 C/C++/Rust 驱动及汇编；另保存实际执行的外层资格检查与 NDU 控制器的冻结 Git blob。归档里的 evidence/ 对应原始证据路径，drivers/ 对应冻结源码片段。这些片段不替代完整源码历史包。[包格式及范围](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_composition_20261104/composition-r3/MANIFEST.json)

原生可执行文件、Cargo 编译产物、依赖／上游重复源码等按清单规则省去内容，保留路径、尺寸、哈希和原始留存位置。其中上游 crate 快照为 115 个文件、1406860 字节；生成的 Hepta adapter 已与冻结 Git blob 绑定。hepta-private-ci 的实际仓库可见性为 public；早期 v2 字段中的 private 是历史过滤标签，不是仓库当前可见性的断言。[范围修订](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_composition_20261104/PUBLIC_SCOPE_R3_ADDENDUM.json)

外层启动脚本、完整 invocation、outer receipt、stdout 和 stderr 位于另一个无损文件 OUTER_OBSERVERS_R1_R2_R3.tar.gz，共 15 个原始文件；其对应 JSON 保存逐文件哈希及内外计时身份。该 capsule 补充各轮证据目录之外的原始文件。[外层观察器清单](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_composition_20261104/OUTER_OBSERVERS_R1_R2_R3.json)

AUDIT_R2_NDU.json、AUDIT_R3_NDU.json 与取消恢复范围文件是从原始结果生成的审查摘要，不覆盖原始输入。首次派生摘要的语法错误另记于 POSTPROCESSING_R3_FAILURES.json；它属于后处理失败，没有被记作实验重跑。最终 NDU 的九个策略 episode、六个原生 session、九次原生请求和三个从未启动 session 的 episode 应分别读取；模型 gap 与实测完整成本不能混为同一指标。

### 已发布的恢复说明

[RESTORE.txt](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_composition_20261104/composition-r3/RESTORE.txt) 给出的步骤是：按 manifest 顺序连接编号 payload 的压缩字节，得到多成员 payload.tar.gz；解压完整多成员流得到 payload.tar；在提取前核对每个压缩片、解压片、完整 TAR 以及 INVENTORY.jsonl.gz 中每个普通成员或受约束后向硬链接成员。

该说明没有给出一条可照抄的 shell 恢复命令，因此本索引不另造命令。目录内已发布 verify_public_composition_package.py；其命令行接口接受一个或多个包目录作为位置参数，并在临时文件中核对归档，不执行归档中的代码。既往独立校验回执为 PUBLIC_PACKAGE_VERIFICATION.jsonl 和 PUBLIC_PACKAGE_R3_VERIFICATION.jsonl。归档恢复成功不改变 r1 的失败，也不把 r3 的性能缺口变为通过。

## 3. 原始源码历史与独立 AOT 档案

[README](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_source_history_20261104/README.md) 与 [SOURCE_HISTORY.json](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_source_history_20261104/SOURCE_HISTORY.json) 分别保存：

- 本机集成历史，直到原始提交 3707b871ecbe563233ee9a3b69299fc627408936。
- 独立 AOT 测量源码 8ce43b8d8f4bf415387ebf4c52435939cd4ad6d2，以及其证据提交 4aedbdfc029e9d77dcf319626e8cc332207c0ff0。
- 独立 AOT 原始 TAR 的全部成员；该 TAR 为 39475200 字节，SHA256 为 ae47856d8672670fe6a4cd3f10d341ba8d4df172b5813a067ef8c484bef97310。未删除、改写或挑选其中的失败记录。

此处 AOT 是独立的 303/372 结果，不能改名为最终 r3 的 293/372 实验。两个 bundle 都依赖 f2b76f5741c83822be2e12cf5a50b50a8d27b96a 及其可达对象；它们不是脱离前置历史的完整独立仓库。

在该材料目录中，README 已文档化的恢复命令为：

~~~sh
python3 RESTORE.py --output /tmp/hepta-retained-20261104
~~~

这会校验分片、组合各编码文件、在需要时解压 gzip，并验证恢复文件的原始尺寸和 SHA256。它不提取 AOT TAR，也不执行任何恢复出的程序。输出应使用新的目录。

README 另列出了在已经含前置对象的 clone 中验证和导入原始历史的命令：

~~~sh
git bundle verify /tmp/hepta-retained-20261104/original-sources-through-3707.bundle
git fetch /tmp/hepta-retained-20261104/original-sources-through-3707.bundle HEAD:refs/heads/review/original-3707
git bundle verify /tmp/hepta-retained-20261104/independent-aot-original-source-history.bundle
git fetch /tmp/hepta-retained-20261104/independent-aot-original-source-history.bundle HEAD:refs/heads/review/aot-original
~~~

这些是供审阅者执行的已发布说明；本索引编写过程中没有执行它们。导入 bundle 只恢复 Git 对象与引用，不证明实验可在不同宿主上获得相同耗时。

## 4. 最终源码的实际宿主 CI 材料

[README](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_native_ci_final_20261104/README.md) 将 17 个原始 CI ZIP 绑定到发布投影 e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4、树 9530e9feccf0077696d2e94746fda6bfb6854417；它与本机测量原始提交 3707b871 的源码树相同，但 CI 与本机组合的工具链分别记录。

材料覆盖七组声明的 C ABI／stb_divide Rust 后端路径、七组未修改 nlohmann/json 的 C++／Hepta 桥路径、两个 Linux 宿主上的捕获 C 到直接 HIA LLVM 路径，以及有限独立 AArch64 corpus。范围不是全部 C/C++、任意 ABI、MMIO、DMA 或一般并发安全。

所有原始 ZIP 的尺寸和 SHA256 先经过核对。公开审查包完整保留 1983 个文本／源码成员；150 个原生二进制只有原始尺寸和内容哈希。相同字节成员使用后向 TAR 硬链接保留，清单仍记录全部原始成员身份。

这里的五个 .gz 分片是“同一个 gzip TAR 的有序原始字节块”，并非五个可分别解压的 gzip 文件。[ARCHIVE_PARTS.json](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_native_ci_final_20261104/ARCHIVE_PARTS.json)

在该目录的 Python 3 环境中，README 的核验命令为：

~~~sh
python verify_retained.py
~~~

该程序按清单连接分片、检查整体与每个保留成员的哈希；不把 TAR 提取到文件系统，也不执行下载的程序。它不能核对包中没有包含的原生二进制内容；这些内容由原始 ZIP 身份和二进制清单追踪。

## 5. 最终 CI 总验收与旧版失败

### 最终源码

[最终 CI README](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_final_ci_20261104/README.md)、WORKFLOWS.json 和 SUMMARY.json 记录 e3b380bd 上八条工作流的实际终态。完整原生回归 1781 项、六结果安全边界 562 项均完成且没有失败、错误或跳过。

selected-qualification-receipts.tar.gz 完整保留两份 JSON 回执和原生回归日志，共三个选择成员；文件为 375920 字节，SHA256 为 ed3179def2e784fce4207b4c71d8c5c62e4dd825ed258832bcc9f0cb91846338。非选择成员只在 ARTIFACT_DIRECTORY_AUDIT.json.gz 中保留目录元数据。实际宿主材料另见上一节。

该目录没有文档化的单条恢复 CLI；按 SUMMARY.json 的归档和成员身份进行文件核对。CI 回执明确不授予整种语言健全性、绝对资源安全、全局最优、一般并发内存安全或广泛性能优势。

### 旧版失败与针对性修复

[失败审查目录](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_ci_failure_review_20261104/README.md) 对应原始 98bdbe9f、投影 9435f048、树 514b607b。回归执行了 1777 项，出现 1 个 error、0 个 assertion failure、0 个 skip；被跳过的准备步骤之后，捕获应用步骤也失败。这些结果不算通过。

retained-regression.tar.gz 保存完整的 429480 字节结果及 333200 字节测试日志；归档 SHA256 为 dd451f67d05f7e1a98802bd2fa0b1e501100ef8e8dfadffb1199ac57a81c0720。MANIFEST.json 绑定原始 GitHub artifact 的 ID、尺寸与完整 ZIP 摘要；没有声称在这个选择包中保留完整原始 ZIP。此目录同样没有文档化的单条恢复 CLI。

补充材料 [回执兼容修复](https://github.com/TrillionniumFoundation/Hepta/tree/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_ci_receipt_compatibility_20261104) 已包含在实现历史中，不替代七类主包。其中 raw-evidence.tar.gz 保留另一条原始 562 项失败流程的完整 CI ZIP、两次失败基线、44／45 项修复检查、实际工具角色以及路径事件的 before/during/restored 记录。该包的 MANIFEST.json 列出 27 个成员和零排除文件；它是针对性修复证据，不是一轮新的完整组合验收。[该包 README](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_ci_receipt_compatibility_20261104/README.md)

## 6. 准备与集成控制的保留范围

[准备材料 README](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_seven_preparation_20261104/README.md) 说明了 26 个逐文件压缩的原始流／报告。MANIFEST.json 同时记录压缩内容和解压原文的尺寸、SHA256，空流也单独保留。

该目录包含 f2b76 基线在缺少离线 Cargo 依赖时的失败，后续锁定依赖准备，以及 unique-owner、GSL、旧／新 factorial 和身份控制的成功与失败。基线有自己的冻结身份；后续准备阶段测试使用尚未冻结的集成文件，不能追溯归到 3707b871 的干净源码上。

最早 unique-owner 三项测试的详细临时目录没有作为完整 native transcript 留存，公开材料对此明确说明；完整持久化结果应以之后各轮组合包为准。这里的 unit 与接口控制没有进行模型推理，也不是 Agent 生产率结果。

该目录只文档化逐文件 gzip 和 manifest 绑定，没有提供单条恢复 CLI。恢复原文时需同时核对压缩摘要和解压后摘要。没有把未知人工成本和历史获取成本记为零。

## 7. 独立 Safe Core 证明研究

[README](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_safe_core_transport_delivery_20261104/README.md) 对应独立 [PR #648](https://github.com/TrillionniumFoundation/Hepta/pull/648)，原始测量提交 ce1dd749ffaf7b0905e55473164f79741facb08c、发布投影 cbc3925ecfae120b1dd471a60499416e139db2e6、树 92fe27daac9d2b2e2c76d0fa7a79362445b7fc4b。其测量基线是 958d47577dce36994f5f9e1484ac50d34d36b65b，不能替换为后来 bbd 或 adf 的未验收组合。

最终完整 r5 在 CertPart03 运行 60.000790060 秒后超时；完整墙钟时间含准备为 339.817342764 秒。前四阶段通过，后六阶段与最终独立重放未到达。接受结果应读取 acceptance-outcome.json；source-manifest.json 是源码交付身份记录，不能把其较早阶段状态当作最终接受结论。

审查包保留 23 个证据根目录的 409 个证据文件、77 个按内容去重的实际 Lean 源码对象、7 个持久化源码测试 job 和原始 55776 字节 Git bundle。37 份 .olean 内容被省去，原始路径、尺寸和 SHA256 留在 review-inventory.json；完整原始证据根目录继续保留。包本身没有变成成功的独立二进制证明重放。[review-parts.json](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_safe_core_transport_delivery_20261104/review-parts.json)

下载该目录的全部文件后，README 文档化的恢复命令为：

~~~sh
python restore_review.py --output /absolute/path/to/a/new-directory
~~~

它核对六个 ZIP 分片、完整 ZIP、包含的 evidence/source/job 内容、支持清单与原始 Git bundle，然后写入新的输出目录。它不会编译 Lean，也不会让超时或未接受的运行取得证明权限。完整 ZIP 为 2747867 字节，SHA256 为 24f6f034d8a7f08195a695f4d286146592ef5874f31ddd522aa098faa54b45f0。

所有十二项更广的生产语义义务仍未证明；生产 native、性能和初始化消除权限仍为 DENY_ALL。新的上游研究基线与本分支没有完成组合验收，见 [上游资格边界](https://github.com/TrillionniumFoundation/Hepta/blob/84c65f560452c34f2b65439070adb08bab33cd14/experiments/hia_safe_core_transport_delivery_20261104/upstream-qualification-boundary.json)。

## 8. Agent 主实验：完整终态与成本

单次主实验的材料见 [Agent 原始记录与成本](../hia_agent_edit_factorial_20261104/README.md)，对应原始测量源码 `3707b871ecbe563233ee9a3b69299fc627408936`、树 `9530e9feccf0077696d2e94746fda6bfb6854417`；发布投影仍为 `e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4`。

主实验共 32 个终态单元、63 次尝试，正确交付仅 1 次，来自 Qwen 的 Rust 补丁臂；HIA 整文件、Rust 整文件、HIA 补丁、Rust 补丁四臂的结果分别为 0/8、0/8、0/8、1/8。三次准备均为零生成，前两次准备保留成本和原始输出，没有充当独立主实验。

`OBSERVATION.json` 保留原始状态、回执派生的失败类别、八个模型／语言／接口分组、token 完整性与原始臂分摊。单元类别合计为正确 1、JSON／协议 2、补丁准入 4、源码／编译 15、公开验证 8、超时 2；尝试类别合计为 63。两次超时的输出 token 未知，因此两个补丁臂及整体输出总量均为 null，已知小计没有删去。零正确臂的每次正确交付成本为 null。

`COSTS.json` 将三次准备外层、唯一主实验外层、最终 gate 与单独桌面放行的六段非重叠计时分开，合计 4,642.117869822 秒；源码工作区物化 8.618618349 秒另列。四个描述性 solo 臂分摊存在公共成本重叠，不能相加。主机未独占；等待、人力、历史下载、能耗和整个经济成本并不完整。完整 attempt 墙钟没有单独测量，原始请求、构建及验证的嵌套计时仍保留，没有相加冒充完整 attempt 成本。

三个原始输出根目录和三个 outerdriver 根目录的所有文件均保留：请求、响应、尝试编辑、生成的 native candidate、编译／公开／隐藏 oracle 回执、身份、清理、失败和原始 driver。归档共 1,150 个成员；重建 TAR 为 105,441,280 字节，SHA256 为 `3f0b0837abb152de545f3967aed87863fa16119ff25bfb7a09e60789bae1fe61`。TAR 经无损 XZ 编码后为 2,531,628 字节，分为四片；包另含最终注册源码。GGUF 模型权重未加入，模型与外部运行环境仍须按记录的身份获取。

从该材料目录执行 README 已文档化的恢复命令：

~~~sh
python3 RESTORE.py --out /absolute/new/directory
~~~

该命令校验分片、完整 TAR 和每个成员，在新的目录恢复文件，不执行归档中的代码。`MEMBERS.json` 保存所有路径和哈希，`PUBLIC_SAFETY_SCREEN.json` 说明有限的公开检查范围。包已实际恢复校验，不代表重新执行了模型或隐藏 oracle，也不改变任何失败评分。

原始 RESULT SHA256 为 `c4e50393d162639662c2274cc405a76837d478f21146c590749de48fa26cbc42`；终态回执 SHA256 为 `3a362a14d5d1ef5d7f2d4c75b78bbb12d1c593ac22dee208b96d74f5140d0c5b`。四个实际会话均回收，源码、运行时与注册身份保持一致。该四任务小模型试点没有建立真实外部维护或稳定生产率优势。

## 9. 如何使用这些证据

先按 PROVENANCE 和具体 manifest 确定源码身份，再判断材料属于原始测量、派生审查、源码历史还是有限 CI。需要读原始结果时，按各包自己的格式恢复或核验；不要对不同格式的分片混用命令。

“内容逐字节保留”只覆盖各清单明确标为已包含的成员。索引项、被省去的二进制、依赖获取、人力以及未测生命周期成本均有各自边界。工具和宿主不同的 CI、本机组合与独立研究不互相替代，失败记录也不会因文件恢复成功而改写。

