# HIA 契约整合：实际源码与完整证据

**有限实现已经整合；六项广义目标没有全部关闭。** 本包的本地资格结果为 True，独立审计结果为 True。旧性能和 Agent 实验没有作为当前版本重新测量。

## 实际执行身份与分母

本地实际检出并执行的 GitHub 提交为 817713b163b6812a6516179951412b4a6c93ae2b，tree 为 6a034a0ed5d001823dc26683e1677520d4b510e2；本地结果没有重标成另一提交。源码与外部输入前后不变分别为 True、True。

源码交付在 [PR #329](https://github.com/TrillionniumFoundation/Hepta/pull/329)，该源码分支保持冻结。本证据目录由基于此源码的独立分支 codex/hia-contract-evidence-20261027 作数据提交；证据提交没有自包含自己的 SHA，也没有声称对数据提交重新运行完整测试。实际受测身份始终是上述源码提交。

本地完整 Python 回归 2718 项，Rust crate 54 项；完整原始结果和日志在 qualification.json。六个门禁及关键模块覆盖属于这一轮；覆盖清单不是额外测试分母。

同一源码的 verified CI 跑了 219 项选择性测试，失败 0、错误 0、跳过 0。不能与完整回归相加。C++ scope 在 1121 个输入上分别执行 C++ reference、Hepta→Rust、Hepta→C、源程序直接 LLVM，共 4484 次正向调用；每路径 3180 次分配/释放、398 次拒绝。第四条路径不是 standalone HIA refinement 证明。

七主机 C ABI 记录 2534 次 foreign calls、21 个类型负例和 7 个错误结果负例。七个原始 ZIP 都保留；其中只有报告与日志，没有七平台的 native binary。Windows 的 CRLF 文件身份差异另有真实对照记录。范围是既有有限 C ABI，不是新 HIA runtime 在所有平台通过。

完整远程资格状态仅按已捕获的 API 快照记录：40559504509: pending/None; 40559493121: in_progress/None。其状态与本地全量、219 项选择性 CI、七主机结果分别记录；运行中或失败不转换为通过。

## 新的递归 NDU 对照仍没有收益优势

| 策略 | 总净成本中位数 ms | 加入共同 setup 与自身 native 构建的摊销中位数 ms |
| --- | ---: | ---: |
| fixed-stop | 277.178 | 404.456 |
| fixed-fold | 536.649 | 663.926 |
| fixed-selected | 276.814 | 404.092 |
| light | 276.214 | 403.492 |
| ndu | 358.105 | 4791.474 |

这次实际闭环的 statistical_superiority_established=False，NDU 比 light/selected-fixed 成本低的描述性标志分别为 False/False。这些是当前源码新 RESULT 的数值，旧 a4ab CI 成本只在历史目录保留。完整 RESULT/PROTOCOL、episode 账本、失败控制及源码身份在原始 ZIP 和 ci/integrated 内保留。NDU 只是 advisory；安全与发布权限独立。成本包含实际记录的编译、提案、证明、拒绝和执行；明确排除项原文为 ["toolchain installation", "preexisting dependency source cache acquisition", "build manifest final write and build process startup"]。不能称整机冷启动或完整开发成本。

## 六项范围

| 项目 | 已落实的有限能力 | 仍待关闭 |
| --- | --- | --- |
| 1 语义收敛 | 同一 Core 准入；两种明确证明 profile；fold-constants 与 optimize 分离；两种 NDU 桥独立 | 通用源语言前端、源/后端 refinement 仍非本次证明 |
| 2 资源/Rust | byte-owner CFG/内部调用、owner 返回、调用内借用、失败/停止账本；C++ 词法清理 | 返回/逃逸借用、通用组合、完整取消/展开等价性 |
| 3 优化验证 | 无环整函数值/首次 trap 证明；保持 CFG/资源/调用骨架的分段证明 | 一般资源、循环 CFG、并发/内存变换及后端证明 |
| 4 NDU | 原始固定版本算法、有限动作、相同预算对照、实际成本 | 增量收益未建立；不代表全局最优 |
| 5 迁移/ABI | 有限完整 C/C++ fixture；库复用契约；实际主机 C ABI | 大型任意项目低成本迁移、任意 C++ ABI/foreign 安全 |
| 6 运行时/指令 | 封存代码、lease、回滚、有界取消；空状态切换；独立有限 x86 搜索 | 真实净收益、活资源状态迁移、ISA 搜索在线发布 |

Adaptive 的自动收益、自动盈利选择和一般活 owner/state 迁移标志均为 false。历史后台正向发布用合成成本检查生命周期，不能当作真实加速。历史有限 x86 字节最小也不是运行时间或全局最优。

## 保留失败与历史边界

第一次整合源码 a4ab878 的 run1 实际运行 2716 项，产生 10 个 failure 条目、0 个 error、0 个 skip，整轮失败。3 个测试方法揭露了同一键预检缺陷：预检用 json.dumps 转换字典键，提前进入完整 encoder。修复使用经过预算和有限值检查的精确内建键转换，保留原拒绝断言，并补上实际 wire 字节/极端键对照；39 项修复相关测试单独记录。历史目录完整保留失败 run1 的非缓存文件、调用/日志、独立审计、a4ab CI、原 source bundle/发布记录及修复日志。a4ab 上通过的选择性 CI/host 结果不重标为817，也不抹去其全量失败。

ci/historical-e147 保存旧源码 e1473a4 的完整 job log、选取报告、API、ZIP 成员清单与诊断：50/50 子门禁和 2640 项测试通过，但最终源码快照变化使整轮失败。前后可得清单显示新增 Cargo target 文件，原 checker 自己未保留最终清单的限制亦保留。当前整合已将 Cargo 输出放到仓库外，并保留严格快照检查。旧 274 MB 原始 ZIP 不重复装包；其路径、GitHub artifact ID、稳定 API URL、大小和已复验哈希列于 raw-evidence-manifest.json。

historical-controls 保留冻结前缺少显式 Clang 配置导致跳过的尝试、签名不匹配的 fixture 失败及修正后通过日志。这些不是当前完整回归的额外测试。仓库已有 evidence/hia_ndu_pipeline_20261027 和 experiments 中 PR325 的历史压缩证据保持原样；不重复打包或重标其性能、Agent 结果。

## 包内容与重建

qualification.json 是逐字节原始本地最终报告；audit.json 是独立重计数/哈希审计。acceptance.json 与 publication-provenance.json 分别说明验收范围和身份。raw-evidence.tar.gz 保留 647 个普通文件，解压前字节总量 51370497；每成员重开并核对实际字节、SHA-256 和模式。构建缓存及大型已安装工具链未打包；实际 Linux Rust oracle、两种实际 NDU executable、原始源码/锁文件/构建输入和身份收据保留。瞬时 runtime generations 已按生命周期销毁，不能声称其字节在包中。

tested-source.bundle 的 SHA-256 为 4c836863f4fd76687a396edae8503e511095b0a9f8d27f284acf4db825f397b8，包含实际受测 HEAD，要求现有仓库先有父提交 a4ab87889616925306b84f9699316d1a850c183d。它不是整个仓库的自包含备份。旧 a4ab bundle 也在历史目录保留，仍要求它原来的两个父提交。先 git bundle verify，再从 bundle fetch HEAD，可检出 817713b163b6812a6516179951412b4a6c93ae2b。完整实际 argv、环境和工具身份在 frozen-plan/qualification 记录中。

raw-evidence.tar.gz SHA-256：06e0766d59422407b5d249b84934eeb332687c27dea7938bf71c190a96ce8597。打包不执行测试、基准或模型推理；哈希证明本地文件一致性，不能认证恶意宿主自造观测。验证器、SMT 编码/Z3、编译器、loader、硬件与可信测量仍是明确边界；全语言 soundness、普遍 Rust 性能优势、绝对 foreign 安全和全局最优均未建立。
