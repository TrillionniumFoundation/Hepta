# HIA 全量原生重写审计（2026-11-12）

## 当前结论

**整套尚未闭合；禁止把选定组件通过解释为整套通过。生产入口尚未切换，旧整套尚未清理。**

本次检查对应恢复分支的已验证父提交 `7d94fc8e3d2ec92429b887d1f59a58ad55a76866`，完整树 `7533edc6c5b1cd4ed032239ad76b87058af785ef`；下一批源码及证据由本提交保存。独立原始参考固定为 `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`，不得随开发分支漂移。读取时主分支为 `5831f52fada45e076f8f68f198a15c0585e6104f`。并行 PR #893 仍 open/unmerged，头为 `9a12b6cd13ba103fc7495aa8d5decf8cd5948143`；本分支没有合并或借用其验收结果。

## 原始完整回归仍为 FAIL/HOLD

原始完整回归共 **4,157 项：187 errors、1 failure、18 skips**。原始报告、stdout、stderr 及其他材料保存在 `review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/qualification/raw-originals.tar.xz`。压缩包 Git blob `2aae1a9fc536d476cf02f32d40b7c3a34335cf34`，666,816 字节，SHA256 `5595532d3fc1d8e8b5021236b30217b85ec53a1452d4b23a98b378996e67cee5`。

独立回读报告 `4d0d2547ab43a21b808ca10e180a7b5038eacdbb` 已完整取回，记录全部124个归档成员、123份原始文件的8,688,721字节及全部2,798个原始源码文件/模式的核对。错误归组文件 `a5f15e07768ae19059ff2f56bef7dafb305b49bb` 亦已完整取回；它按原始 traceback 最后非空行归组，没有猜测删除责任。

| 原始记录分组 | 数量 |
| --- | ---: |
| 旧调试桥绝对路径不存在 | 1 error |
| 有界普通文件读取失败，OptimizationRejected | 19 errors |
| 无法以 no-follow 打开原生工件，DifferentialRejected | 2 errors |
| raw-model 前置 release/hia-ndu-bridge 不存在 | 155 errors |
| raw-model 前置 target 不存在 | 10 errors |
| 预期 native evaluator failed，实际得到文件读取失败 | 1 failure |
| 需要实际 native NDU bridge 路径 | 14 skips |
| 需要实际 Z3 与固定 native NDU build | 4 skips |

全部187个错误和1个失败的原始异常链都包含 ENOENT；造成文件缺失的行为主体仍未知。修复前置条件并完成新的完整回归之前，状态继续为 FAIL/HOLD。没有用较早3,547、3,590、3,699或3,931项的不同历史测试替代它。

## 当前实现和交付边界

父树包含 4827 个文件；其中生产包 `hepta/` 仍有 153 个 Python 文件。`pyproject.toml` 仍使用 setuptools、要求 Python >=3.11，并把 `hia` 注册为 `hepta.cli:hia_main`。整树另含 1827 个 .py、60 个 .hiaasm、12 个 .hia、30 个 .S、69 个 .c、48 个 .rs；这些统计包含审计证据和参考文件，**不能换算成原生语义完成百分比**。

| 层次 | 已有独立证据 | 尚未闭合的范围 |
| --- | --- | --- |
| Core 入站、类型、SSA/CFG、资源流与选定原生服务 | 恢复分支已有组件验收；原始证据保留 | 不能代替普通 CLI、安装入口和全部语言后端的产品级验收 |
| Function 机器码降级 | 已有 frame 与 Code 组件证据；本提交新增五核组合、39组/718例/129私有控制的实际运行门 | 本提交新组合尚未运行；完整 Emitter、wrapper、exports、全后端未接管 |
| 普通 patch 协调器 | follow34 实际5次 B3 编译和1次原生 ELF packer 通过 | 九组均在夹具指纹检查前停止，实际候选进程0；本提交只修该指纹和传递引用后重跑 |
| Worker wire/digest/initializer | follow33 digest 253例/1,672次入口，initializer 8例/6,495次入口 | Store.json/profile 新组合尚待运行；14类外部效果及普通 Worker 全链仍开放 |
| Store.json/profile | 本提交保留完整原始 Store oracle 和新9编译/7组门 | namespace 结果仍是明确的外部夹具，不能当成实际落盘、完整构造器或31种SQL闭合 |
| DB/DMS/共享文件系统/内存六角色 | follow34 六个原生编译通过，原先重定位问题已过门 | packer 参数23超过原16上限；本提交改局部存活状态，并要求原33个packer控制、18个物理测试和新增84组三方完整缓冲对照全部通过 |
| robust_open / unixOpen | follow34 两个 B3 编译及984字节原始 C 函数编译通过 | 运行在原90 CPU秒处被杀；实际完成例数等待原始gzip回读；完整 unixOpen、URI/创建模式及真实持久性仍开放 |
| 冷启动自举 | 完整原始回读确认 follow32 为11/11、38/38阶段，178.835092237秒 | follow33 为6/11、34/38阶段，180.144268141秒超时；不能因一次通过宣告稳定闭合 |
| 构建与安装 | 固定独立参考、原生编译器和完整工件指纹可追溯 | Python作者、测试/构建脚本、机械汇编和当前安装入口仍是依赖，不能称最终全HIA原生整套 |
| 证明、优化、进程/lease、更新与迁移 | 有各自组件和原始控制材料 | 完整普通调用图、所有平台入口、持久身份/恢复与替换后的全量验收仍需继续完成 |

## 本提交执行什么

1. 完整 Function frame → lowering tape → Code issuer → encoder → finalizer 的新独立CI。计划5个新 B3 编译、39组、718例，不继承旧组件计数。
2. Store.json/profile 与原始 wire/digest、固定 op5、registry 和 initializer 返回的组合CI。计划9个新 B3、7组；明确保留外部 namespace 边界。
3. 普通 patch 协调器修复的两处精确引用：测试夹具SHA，以及CI中的测试SHA/SHA256。十一份被抽取的夹具函数源文本完全相同，候选HIA逻辑、用例和限制未改。
4. 六角色物理链路 packer 的局部状态修订；上限仍16，不靠放宽编译器通过。旧packer作为VM参考保留，不尝试把它当成合格B3输入。
5. 下载 follow34 原始物理和robust工件，全成员读回、完整输出和可恢复gzip前缀核验，并绑定实际生成的HIA源、镜像和编译回执。
6. 保存 follow32/33 原始冷启动记录的逐字节回读：follow32共1,498文件/287,444,784字节，follow33共4,924文件/366,750,045字节。两者所有输入保持不变，失败不重标为成功。

所有新源码在提交时仅完成 Git 全文/字节/SHA256/blob身份核对；CI尚未执行的阶段保持 PENDING。活动 Python 语法清单为262个文件，语法通过也不授予语义验收。

## 最终清理条件

只有完整普通用户入口、编译/执行/存储/Worker/工具链/安装/更新恢复均由HIA实现承接，才能进入最终替换。必须在无旧业务实现可调用的环境下实际执行完整回归、冷启动、故障恢复及平台门；同时验证可重建HIA源、二进制和安装包的完整身份。旧参考、旧日志和失败证据在这之前保留。任何删除都要发生在验证后的明确切换提交中；本提交删除0个文件，不激活新产品入口。

相关精确材料：`review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci-followup-r35/checkpoint.json`、同目录 `deliveries/`、`ordinary-patch/`、`cold-follow32/`、`cold-follow33/`，以及 `namespace-ci/follow34-originals/`。
