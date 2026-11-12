# HIA 全量原生重写审计（2026-11-12）

## 当前结论

**整套尚未闭合。函数降级组合已有 CI 成功结果；普通补丁与 Store 组合已进入实际运行并暴露具体缺口。生产入口尚未切换，旧实现保留。**

本次审计基于恢复分支提交 `2544ec88203992d5d8590b4ab09fb0231066be72`、完整树 `45e30c5c79f25190c4424edcf97ad53e70bbafa1`。独立参考固定为 `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`。本提交继续补齐 HIA 实现、运行独立组合测试并保存原始失败。任何选定组件成功都不能替代整套验收。

读取时主分支为 `5831f52fada45e076f8f68f198a15c0585e6104f`；并行 PR #893 为 open/unmerged、头 `9a12b6cd13ba103fc7495aa8d5decf8cd5948143`。没有合并该分支或借用其验收结果。

## 原始完整回归仍为 FAIL/HOLD

原始完整回归共 **4,157 项：187 errors、1 failure、18 skips**。完整压缩包位于 `review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/qualification/raw-originals.tar.xz`，Git blob `2aae1a9fc536d476cf02f32d40b7c3a34335cf34`，666,816 字节，SHA256 `5595532d3fc1d8e8b5021236b30217b85ec53a1452d4b23a98b378996e67cee5`。

既有独立回读 `4d0d2547ab43a21b808ca10e180a7b5038eacdbb` 记录124个归档成员、123份原始文件的8,688,721字节及2,798个原始源码文件/模式的核对。原始错误归组 `a5f15e07768ae19059ff2f56bef7dafb305b49bb` 已完整读取：

| 原始记录分组 | 数量 |
| --- | ---: |
| 旧调试桥绝对路径不存在 | 1 error |
| 有界普通文件读取失败 | 19 errors |
| 无法以 no-follow 打开原生工件 | 2 errors |
| raw-model 前置 release/hia-ndu-bridge 不存在 | 155 errors |
| raw-model 前置 target 不存在 | 10 errors |
| 预期 native evaluator failed，实际得到文件读取失败 | 1 failure |
| 需要实际 native NDU bridge 路径 | 14 skips |
| 需要实际 Z3 与固定 native NDU build | 4 skips |

全部187个错误与1个失败的原始异常链包含 ENOENT；导致工件缺失的行为主体仍未知。本轮新增完整原始档案读回程序，逐字节保存原始命令、前置环境、完整测试结果及stdout/stderr，为重建真实前置条件提供依据。它自身不重跑测试，不把原 FAIL 改成 PASS。新的完整回归必须使用完整 discovery，不删用例、不跳过前置条件、不借用不同历史测试总数。

## 当前仓库与依赖

已核对的父树有 **4,943 个文件、556,154,594 字节**。生产包 `hepta/` 仍有 **153 个 Python 文件**；整树有1,879个.py、60个.hiaasm、12个.hia、32个.S、69个.c、48个.rs。整树数字含历史证据和参考文件，不能换算成原生语义完成百分比。

`pyproject.toml` 仍使用 setuptools，要求 Python >=3.11，`hia` 入口仍指向 `hepta.cli:hia_main`。因此当前安装交付明确仍依赖 Python。新增完整静态审计会读取本次全部已提交文件、解析全部Python源并逐模块列出导入、公开定义、native选择项和静态调用关系，保存失败解析及完整源身份，检查前后字节和模式不变。该审计尚待首次运行。

## 最新真实执行结果

| 范围 | 已确认的实际结果 | 保留的缺口 |
| --- | --- | --- |
| Function frame/lowering/Code/encoder/finalizer | follow35 job `131005901343` SUCCESS | 原始39组结果与完整ledger尚待独立读回；不将计划718例当作已读计数；完整Emitter、wrapper、exports尚未闭合 |
| 普通patch固定ELF协调器 | 5次新B3与1次原生packer通过；132次候选进程和132次原始完整apply；128例完成 | semantic、interfaces、identity、large-valid各自首例失败；整组仍FAIL |
| Store.json/profile | 9次新B3通过；5组269例、10,268次实际native入口通过 | 两个8MiB大值组在原90 CPU秒处被杀，无terminal summary；完成前沿等待原件读回；整组仍FAIL |
| 六角色物理链路r5 | 6角色B3+1packer B3、33个packer控制、84组三方完整缓冲区对照通过 | 后续physical返回-7/SIGBUS，180.859878034秒；297,491字节INCOMPLETE摘要待全文核验，实际物理完成例数未知 |
| robust_open | follow34两次B3与原984字节C编译通过；配对运行在90 CPU秒被杀 | 原始gzip可恢复前沿仍待独立读回；完整unixOpen未闭合 |
| 冷启动 | follow32完整回读11/11、38/38阶段，178.835092237秒；follow34 Core job报告11/11 | follow33完整回读6/11、34/38阶段，180.144268141秒超时；follow35再度报告6/11失败；follow34/35完整工件未另行读回；稳定性尚未闭合 |

### 普通补丁的明确协议缺陷与修复

四个有效补丁组的原始stderr均为32字节 `HIAXER01`：error=3、role=56、sequence=123。原始完整日志及九个逐字输出的组摘要已保存；没有把事件序号123误计为返回值。

静态检查确认：收据HIA内核在完成后把version、policy、edits、interface-change count写入 `HIAPRC01` 的64..95字节；协调器phase100却把64..127全部当作保留零区。这会拒绝有效结果和正确的接口策略拒绝。新HIA协调器只对96..127校零，同时严格绑定前三个字段到实际prepare结果，检查变化数不超过两侧各1024函数的并集上界2048，并保留preserve/migrate拒绝条件；NEED分支仍要求全部元数据为零。

修复新源Git blob `1ec25d1a9e579fe077f680b7d34ff40e6db66ee1`。收据内核、执行器、独立原版oracle、测试用例和原限制保持原字节。独立静态复核确认字段契约一致；真实因果确认以重新生成五个B3镜像并运行原九组结果为准，尚未宣告通过。

### Store 大值失败与构造器接线

已通过的五组分别为semantic 27例/6,188入口、errors 14例/2,674入口、protocol 223例/574入口、growth 4例/708入口、large-ref-8m 1例/124入口。两个large-value组返回-9；记录的wall约90.281/90.220秒、CPU约90.019/89.994秒。没有足够证据认定被杀时具体停在哪个角色，不推断完成计数。

本提交独立首次运行完整initializer与Store.json/profile的真实接线：11次新B3、4组计划8/12/1/3例，比较原始完整构造器状态、缺失属性、首个异常、顺序调用和Store wire/put/SQL序列、profile引用handle及native Graph别名。该小域接线不包含两组已知8MiB大值选择，因此可独立验证，但绝不替代其失败。其余12类initializer外部peer及namespace put/SQL实际结果仍未接管。

## 本提交继续执行的开发工作

1. 首次执行完整scalar/borrowed-byte wrapper的两项新HIA实现及实际Code接线：4次新B3、26组计划502例/79私有控制；不继承Function成功，完整Emitter仍开放。
2. 修复普通patch收据协议并重跑原完整九组，保持原B3、资源与public1024函数边界。
3. 首次执行完整initializer与Store JSON/profile的24例独立接线验证；保留底层两个大值FAIL。
4. 首次执行SQLite URI/创建模式的HIA实现：两次新B3、一个精确C参考编译，计划222语义例、389私有拒绝、8直接边界。固定15段原始C字节和5份完整来源；raw-provider仍为可控结果，不声称真实OS落盘。
5. 全树源码/安装依赖盘点，以及原始4,157项完整失败档案的独立字节读回。
6. 保存原Function/Store等运行的完整原件，并继续完整Emitter、unixOpen/reuse、真实存储和剩余Worker效果接线。
7. 保存读回器的异常传播修正：只捕获gzip/编码内容错误，TimeoutError、MemoryError和输出IO失败进入外层FAIL；当前既有运行不热改、不取消。

## 原门与最终清理条件

B3始终为10 CPU秒、20 wall秒、256MiB地址空间、1MiB源/输出/工作区。Bootstrap保持128 functions、1536 blocks、8192 operations、每函数256 blocks、每block16参数、SSA序号<2048；不存在额外128 operations/block门。普通配对组保持90 CPU秒、180 wall秒、1GiB。需要物理全链900秒的原聚合门仍独立保留。

完整普通用户入口、编译/执行/存储/Worker/工具链/安装/更新恢复均需由HIA实现承接。随后必须在旧业务实现不可调用的环境中实际运行完整回归、冷启动、故障恢复和平台门，并核验可重建HIA源、二进制和安装包身份。Python作者、构建/安装脚本、机械汇编和当前产品入口仍是待替换依赖。**本提交激活0个新产品入口，删除0个文件。**

精确材料位于 `review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/ci-followup-r36/`；旧follow35及更早原始成功、失败、超时记录全部保留。
