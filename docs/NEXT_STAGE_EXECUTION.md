# 四阶段实施与验收边界

本轮把“真实所有权库 → 真实 C 模块 → 分成本 C++ 接口 → 跨文件 Agent
任务”的顺序落实为源码、命令、负向测试和可重放验收。所有最终结果必须绑定同一份
源码快照。实现当前有限范围、通过验收、证明普遍性质，是三种不同结论。

统一入口为 `python tools/release_check.py`。它要求非空单元/集成测试且零跳过，
随后执行严格 namespace 隔离、原生示例、资源 IR、三个 C 资格工具、C++ 库及带参构造、ABI、
并发、性能、Lean、AArch64、两套评测夹具资格、真实隔离的生产 workspace 闭环
及五任务发布前后的崩溃矩阵。
任何必要子项未运行、失败或超时都不能使外层通过。
运行前后源码快照必须完全相同。新四阶段资格使用独立时间戳输出路径。

`artifacts/release-validation.json` 是本地运行的总索引；本轮通过后的原始 JSON 与
日志按源码快照归档：`evidence/next_stage/` 保留最初的四阶段集成资格，
`evidence/production_v4/` 保留实际 v4 评测接入后的首次资格，
`evidence/production_v4_final/` 记录进一步修复 HTTP 响应完成处理后的完整资格。
`evidence/next_blockers_final/` 记录有限 Owned 泛型、真实有状态 C 模块、channel
超时、真实 C++ 库带参构造和逐任务崩溃资格等后续增量整合后的资格。
每个索引都记录原始相对路径、文件哈希与归档位置。旧快照的通过结果不代替修改后的验收。
`whole_project_blockers_closed=false` 保留完整生产目标尚未实现的事实。

## 1. 真实资源结构与独立检查

实现入口包括 `hepta/checker.py`、`hepta/backend.py`、
`hepta/resource_ir.py` 和 `hepta/resource_lowering.py`。

- `Buffer<u8>` 可以作为结构体、枚举、具体泛型数据与 `Result` 的载荷。
  整体移动、消费匹配和递归 drop 都有明确检查；提前返回不能遗留本地资源义务。
- `try_buffer` 把实际分配器拒绝返回为 `Result`。测试中的分配器确实拒绝指定布局，
  然后允许恢复；这与单纯构造一个错误枚举有不同的验收意义。
- 返回借用绑定唯一借用参数；允许明确不重叠字段借用。任意生命周期组合、存储引用、
  部分字段移动和无限制 trait 尚未开放。函数泛型接受有限 `Copy` / `Owned` 约束；
  `Owned` 参数可移动、借用和显式 drop，不能隐式复制，也不能隐藏带作用域的任务资源。
- 独立 JSON 验证器处理显式 owner、loan、move、drop、CFG 汇合与外部义务。
  它不导入 parser/checker，不能信任调用方伪造的“已证明”状态。
- `examples/owned` 是实际含所有权结构的双文件库；返回借用项目另有完整原生执行。
  单元与跨文件任务还验证真实分配拒绝、提前错误、任务取消、线程 join 和释放。
- `examples/owned_generics` 把这些路径通过真正的泛型函数组合。资源 IR v2 独立检查
  六个未具体化的泛型函数体和十六个调用，显式保留作用域与约束；三个项目共用资格入口，
  十一个图变异对照验证拒绝路径。它没有把 Rust 的检查结果当作图验证结果。

channel 增加基于一次性单调时钟期限的 send/receive timeout 和显式 `group_cancel`。
超时保持接收输出与队列状态；取消唤醒等待者但仍要求 join。五个原生场景各执行三轮。
独立原生审查还覆盖取消/超时竞态、错误唤醒和伪唤醒后不重置期限。互斥锁调度与用户
worker 的执行时间没有上界，因此这项功能不构成硬实时期限或抢占式任务终止。

资源 IR 的并发建模与源码到 IR 的精化证明仍未完成。Rust 后端继续负责参考执行
和关键借用检查。当前 `panic=abort`，进程被中止或杀死时不承诺运行析构函数。
正常错误返回与协作取消的资源协议，不能推广为所有崩溃模型的清理保证。

## 2. 完整声明盘点的真实 C 模块迁移

`hepta migrate-c-project` 捕获 `compile_commands.json`、允许的编译参数、
预处理身份与依赖源码哈希，迁移局部变量、循环、调用、普通结构、指针加长度接口，
以及文档定义的有限 malloc/calloc/free 模式。未知活动声明即使未被调用，也会阻止
整个模块被报告为迁移完成。被预处理排除的分支不属于当前构建配置的活动声明集合。

冻结第三方输入是未修改的 `fragglet/c-algorithms`，上游提交
`23d453792ed89a28ed7d2c8d4311a4d9f7822edd` 的完整 `compare-int` 与 `hash-int`
源文件/头文件，连同许可证、原始哈希和上游 URL。每个函数定义与原型都进入分母。
实际原 C 编译器输出与 Hepta/Rust 输出进行 25,302 次比较，包含 8,434 个同地址
只读别名输入；另有独立算术 oracle、输入不变检查与故意错误实现的拒绝对照。

独立的模块/结构/缓冲区/分配组合资格包含 1,046 次差分调用和 10 次分配失败/恢复
调用。人工构造的复杂缓冲区样例如实标为 fixture，不伪称第三方历史源码。
有效指针的 provenance、完整分配范围和无外部数据竞争仍是 unsafe ABI 的调用方义务。
NULL、对齐和数值长度检查不能证明这些条件。工具时间会记录；人工迁移工时、模型
token 与整体性能优势没有测量时保持未知，不能从机器执行秒数推算“低成本”。

新增的真实有状态模块为未修改的 `AndersKaloer/Ring-Buffer`，冻结于
`8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba`。C11、`NDEBUG` 与 unsigned-char
配置全部显式捕获；九个函数和全部二十二个活动声明进入分母。显式 record-view
合约把原 C 指针结构分解成安全核心的标量状态和调用期 slice，原始 ABI 布局保留在边界。
这没有向语言核心加入存储裸指针或自动推断外部 ownership。

资格入口 `tools/qualify_c_ring_buffer.py` 执行八个容量下的 16,384 次状态转换、
65,544 次原生差分调用、独立 deque oracle、每个存储字节和状态字段检查，包含
543 次零长度 NULL slice 调用。九个无效边界输入在独立进程中拒绝；GCC/Rust
布局实测和真正编译过的错误实现对照均必需通过。另写的 Hepta Buffer owner 经
实际分配失败、提前返回和恢复检查；上游本身使用调用方存储，不能说它的分配器已迁移。
三类工作负载各保留七次交替顺序计时，慢于原 C 的路径也保留。

独立审查曾发现有效负相对索引和混合编译单元 `char` 模型的误编译。当前相对索引
在扩大到有符号类型后检查绝对位置，混合数据模型在完整盘点后拒绝；ABI 模型查询
不接受用户 `-D`/`-U` 对预定义宏的覆盖。旧有限差分通过记录、反例与修复后的报告
分别保存。具体接受范围、外部义务和剩余限制见 `C_RECORD_VIEWS.md`。

集成期间另以实际 GCC 复现并修复了头文件导入的 tag/typedef 名字空间混淆、const
层级丢失、被预定义/include guard 隐藏的函数，以及 typedef 原始拼写造成的原型
自比较问题。native probe 现在先验证别名，再验证真实函数存在及类型兼容。
相应的 raw-pointer 义务盘点也覆盖 nominal 类型内的字段；详见
`C_IMPORT_SAFETY_INTEGRATION.md`。头文件快照 relocation 与原 C API 的双后端
执行均保留回归。首轮通过的旧快照不能替代这些修复后的完整验收。

## 3. 分开测量的 C++ 接入

`hepta bridge-cpp-contract` 与 `tools/validate_cpp.py` 支持三个明确层次：

| 层次 | 当前机制 | 不能省略的成本或外部义务 |
| --- | --- | --- |
| 直接调用 | native 签名与 POD 布局校验、noexcept 标量/值接口 | ABI 调用成本；外部实现的正确性与未定义行为条件 |
| 调用期借用 | 指针/长度检查，借用仅在调用期有效 | 动态边界检查；外部不得保留指针的契约仍需信任 |
| 动态 handle | 整数 handle、对象锁、线程身份、重入规则、在途析构延迟 | 查找/锁/共享生命周期保护；遗弃 handle 不等于自动回收 |

复杂模板选定具体类型后在 C++ 侧实例化，实际使用 `std::vector` 与 `std::string`。
异常被翻译成接口状态，析构与分配器配对在同一 C++ 模块完成。异常返回不承诺回滚
外部已经产生的副作用。所有外部实现仍保持明确 unsafe 边界。

资格报告分别记录三个原生调用和三个桥接调用的全部计时样本、循环次数与本机环境。
这些数据允许估计当前接口的成本，但不能证明普遍零开销或普遍快于 Rust；handle
路径有实际运行时成本。没有把复用 C++ 库描述为已把其实现自动重写成安全 Hepta。

`hepta.cpp-contract.v2` 进一步为 handle 声明有限的具名构造器，支持既有标量、
POD、const-ref 和调用期 span 参数；v1 的无参 `_new` 接口保留。构造器使用原生
constructibility 与 noexcept 检查，参数类别与实际生成调用一致。C++ 构造器没有
可用于该探针的函数地址，所以报告明确区分“该带类型的构造表达式有效”与“精确参数
签名已证明”。对象构造为 noexcept，也不能消除包装层分配失败。

`tools/validate_cpp_constructors.py` 实际构造安装的 Boost.Math
`students_t_distribution<double>`，覆盖五个合法值与三个 domain-error 路径，
以及八个 `std::vector` 长度／填充值构造用例。另写的 POD/span 复制与 noexcept
类如实标为 authored probes。真实 C++ `operator new` 拒绝用于检查对象和 registry
分配失败后的输出保持、析构及恢复；对象只在注册成功后写入输出 handle。
八项契约／原生拒绝对照全部保留。安装的 Boost 版本、实际读取的系统头文件哈希
及前后内容一致性进入报告，这不等于完整密闭工具链或动态库锁。

新成本报告分别保留 native/handle 两种对象的“创建＋销毁”与稳态方法调用，共八行、
每行七次原始样本。生命周期行没有额外 getter，方法行不混入构造开销；冷启动与
分配拒绝单独验证。外部构造器不保留 `call_only` 引用仍是显式外部义务。

## 4. 跨文件编辑与四臂评测

生产 workspace v4 提供不可变版本、节点身份、接口迁移、整个 import 图的 native
验证，以及一次 CURRENT 更新的一致发布。读者先 pin 版本；协作写者用 compare-and-swap
防止覆盖新版本。真实进程中断测试覆盖发布前后，恢复不会擅自发布未提交候选。
生成 Rust 诊断只映射到确实包含该诊断范围的源节点；运行时支持代码不伪造源位置。

四臂评测通过有限的 study v2 协议暴露两种语言同等的 function/body/declaration
操作范围。Rust 的语义索引是明确受限的 lexer/分隔符索引，不冒充完整 rust-analyzer。
Hepta 第四臂实际调用生产 `hepta.workspace`：独立子进程中的持久化 store 先
prepare，经过任务接口原生检查，再用完全相同的补丁和 CAS 条件 commit，随后
recover、重新 pin；最终候选来自确认发布的版本。初始验证、工具验证和最终 pin
都占用共同的 wall budget；发布状态不明会终止尝试，不伪称回滚并继续评分。

`production_workspace_v4_exercised` 只在真实初始化、检查、提交、恢复、最终 pin
均完成时成立。完整二十组参考脚本中要求五次这样的 v4 闭环；另有五任务严格
namespace 执行资格，直接验证生产隔离路径。第四臂没有额外的 expression/statement
操作。所有语义前端都在有界子进程内处理候选代码。

另有 `qualify-workspace-crashes` 在全部五个任务的 prepared/published 检查点
执行十次真实子进程退出。新进程观察 CURRENT、journal 和旧 pinned 版本，恢复两次，
然后重试原始 CAS 请求：prepared 死亡后正常提交，published 死亡后拒绝 stale 请求。
最终重新 pin 的版本通过 624 个隐藏原生输入。全部操作沿用同一个每案 wall budget，
十六个重新封装的伪造证据对照必须被拒绝。该专用故障 worker 不进入 provider 胶囊。
这些是脚本与恢复机制的资格，真实模型运行数仍为零。

五项任务覆盖跨文件 API、资源 Result、实际 C/C++ 库调用、真实线程取消与 join、
跨模块边界缺陷修复。十个 starter 均能按原接口编译且未通过新目标；二十个四臂
参考脚本覆盖 1,248 个隐藏原生输入。输入数量不等于独立 coding 任务数量。

可信 driver 与候选分别编译为不同 crate，避免候选修改资源计数器。provider receipt
在整个计划矩阵中去重；失败、超时、不完整和重复样本均保留在计划分母中。失败前
已验证的费用前缀保留，未知总费用与人工修正时间为 null。显式 abort 保留真实
失败状态：合法收据覆盖全部实际请求时，失败也可有完整已知费用；丢失响应、缺少
usage 或有 pending request 时，总费用仍为未知。plan 绑定每个模型的 adapter
目录哈希、命令、解释器哈希、环境变量名称和网络配置，同一模型的四臂不能换适配器。
旧审查前夹具报告被保留并明确 supersede，新报告绑定修正后的 taskset 与 evaluator 身份。

严格隔离资格检查 namespace 身份、清零 capabilities、空 `/proc`、父进程私有
路径/凭据不可见、宿主网络不可达、系统挂载只读，以及 Hepta/Rust 原生执行与
workspace profile。通过依赖当前宿主允许建立这些 namespace；受限宿主仍须拒绝，
不会自动降级为可信 fixture。具体配置见 `SANDBOX_QUALIFICATION.md`。

**当前真实模型运行数为 0。** 已实现带真实 HTTP usage/request-id 记账的独立
OpenAI 适配器、导出器与离线传输测试，见 `tools/provider_adapter/README.md`。
当前仍没有显式配置的 API 凭据、至少两个可用且固定的模型修订及运行预算；父环境
和适配器胶囊的 API 域名解析也失败，尚未验证 TLS 握手与实际 HTTP 连接。没有
执行真实 API 请求。适配器测试和可信参考脚本只验证实现，不能转换成 AI 成绩。
模型/预算配置齐备后必须创建新 plan，运行全部四臂矩阵；现有资格不能证明 Agent 收益。

## 仍保留的完整目标

本轮完成的可执行子集不能关闭 `docs/BLOCKERS.md` 中所有 P01–P12：完整类型健全性
与降级证明、全局资源预算、任意 C/C++ 自动安全迁移、成熟标准库、真实硬件/GPU、
多平台 ABI 资格、广泛性能优势，以及真实模型生产力优势，都需要各自的实现与证据。
特别是使用 C ABI 或 C++ 包装器不会把不安全外部实现自动变成安全代码。
