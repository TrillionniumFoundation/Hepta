# 5c3741d 宿主 artifact 只读审查

审查源：`5c3741da1d36e8c1f79ec728ec325b8d973c899e`；tree：
`3492a8efb0ea2818b3260585c6b937935cd505a4`。
读取既有 ZIP 内 JSON/log；未展开归档、未重跑 CI、未执行原生程序。

## 范围和身份

核对 ABI run `41599662999` 的 7 个常规宿主 artifact，以及 C++ run
`41599662735` 的 7 个 artifact。排除 root 单独审查的 standalone AArch64
artifact `13213538272` 和 captured-C 两个 artifact。14 个 ZIP 的原始字节数与
GitHub 提供的 SHA-256 全部匹配；保留了 105 个关键原始 JSON 成员的字节数和
SHA-256（`json-member-sha256.tsv`）。

| 实际宿主 / 编译器 | ABI artifact | C++ artifact |
|---|---:|---:|
| Linux x86_64 / GCC | 13214405288 | 13213538323 |
| Linux x86_64 / Clang | 13214047461 | 13213648021 |
| Linux AArch64 / GCC | 13213782999 | 13213553320 |
| Linux AArch64 / Clang | 13213548333 | 13213742868 |
| Windows x86_64 / MSVC | 13213088333 | 13213883013 |
| Windows x86_64 / Clang | 13213942997 | 13214112648 |
| macOS AArch64 / Clang | 13214232032 | 13213653071 |

所有 setup log 均记录实际 HEAD 为 5c3741d。ABI 内 stb source_before/source_after
均记录上述 HEAD/tree、402 个 implementation 文件与 6 个 fixture 文件的字节哈希，
本次与该 Git tree 逐项一致。这里的空 status 只覆盖 implementation/tests/workflows，
不能替代全仓库 tracked-clean 观察。

## 已核对的有限观察

- 每个 ABI 宿主：两个优化配置各 181 次 foreign call；3 个真实编译拒绝的类型负控制；
  1 个真实编译并运行的错误 C echo 被拒绝。
- 每个 stb_divide 宿主：21,453 个不同输入、两个宏配置；42,906 个输入/配置对，
  514,872 次原生函数观察、696 次单独的 HIA 解释器观察、24 个仅进入安全目标的
  trap 进程。所有原生目标路线为 Rust backend；HIA native_requested/native_executed
  均为 false；本组没有额外 UBSan 观察。
- 每个 stb 宿主保留 3 个整包拒绝、实际 wrong-code oracle 退出码 2，以及
  `E_CPP_PROJECT_PROFILE` 的 C++ entry 拒绝，无部分迁移包发布。
- 每个 C++ 宿主运行 nlohmann/json 3.11.3 和 3.12.0；每版本 98 个 direct/Hepta
  比较案例、32 个生命周期案例、1024 次并发调用、ordinary_live_delta=0，
  registry 保留分配单列计数：Linux/macOS 每版本 2 次，Windows 每版本 3 次。
  每个宿主有实际 wrong implementation 退出码 2、
  `E_CPP_NATIVE` 的实际不兼容签名编译拒绝，以及 8 个既有 evidence 负控制。
  Hepta consumer 经 Rust 1.90.0 原生构建，不是 standalone HIA LLVM 后端。
- Artifact 内 ABI unit logs 分别为 11、16、4 项，C++ unit log 为 9 项，均 OK、
  无单项 skip。Root 保留的完整 job logs 另显示 5 个 POSIX ABI 宿主各 20 项 ownership
  边界测试 OK、无单项 skip；该整步在两个 Windows job 按条件跳过。非 Windows 的
  Visual Studio 环境建立步骤按条件跳过，未将条件 skip 计作执行。

## 必须保留的来源缺口

三个 C++ 宿主（macOS、Windows Clang、Windows MSVC）的
`tracked_source_status` **在编译前即非空**，均记录：

```
 M artifacts/hia-ndu-eight-arm-20261030/BASE.json
 M artifacts/hia-ndu-seven-arm-20261030/BASE.json
```

5c Git tree 的 8,655 个 tracked 路径（含目录前缀）恰有两组 casefold 冲突：这两个
目录各自同时存在 `BASE.json` 与 `base.json`。大写为 14,573 字节 HIA 程序，小写为
83,787 字节 native receipt；不是 LFS pointer。既有 job logs 没有明确的 collision
警告，artifact 也未保存当时这两个历史路径的物化字节，不能声称已测得当时 checkout
覆盖结果的 SHA。旧 qualifier/validator 允许相同 dirty 状态前后一致，因此这些绿色
job **不能记为通过新的严格 clean-checkout gate**。

C++ 实际 source_inputs 共 197 项：Linux/macOS 全部与 Git blob 原始字节一致；
Windows 189 项一致，另 8 个 `examples/cpp/upgrade`、`examples/cpp/upstream_host`
输入只发生 LF→CRLF 物化差异，无其他不明字节差异。保留这一平台差异，不写成
“所有平台原始 Git blob 完全相同”。三项 dirty 宿主的历史路径不在编译输入清单中，
但全仓库不干净的事实不能因此忽略。

## 后续修复与结论边界

独立修复提交 `f7fbce0e6c9c6788e1deae5cbb4f582aef8d3ea6` 对两个历史大写文件做
100% 纯 rename 至 `BASE_PROGRAM.json`，保存四份原始数据哈希与路径迁移清单，
不编辑历史 sources 快照；两个活动 NDU 生成器同步使用新名称。C++ 开始/结束/current
验收都要求空 tracked 状态与完整一致 Git 身份，并检查 casefold 唯一性；ABI 主矩阵
新增前后 HEAD/tree/全 tracked-clean gate。旧 8 个 C++ evidence 负控制保留，新增 4 个
checkout 负控制。此补丁有 15 项 C++ 模块及 5 项 composition identity 本地回归通过，
不属于对新提交的原生多平台 CI 执行证明。

本审查只覆盖所列有限宿主、固定输入、控制与来源身份，不证明一般 C/C++ 迁移、
foreign memory safety、所有分配失败可恢复、任意线程/设备安全、全语言类型健全性，
也不推出完整 P0–P7 已闭合。
