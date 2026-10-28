# 最终归档审计与补充源码

此补充记录在原始归档生成后完成；[README.md](README.md) 所列源码、执行结果及原始归档均保持原字节。最终源码为 `efb210e994c151c1161acfe8d50d5d48716d2755`。以下审计只读取已有证据，没有重新运行测试、编译器、求解器、原生程序或性能实验。

| 材料 | 实际核对范围 |
| --- | --- |
| [archive-audit.json](archive-audit.json) | 原固定清单、两份元数据与九份冻结清单对应的 2,796/2,796 必需成员；`PASS_WITH_SCOPE_LIMITS` |
| [archive-acceptance-audit.json](archive-acceptance-audit.json) | 43,925 项只读检查、0 failed；全部 5,602 个归档成员，以及独立重建的 3,045 个必需原件来源 |
| [archive-path-mapping.json](archive-path-mapping.json) | 原件路径到归档成员的映射；各覆盖分母保持独立 |
| [package-audit-materials.tar.xz](package-audit-materials.tar.xz) | 全部 24 份审计原始文件加原始冻结清单，共 25 个文件；包括首轮附审的解析错误、纠正说明、脚本与日志 |
| [package-audit-freeze.json](package-audit-freeze.json) | 原 24 份文件的 SHA256 与长度；原始冻结清单的逐字节副本 |

原始归档为 36,421,592 B，SHA256 为 `88da2a1560adf6763d57a1e5780ead3dd6fb9e7bb4f7f9b0c7a1d22aa6ec5bd2`。六个分片逐字节拼接后仍为该值。审计材料包是独立补充文件，不计入原归档的 5,602 个成员。

## 有限 NDU 输入源码补件

固定上游提交 `4b6391e116949af0c7e59776baead67271856bdb` 的 93 项有限 NDU 源码输入中，原归档包含 92 项的字节身份。另一个输入 `tools/hia-ndu-bridge/src/protocol_tests.rs` 以 [ndu-finite-protocol-tests.rs](ndu-finite-protocol-tests.rs) 单独补齐：5,010 B，SHA256 为 `7ef966a7c757add2915468b02d0dcb58d7ed71bc3980c1308dd1e00416828f28`，Git blob 为 `2a3e07251d9f11c839baf7a60fb37b870b5c5e59`。

[supplemental-source.json](supplemental-source.json) 将补件绑定到原上游仓库、提交、路径和已保留的 LICENSE/NOTICE。独立审计逐项核对全部 93 项固定 Git 输入；原归档 92/93 与原归档加补件 93/93 分别记录，没有改写原归档或旧冻结清单，也没有声称交付了完整离线工具链与依赖闭包。

## 保留的限制与负结果

首轮附审的两处解析失配是审计程序漏纳实际 Rust VM，以及把 `skipped: []` 当成整数零；纠正后的审计重新读取原始字节。首轮报告、脚本、日志及纠正记录全部保留在审计材料包中。

主审的两项资源收据观察仍保留。正式 48-episode NDU 经济实验继续绑定原 `8b0fd11d` 源码，0 个候选发布，warm 净收益 −0.921820181 s、cold 净收益 −22.157880431 s；当前 CI 的 30 个 episode 保持独立。只读审计数不作为新增测试数或性能样本数。

本目录所有普通文件均由 [SHA256SUMS](SHA256SUMS) 覆盖（校验表自身除外）。原始六分片与清单可用 [verify-evidence.py](verify-evidence.py) 核对；审计材料包展开后可再按其中的 `AUDIT-FREEZE.json` 核对 24 个原件。
