# 当前 CI 完整诊断读回：通过项与失败项分别保留

当前标准 CI [43612781760](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43612781760) 已结束，结论为 **failure**。本目录保留其完整选择原件和 Root 独立读回，不把诊断读取成功解释为产品通过。

## 当前结果

- Source：105 个原 selectors，553 个唯一测试方法，全部通过，0 跳过。
- Wire：89 个原方法通过。unittest 全套耗时 252.299 秒；wrapper 为 252.337344026 秒。原 5 秒约束只用于原指定方法中的 evaluate 区间，不能写成全套 5 秒。
- 独立 Core：15 + 51 + 50 = 116 个原方法通过。ELF 的 component 20 和 caller 51 门通过。
- Core/UNPACK 联合门：原 180 秒运行、3 秒清理预算不变；69 个方法已开始，68 个原日志明确 ok，超时后 owner 返回 -9。最后开始的方法距 owner deadline 0.703504958 秒，没有完成结果。不能据此认定它独占了全部时间。
- progress 中 native_returns 是 UNPACK _step 正常返回的采样数，不是 Core 指令数，也不是终止时最终计数。
- 后继 UNPACK18 被跳过；当前候选 Full32 未启动。完整语言自举、全栈 HIA 原生交付、默认切换和旧实现删除均未闭合。

## 完整原件与读取范围

原大 ZIP 为 662,866,102 字节。collector 完整读取了其 22,448 个目录成员及对应正文；Root 没有直接读取这个大 ZIP。collector 选择了 961 个预期路径，其中 938 个产品原件存在，23 个不存在（联合超时缺失 5 个结果文件，后继 UNPACK18 缺失 18 个记录），控制原件没有缺失。

Root 完整读取小 ZIP 的 81,436,642 字节，以及其中全部 954 个成员的完整正文。成员数量包括 938 个产品原件、3 个目录/索引元数据、11 个 collector 控制原件和 FINAL/SMALL-READBACK 两个最终原件。每个成员均核对完整长度、CRC32、SHA256 和 Git blob 身份。完整索引可在小 ZIP 内恢复；本目录也保存 MEMBER-MANIFEST 和 SELECTED-MANIFEST。

### 无损恢复

1. 按 transport/MANIFEST.json 的数字顺序，分别对 8 个 part 文件进行 base64 解码，再拼接解码后的二进制。不要先拼接含独立 padding 的 base64 文本。
2. 拼接所得 gzip 必须为 7,654,653 字节，SHA256 为 8753aa60ea7f40b331b82499a873dfb059c4fdd4255524068c6360ad684b3378。
3. 对单一 gzip member 完整解压，得到原小 ZIP：81,436,642 字节，SHA256 为 e76ca1957baa43e4bf7d56dea21f58fb8baa64df982ad25ce3011f7793265fdb。
4. ZIP 内 originals/INDEX.json 将原 CI 路径映射到 originals/member-*.bin。保留它们的原字节，不以解析后重新序列化的 JSON 取代原件。

所有 part 均已发布并做完整 Git GET 等值核对。压缩、传输和解码只处理已闭合的证据字节，没有重跑产品。

## 边界与原失败保留

ROOT-CHECKS 中通过的检查用于原件保管、源码绑定和有限资格结果的复核，不改变联合门的失败结论。installed 控制仍使用 CPython 和 Python 对象桥；冷自举仅覆盖固定 canonical HIA v8 子集。Root 没有直接读取完整 wheel 或全部安装资源正文，也没有声称获得完整历史后代进程清单。

COMBINED-FAILURE-ANALYSIS 保留逐项时间及原计数语义；history 中保留旧分析。ROOT-PREPARATION-INCIDENTS 保留 Root 的读取、解析和说明错误及其修正。旧 archive ref 的 UNKNOWN 变更没有重放。

同一提交附带 Pager retained-page 源码草案及 Source553 闭合原件。新增 6,115 字节 Pager HIA 组件尚未实际生成、执行 VM/native 或通过新增 interop；旧 R3 有限场景结果不转授给它。仓库产品源和全部原测试门保持原样。
