# a733 原始 Normal Core 终态

**结论：原工作流失败。** run `43347253395`，attempt 1，源码 `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`。source job 成功；native job 在第 27 组失败。没有重跑、修改限额或将后续跳过组算作通过。

## 已核对的原始结果

| 范围 | 原始结果 | 证据范围 |
| --- | --- | --- |
| Source | 973 tests，515.050 秒，OK | 完整原 job log |
| Cold replay | stdout `COLD_SELFHOST_REPLAY_PASS`，11/11 | 原 stdout；完整冷报告及 CRC 尚待独立核验 |
| Language | 1242/1242 checks；另 10 unit tests，OK | 原 stdout；不合并两个分母 |
| native steps 8–26 | 19 组分别 OK，共 1049 次外层测试执行 | 原 unittest 汇总；不是唯一方法数 |
| native step 27 | 108 tests，1571.207 秒，2 failures | 两个外层测试各包含一个失败的原调用者组 |
| 原 namespace caller | 35 tests，389.129 秒，3 failures | 完整原失败栈 |
| 原 ledger caller | 48 tests，601.279 秒，3 failures | 完整原失败栈 |
| steps 28–66 | 39 个业务步骤 skipped | 原 terminal jobs API |

## 六个内部失败

| 原组合 | 原方法 | 原失败位置与结果 |
| --- | --- | --- |
| namespace | expired evaluation | `build_pair` 第一次 emit；`E_CAPTURE_TIMEOUT` |
| namespace | native timeout | 返回后的原 `< 5s` 断言；实际 5.602196661999642 秒 |
| namespace | reference loop | `build_pair` 第一次 emit；`E_HIA_REJECTED`，native build deadline exhausted |
| ledger | expired evaluation | `build_pair` 第一次 emit；`E_CAPTURE_TIMEOUT` |
| ledger | native timeout | 返回后的原 `< 5s` 断言；实际 5.583486049000385 秒 |
| ledger | reference loop | `build_pair` 第一次 emit；`E_CAPTURE_TIMEOUT` |

原上下文预算仍为 max_total_wall_ms=3000、max_native_wall_ms=1000。这里记录原结果，不据跨 runner 耗时归因硬件，也不据一次 cold 成功推断 fastpath 的因果效果。

## 原 artifact 和持有边界

Artifact `14006895740`，193,650,347 字节，SHA256 `d91c2215aa578cf915c06a3e52b6ca9aba38b52276dbe618fadc98d50ead1bad`。GitHub API 与原 upload 日志一致。当前执行环境不可用，本报告没有宣称已在本机下载或完成外层/内层 CRC。独立纯证据 collector 已收到该输入，将验证原 ZIP、源绑定和完整冷报告；业务不再执行。

完整 native log：`b6f9387f7e4f99af21ed437554253660f96a8105`；完整 source log：`2ca627194a95d843e0637f835bb0b89f15a5886d`；原 terminal authority：`e55507a1df058f566b978eecb23ebf95c26b2384`。以上全部已全文读回并核哈希。

本结果只绑定 a733；当前其他集成推进的 main `51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8` 是另一源码树。whole-native/default/deletion 资格没有由本报告闭合。
