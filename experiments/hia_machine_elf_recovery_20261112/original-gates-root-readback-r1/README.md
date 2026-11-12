# 原始 ELF 51 调用方门禁失败：独立原字节核对

根因已经从两份实际原始报告定位，但当前产品尚未修复或重新通过门禁。

原运行 43117621509 / 43117632066 的 gate 均为 HOLD，实际 traceback 都在 tools/hia_compiler_owner_gates.py 的原源码成员约束处报告 ValueError: ELF original caller source bytes differ。保留的 51 调用方报告本身均为 SELECTED_NATIVE_ELF_CALLERS_PASS：预期、加载、执行的 51 个 ID 逐项顺序完全相同；五类异常计数均零，旧 writer 调用为零，原180秒/3秒owner自然返回且清理到ECHILD。

其四个测试模块的实际 SHA、原报告预期 SHA 和根代理从 acffa 直接读取的 SHA 全部相等。失败来自780项源码清单遗漏三条已执行的测试输入：tests/test_hia_machine_plan.py、tests/test_hia_machine_x64.py、tests/test_hia_safe_core_artifact.py。tests/test_hia_program_native.py 已在原清单中且 SHA 相等。

这些原报告通过事实不改写外层门禁 HOLD，也不改写两次历史 CI FAIL。修复必须补完整源码闭包，保留原成员断言、51分母、所有时限，并对新的精确源码重新验证。line821之后的构建文件/运行时完整性检查并未由本次诊断反事实执行。

原大包经独立只读取证转为固定小包，取回任务43132079819成功。根代理实际取得完整job log 1810149字节，SHA-256 9862af4f51694a3905a21727ed3b88547902abad8c7415c8d5a50f63f039e017，独立解码69帧/28文件/1312028原始字节，逐帧位置、长度、SHA及每个文件全文SHA均核对，无缺项。当前900/3取回owner自然闭合不构成产品资格；原产品scope字段、HOLD与false声明均原样保留。

所有 originals 下JSON均保存解码后的原文，未将大整数纳秒时间经JavaScript解析再编码。独立分析JSON为派生观察，不冒充原报告。修复候选、冷启动和完整5400秒验证仍待执行。
