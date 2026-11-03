# d562d6d 宿主证据复核

源码 `d562d6d3dc4b9ea54f5692ec5945f3a42b30effc`，tree `78ed5f7ff68587e1e07865cbb921f369588307f2`。本报告只读检查已有 artifact，不是新执行。

七个 ABI 宿主的前后 source log 均精确匹配上述 commit/tree，前后 tracked-status 原始文件均为0字节；原有限执行分母与负控制不变，POSIX ownership 日志现在完整随artifact保留。

C++ 五个 Linux/macOS 宿主的 before/after 完整Git身份一致、tracked_status为空、casefold_collisions为空，8656个tracked路径的原始清单SHA与Git tree一致；各执行两个上游版本，原8个与新增4个共12个证据负控制全部拒绝。

两个 Windows C++ job 明确在15项unit suite中的generator publication路径测试失败：导入POSIX resource模块不可用；其余14项通过，qualification保留setup_failed stub，没有原生执行分母或clean qualification。修复提交6e33f40仅延迟真实measured的resource依赖并隔离纯路径测试；不伪造CPU，不加skip。新组合提交的Windows实际执行仍待核对。

14个ZIP字节数/SHA匹配API元数据；`member-sha256.tsv`保留127个关键JSON/log原始成员哈希。standalone AArch64和captured-C由root另审，不纳入此14项。

|Artifact|名称|状态|
|---:|---|---|
|13214483955|native-ubuntu-24.04-clang|strict_clean_qualified_for_declared_finite_host_profile|
|13214828665|native-windows-2025-clang|strict_clean_qualified_for_declared_finite_host_profile|
|13215043816|cpp-upstream-ubuntu-24.04-clang|strict_clean_qualified_for_declared_finite_host_profile|
|13215223722|native-ubuntu-24.04-arm-clang|strict_clean_qualified_for_declared_finite_host_profile|
|13215248690|native-ubuntu-24.04-arm-gcc|strict_clean_qualified_for_declared_finite_host_profile|
|13215313049|cpp-upstream-ubuntu-24.04-arm-gcc|strict_clean_qualified_for_declared_finite_host_profile|
|13215327888|native-ubuntu-24.04-gcc|strict_clean_qualified_for_declared_finite_host_profile|
|13215623631|native-macos-15-clang|strict_clean_qualified_for_declared_finite_host_profile|
|13215633113|native-windows-2025-msvc|strict_clean_qualified_for_declared_finite_host_profile|
|13215702491|cpp-upstream-windows-2025-clang|qualification_not_completed|
|13215727401|cpp-upstream-ubuntu-24.04-arm-clang|strict_clean_qualified_for_declared_finite_host_profile|
|13215792072|cpp-upstream-windows-2025-msvc|qualification_not_completed|
|13215960980|cpp-upstream-ubuntu-24.04-gcc|strict_clean_qualified_for_declared_finite_host_profile|
|13216040256|cpp-upstream-macos-15-clang|strict_clean_qualified_for_declared_finite_host_profile|
