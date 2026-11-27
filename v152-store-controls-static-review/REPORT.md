# Store R2 静态审查：未发现所审范围内的确定性阻断

本次只使用 Git API、functions 内存和纯 JavaScript。**没有文件系统调用、Python/HIA 执行、编译、Native/VM、owner、reader、CI 或 ref 操作；资格仍为未执行。**环境不可用，旧 inode/stat 不作为当前准入。

## 完整源码恢复

原 recipe `a17bc43b40e80f6bb93866919625871e5d8c9660` 的 capsule `ee8aabd17c0900ba117a19370e9f76bb70bc9c25` 已从此前完整 GET 的原 bytes 在内存中解码。30 文件、438,241 B 全部按原长度、SHA256、Git blob 与 zlib Adler32 校验；其中 R1 14 文件、R2 16 文件。六个实际控制源码将各自以原全文独立 Git blob 交付，原 PLAN/MATRIX 直接保留原文本，不将大整数 stat 经 JSON 重写。

另从先前完整 generation author capsule 恢复准确 source map，直接 map GET 的失败如实保留。实际 VM 与 Native mapper 两源已 fresh Git fullGET 并核完整 pins。阅读其 invoke/loan.end/mmap/mprotect 接线后，未见借用参数必然在返回时失效等静态启动阻断。

## 全帧比较与可达性

每次实际 Native entry 调用之后，计划由真实 Core VM 从同一组完整前像调用一次。每个调用保全 6 个 Native 逻辑 before/after、6 个物理 before/after、3 个 VM-after 文件，共 15 个完整 payload。父 frames() 逐文件重读、核长度/SHA/Git、真实两端各64B guard、物理区间互不重叠、readbuf 不变，并比较三份 Native-after 与 VM-after 全 bytes。INDEX 与 AFTER/BEFORE/NATIVE-AFTER 的时序字段也被逐项核对。

我按六源实际循环和 action 轨迹独立重建全部 ID 顺序及每 case 调用数，所得完整顺序与 MATRIX/PLAN 一致。118 个 head case 对应1,009对调用；130个catalog case对应130对；总计248个ID、1,139对。两次 compile 加25组为27个owner。此为静态可达结构，任何早期断言/预算失败仍会停止，不能称已经执行完这些分母。

| 固定组 | case ID 数 | 预期 Native/VM 对 |
|---|---:|---:|
| head-genesis-commit | 3 | 75 |
| head-partial-eintr | 8 | 230 |
| head-replay-conflict | 3 | 27 |
| head-lost-ack | 12 | 192 |
| head-eintr-refusals | 5 | 96 |
| head-effect-errors | 15 | 199 |
| head-protocol-errors | 8 | 17 |
| head-sha-format | 22 | 56 |
| head-generation-boundaries | 4 | 28 |
| head-abi-extents | 19 | 19 |
| head-dirty-seal | 17 | 29 |
| head-terminal-observe | 2 | 41 |
| catalog-genesis-empty-pages | 11 | 11 |
| catalog-ten-single-transitions | 10 | 10 |
| catalog-joint-transaction | 1 | 1 |
| catalog-all-table-transition | 2 | 2 |
| catalog-uuid-generation | 5 | 5 |
| catalog-header-selector | 15 | 15 |
| catalog-extents | 16 | 16 |
| catalog-table-order | 12 | 12 |
| catalog-root-bindings | 21 | 21 |
| catalog-sha-corruption | 18 | 18 |
| catalog-change-mask | 7 | 7 |
| catalog-dirty-scratch | 9 | 9 |
| catalog-count-boundaries | 3 | 3 |

## 失败与预算

原180+3 owner、VM每次10M steps/8MiB heap/depth128、编译20s/10CPU/1MiB、16MiB capture、4MiB完整metadata shards及1GiB实际文件系统floor均保留。原Root1800+3外层仍需由Root独立launcher实现，六控制自身不另装该watchdog。完整source3210/runtime2496和全部先前证据在每阶段fresh重读；没有缓存代替、自动retry或缩小case集合。

Python可见失败在finally保留帧和异常；真正进程死亡可能没有after/INDEX/RESULT，必须按owner/outer真实失败和partial原件记录。len(calls)是已建立调用记录数；异常死亡期间不能仅凭它断言实际进入机器码。成功路径另外要求returned/complete及每row一对真实调用。

## 真实持久性边界

这些控制不会执行Store实际FD协议。head的锁定、read/write、rename、fsync、close及errno/丢ACK仍是开发控制输入；没有实际重启/断电/并发writer。catalog已设计完整十表根格式和一次代际更新，但未证明行页图、全部十表操作或持久事务。ctypes/mmap及证据文件写入也不能当作Store后端已实现。

下一真实生产层仍需 held-FD effect owner、精确durable-unknown处理、可验证row/page图、重启/崩溃恢复、并发序列化与原Store完整行为。SQLite替换、默认切换、current-cold、whole和durability始终没有被本次审查授予。

**结论：六个完整控制在所读范围内未见确定阻断；所有真实编译、1,139对Native/VM、时间/空间和当前守卫仍待Root实际执行。**
