# SQLite WAL 字节内核的 HIA 重写

这是新增的 WAL 校验和、32 字节头部与单个 frame 的 HIA 实现。原 AgentStore 的 SQLite 连接、事务、WAL 文件和默认安装入口保持现状；本目录不取得数据库写入或恢复权限。

实现算法来自 SQLite 官方文件格式和两个固定版本的完整 `src/wal.c`：3.46.0 对应 `bebe2d8be8acfd02592c4972f4ba32c3b4e4a33f`，3.53.2 对应 `ccc132c5be20ab5c755c97a08d06b1b592fef330`。`reference/UPSTREAM.json` 记录原件及原函数的完整字节、哈希和位置。两版 `walDecodeFrame` 原函数完全相同；checksum 原函数的差异在断言写法，两个版本分别保留。

HIA 函数接受三个显式字节跨度，执行所有格式判定与校验运算。校验每一步按无符号 32 位回绕；WAL 头和存储的校验值保持大端解释，校验输入依据 magic 选择字节序。Frame 校验覆盖前 8 个头字节和 page 内容，排除盐及已存校验值。页大小的有效范围为 512 到 65536 的二次幂；WAL 头中不把 1 当作 65536。

ABI 明确区分控制、输入和输出：每个拒绝都不修改任何跨度，成功仅写固定大小输出。内部 C `walDecodeFrame` 在校验失败时会改变 `Wal.hdr.aFrameCksum`；这里的独立字节接口保留不可变控制，不是原 Wal 结构的直接替换。后继恢复扫描必须以有效链和最后提交帧为依据处理结果。

十项源码控制使用完整 HIA/Core VM，不运行本机映像、SQLite 或 C 编译器。校验参考采用独立的 Fibonacci 加权公式，包含增量组合、已知数值、大小端、全部页大小、损坏输入、拒绝后的全缓冲不变，以及桥的外部写越界拒绝。独立 C 对照 adapter 仅供后继单独原生资格使用，目前未编译或执行。

后续还需要全量原生/C 对照、有效 WAL 链扫描、提交视图、锁、持久写入、检查点、崩溃恢复和升级迁移；一个校验内核不构成 SQLite 或整套 HIA 原生迁移闭合。

官方格式依据：https://sqlite.org/fileformat.html#walformat
