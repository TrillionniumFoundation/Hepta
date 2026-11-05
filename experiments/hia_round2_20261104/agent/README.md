# Hepta round2：唯一正式Agent队列原始证据

固定5ee/d47a，16/16 cells、26 attempts，四臂均0/4正确；8格公测/验证失败、8格timeout。
这份交付不运行模型、编译器、evaluator、VM或native程序，也不改变原correctness分类。
原始结果、独立审计、外层成本与独立算术peer可直接阅读。

下载此目录全部文件后，在任意目录运行：

```sh
python3 /path/to/agent/RESTORE.py --source /path/to/agent --target /new/absent/output
```

parts均相对此目录解析；RESTORE核每part、整体archive、每member、全部原路径/字节/权限和目录集合，
包含嵌套空目录，恢复文件为独立普通inode。原mtime/ctime保留在manifest，不声称目标历史时间复原。
已实际在搬移后的独立包目录启动fresh Python完整恢复；所有原件末尾再hash且成员集不变。
模型权重、工具链和credentials没有纳入；OMISSIONS保留原引用身份，不能称只解压即可hermetic模型复验。
10模型会话全部reaped，2次kill-requested/−9后实际wait/reap，不推断OOM。observer完整stdout和已知job元数据保留。
实际outer4405.504830151秒；四臂solo是复用同一observed common的替代费用分配，不可相加，非单臂另跑的预测。
输出已知下界4996、8attempt输出未知；total output及各臂cost/correct仍null。
归档压缩、恢复、读取与上传属于交付账本，不添加到原实验outer。
