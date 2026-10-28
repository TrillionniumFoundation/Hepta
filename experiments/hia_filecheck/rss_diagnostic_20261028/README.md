# 原始二进制的 RSS 补充诊断

**原先 112 个样本都为 35,072 KiB 的 RSS，不应被解释为各实现本体的峰值完全
相等。** 在不改变 driver、动态库或输入的条件下，新控制显示直接启动时的
`ru_maxrss` 明显受 Python 启动进程的历史内存峰值影响。小型 C supervisor
先 fork 再 exec 同一程序后，观察到了约 1.5–3.0 MiB 的有限进程 RSS。

这是发现统一 RSS 后专门登记的**事后资源诊断**，不替换任何原始样本，
不重新运行原性能协议，不重算吞吐、P95/P99 或性能胜者。原性能优势 gate
仍为 false。程序原本输出的 timing 字段保留在原始 stdout 中，但没有用于
本补充的比较或选择。

## 做了什么

原始性能源码为 `96bc1b4598a8469b0d44b09e7e97d4705cac2cc5`，原报告 SHA-256 为
`d8271f1aa20aecc8f47da773006246278ea13f2422f7e142b514f27047dae09e`。
诊断工具、C supervisor 和协议先提交为
`c4efc29610fab58f495e38e22c7cb10b0d63c876`，然后执行：

```sh
python tools/qualify_hia_filecheck_rss.py \
  --original-report /tmp/hepta-six-filecheck-formal-01/qualification.json \
  --output /tmp/hepta-six-filecheck-rss-diagnostic-01 \
  --clang "$CLANG"
```

程序在启动前及结束后核对原报告、driver、八个库、输入、编译器和 supervisor
的文件身份；每次调用还核对目标文件。只构建了 supervisor，没有重新构建
任何被测实现。此处是受信宿主上的路径执行检查，不冒充 sealed loaded-image
证明。所有 60 次执行都完成了原有 checksum 和处理字节数校验。

- **48 个资源样本：**3 组 × 2 种 CRC × 8 个原有 arm，全部经过 supervisor。
- **12 个启动控制：**固定原 `hia_default` / IEEE，实现和输入不变；普通
  Python 与额外持有 64 MiB 已触页内存的 Python，各 3 组 direct / supervisor。
  普通控制先完成，之后才分配 padding；padding 在所有对应调用期间保持存活。
- 每次 supervisor 记录其 `/proc/self/status` 中当前 `VmHWM` / `VmRSS`，
  fork 子进程的 exec 前指标，以及 wait4 返回的完整子进程 `ru_maxrss`。

Linux [getrusage 手册](https://man7.org/linux/man-pages/man2/getrusage.2.html)
说明 Linux 的 `ru_maxrss` 使用 KiB，资源使用指标跨 execve 保留。这为启动
历史影响提供了文档依据；本实验仍实际测量了 fork 后的情况，没有假定 helper
天然能移除影响，也没有声称证明全部内核计数路径。

## 启动历史的实测控制

下表是同一个原 HIA 程序报告的 `RUSAGE_SELF.ru_maxrss`，各 3 次的中位数：

| Python 进程条件 | 直接 subprocess 启动 | 小型 C supervisor 后 fork / exec |
| --- | ---: | ---: |
| 普通 Python | 47,528 KiB | 1,616 KiB |
| 额外保持 64 MiB 触页内存 | 84,384 KiB | 1,500 KiB |

直接启动的增量为 **36,856 KiB**；supervisor 路径差异为 **−116 KiB**，落在这
组小样本的波动范围内，不能将负差解释为确定的内存改进。

48 个资源样本中，supervisor 自己的历史 `RUSAGE_SELF.ru_maxrss` 始终为
47,528 KiB，但它当前映像的 `VmHWM` 只有 1,348–1,436 KiB。fork 子进程在
exec 前的 `VmHWM` 为 768–1,004 KiB，`RUSAGE_SELF.ru_maxrss` 为
1,024–1,224 KiB。子进程最终 wait4 峰值为 1,492–3,024 KiB。

这些对照支持“原统一 RSS 被启动历史上界覆盖”的解释。它们没有重建已经
结束的原 Python 进程，不能精确归因原 35,072 KiB 中的每一页；原始报告和
112 个原始字段因此完整保留，而不是被新值覆盖。

## 资源补充结果

以下为 **wait4 取得的完整子进程峰值 RSS**。它覆盖原 driver 最后一次
`getrusage` 之后的输出及退出阶段，所以个别样本会高于 stdout 中自行报告
的值。每种算法、每个 arm 只有 3 个样本。

| 原 arm | IEEE 中位数 KiB | Castagnoli 中位数 KiB | 六次观测范围 KiB |
| --- | ---: | ---: | ---: |
| HIA 默认 | 1,548 | 1,652 | 1,540–1,708 |
| HIA native + LTO | 1,652 | 1,552 | 1,492–1,708 |
| C native + LTO | 1,568 | 1,552 | 1,496–1,612 |
| C native + LTO + PGO | 1,612 | 1,548 | 1,532–1,652 |
| C++ native + LTO | 2,824 | 2,984 | 2,824–3,024 |
| C++ native + LTO + PGO | 2,812 | 2,924 | 2,812–3,024 |
| Rust native + LTO | 1,876 | 1,844 | 1,780–1,908 |
| Rust native + LTO + PGO | 1,900 | 1,840 | 1,712–1,904 |

RSS 包含运行时、动态加载器、共享页面和剩余的小启动基线，**不是 HIA
活跃 owner 字节数**。这是非独占 Linux 宿主上原有小型 CRC 应用的有限
观测，不能据此宣称普遍优于 Rust、证明进程资源上界，或改变原性能结论。

## 证据

- [REGISTRATION.json](REGISTRATION.json)：执行前登记的协议、源码和目标身份。
- [DIAGNOSTIC.json](DIAGNOSTIC.json)：完整资源汇总、控制、来源与有限解释。
- [OBSERVATIONS.jsonl](OBSERVATIONS.jsonl)：60 次开始到完成的实际 argv、stdout、
  stderr、父进程状态、原程序数值和 supervisor 观察。
- [SUPERVISOR_RECEIPTS.jsonl](SUPERVISOR_RECEIPTS.jsonl)：54 份 supervisor 原始
  UTF-8 receipt 及其大小和哈希。
- [SUPERVISOR_BUILD.json](SUPERVISOR_BUILD.json) 与
  [ARTIFACT_MANIFEST.json](ARTIFACT_MANIFEST.json)：实际构建命令、诊断文件身份
  和未复制的 17,032 字节 supervisor 二进制身份。

完整实际输出仍在 `/tmp/hepta-six-filecheck-rss-diagnostic-01`。本目录只保存
文本；原生二进制保持在原目录，未添加到本补充提交。
