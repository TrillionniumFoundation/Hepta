# Windows 示例源字节差异的精确解释

原 WINDOWS_ARTIFACT_AUDIT.json/SOURCE_BYTE_COMPARISON.json 如实保留 16 项原字节差异，不能把 Windows 和 Linux 工作树文本表述为原字节相同。

后续只读核查证明：这 16 项是两个 C++ profile 各 8 个相同 example 文本。每个 Linux 原文件均为纯 LF，且 Git blob 精确匹配冻结 HEAD。仅把 LF 替换为 CRLF 后，16 个 SHA256 均恰好等于原 Windows source_inputs 记录；没有做其他文字、空格、数值或路径内容变换。SOURCE_EOL_AUDIT.json 保存每项两个原 SHA、转换后 SHA、Git blob 和原控制器终态。SOURCE_EOL_AUDIT.stdout 是本次只读核查的原始输出。

196 个 C++ source inputs/profile 的其余原字节已经完全匹配；ABI/STB 的 477 个 implementation 文件记录/profile 无原字节差异。此补证解释同一 canonical Git tree 的工作树换行表示，保留平台 backend、原生执行 profile 和 source commit 的区别，不增加 native execution 或 CI rerun。
