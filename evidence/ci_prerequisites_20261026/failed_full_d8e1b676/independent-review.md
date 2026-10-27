# Separate reviewer receipt

The second reviewer `/root/review_task_io/ci_hia_forensics` read the exact d8e
originals, raw bytes, AST constants and immutable Git blobs. The messages below
are preserved as review correspondence. They are distinct from the executable
data-only verifier and are not a signed execution attestation. The reviewer
reported no compiler/native/qualifier execution, resampling, compression or file
writes.

## Metrics and unit denominators

> 从本轮 d8e 原件独立重算已通过：168 样本顺序逐行匹配各冻结协议（owned 使用 kernel-position，HIA 使用 original-kernel-index），每 cell 的 7 样本中位数/MAD/paired ratios 均与报告完全相同。Scalar LLVM/Rust 三核 signed_walk=1.0000819480497773、unsigned_walk=0.9927194064055778、branch_accumulate=1.016397478409726，geomean=1.0030176137864135，max relative MAD=0.003688021048344245。Owned 对 Rust 三核 full/constructor/two=0.9992923555776444/0.8623570055270009/0.9988913764456812，对 handwritten=0.9989817613939076/0.8620726281844218/0.5628503787824751；geomean rust=0.9512601598643909、handwritten=0.7855336480984962，max MAD=0.002034244909442441。HIA 对 Rust=0.9994745683359879/0.8600052551064754/0.9989111018893055，对 handwritten=0.9994060332313742/0.8516882012196885/0.998648515321479；geomean rust=0.9504586575880596、handwritten=0.947280112013114，max MAD=0.004131961727089743。三者 passed/complete 确认；均远离 1.2/1.1/0.05 门槛。实际 unit 终行 full Ran 2108 in 560.403s, OK；HIA Ran 2108 in 562.808s, OK；两者零 skip。正在收尾 telemetry/完整流哈希/留存及 Git 身份。

## Exact source and artifact availability

> 身份/留存独立核对完成：这批 d8e 的 source snapshot 是 923 项（不是 7ef 的 922），full + HIA before/after 三份 map 完全相等，canonical SHA256=0aad7ec72ebeae72eae1d76099c959c8e1ce109526204b5086ab3e8296c08601；923 个路径逐个 git cat-file 对 d8e immutable blob 全部 SHA256 相符，tree=ad5dcb9118c392ef35cc8621916580eed474621c。full 50 log+43 evidence=93 links、HIA 30 streams+14 evidence=44 links，所有留存文件 hash/所列 bytes 相符。HIA performance-artifacts 16 文件共 7,821,997 B + artifact-retention.json 7,026 B，manifest SHA256=1542fd024b8c4169138b043b23212e900a67e3e5c1785c8004a74fe37b82d0ec，16 mappings、4 timed binaries+4 controls/objects 均绑定实字节。扫描整份 downloaded artifacts：scalar 6 declared binary/object identities 全无原字节；owned 12 identities 仅 handwritten_rust_library 与 HIA handwritten_rust.so 同 hash 留存，其余 11 缺失；不能表述三组原生 binary 均封存。

## Observation, stream and correctness review

> d8e 独立复核收尾，无需再扩展检查；没有发现会改变本轮三 perf 通过结论的剩余数据/审计错误。
>
> Telemetry：scalar 42 条 process_observations 与 42 样本逐条 sample_index/group/kernel/backend/command 关联；owned 63 条与 63 样本同样关联。全部 state=complete、capture_exception=null，monotonic 起止/差值及相邻顺序正确；scope 与 d8e Git 常量一致。scalar 验证 252 个 Linux raw/raw_sha256（3 sources × before/after ×42），owned 378 个；三个 Linux 源及 children 的 snapshots/deltas 全部 observed，无 unavailable/reset/set-changed。scalar children delta 总计 user_cpu_ns=32175137000、system_cpu_ns=34614000、voluntary=42、involuntary=3693、minor_faults=3265、major=0；owned 对应89190059000、49675000、63、10030、5010、0。PSI some.total_us scalar=120099、owned=337544（host 与 visible-cgroup 各自相同），full.total_us 与 nr_throttled/throttled_usec 均0。这只能描述捕获区间，不能证明无其他进程/独占CPU或解释性能原因。
>
> HIA 63 行内嵌原生 telemetry 经 execution.stdout 逐字段绑定，汇总完全复算：CPU/wall min=0.9977149377961304、median=0.9983505463678655、max=0.998593210758537；involuntary switches=11796；voluntary/minor/major均0；samples_excluded=0、acceptance_thresholds_adjusted=false。HIA 不存在 process_observations 数组，不能把63条称为同型外部observer记录。
>
> 完整六字段 process receipts：scalar 0（不能声称42组stdout/stderr hash已核），owned70（63timed+2driver build+3observer build+2controls，rc69×0+1×1），HIA71（63timed+1correctness+2driver build+3observer build+2controls，rc70×0+1×1）。owned140、HIA142个stdout/stderr hashes全部重新验证；与630个Linux原文hash为不同计数。owned/HIA全部126个timing行 command、driver/library SHA 与各自artifact identity相符。
>
> 正确性强度：scalar独立复算186公式case（60 signed/56 unsigned/70 branch），原件报告372 native calls，未留存逐case实际输出；owned196公式case（58+58+58+22）、报告784 calls/4backend digest，四个digest均可由公式重建为836bbec9b9ef36c5aea12ee157346462e6ede4a407902222c4e319b51d94ea42，但也无逐case实际输出。HIA retained588 observations及correctness.process.stdout的588 JSON lines都逐项等于196case×3backend的独立公式结果，observations SHA=e38e6622adc4675c398fe4ef891742e61c9cfdce124f1f0b8364e36779d04aae，stdout SHA=b0fd14cdbf4bde80d0654552c3ec3d0ceda151c824c26d745c3baa5ac19a0192。owned/HIA各63 timing checksum全部按纯整数公式复算匹配：full=2016016049049797507、constructor=17884724386126693251、two=5035777366165914499。两profile positive=7alloc/7free/0live/1refusal rc0；negative=7/0/7/1 rc1；origin/rehashed mutation rejected flags均true。
>
> 本轮只读读取JSON/原始字节、AST常量与immutable Git blobs，并做纯数据算术；没有import/execute生产qualifier、编译器、原生程序、重新采样、压缩或写文件。
