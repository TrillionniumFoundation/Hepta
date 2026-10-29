# fc4a source/application 与 broad CI artifact 独立只读核对

本审查只解析下载的 ZIP、JSON、日志和不可变 Git blob，没有运行任何测试、native、编译器、solver、模型或 tokenizer。结论只属于保存的 fc4a CI 结果，不能替代新来源的 CI 或模型实验。

## 身份

公共来源 `fc4a63e8a5064c6f054a67ea2fe8dd56cbcb37a4`；本地同树来源 `79d7bb4891eca97546f08ff8abe5a0d1e50380ff`；tree `0d0fa474fa4a92ec842c8969873b3e5d87c6ca03`。

- source/application：run40813549738，artifact12871701719，48,137,959 bytes，SHA-256 `e1b81b42675a09002289119f7fdd24203c022b62449b1b588dda0d5e5cff8fc1`。
- broad：run40813549720，artifact12872245188，4,796,147 bytes，SHA-256 `cf6e4363e8b3a2c29451e0ae372dd67c3398ef7a51e93498aea7994dc3fd9591`。

两个 ZIP 的摘要和长度都与父任务保存的 GitHub artifact metadata 对应；审查没有复制下载 URL 或 signed URL。broad metadata 在主体审查完成后提供，另外使用 `BROAD_METADATA_CHECK.json` 绑定原审查和原 ZIP，没有改写原回执。

公共 fc4a commit 对象当时不在本地库，因此没有声称在本地独立重算了公共完整 Git tree；同树关系引用父任务的公开映射回执。本地79d7的tree已实际核对，所有被审查源码绑定均逐个与该不可变提交的 Git blob 相符。没有尝试网络补对象。

## 计数与证据

source/application日志有238条测试ID，238个distinct，regression.json为0failure/0error/0skip。safety.json的37个独立ID均通过；它与source regression有7个相同ID。

broad ZIP中的tests.log自身摘要匹配result.json，实际750条ID、750个distinct，无重复，0failure/0error/0skip。它与source regression有218个相同ID。因此不能把不同suite的计数相加称独立分母。新750来自实际日志，不是由历史756减31再加25推算。

449份独立lowering记录均为verified/unsat，Core和LLVM文件摘要吻合。SMT query摘要按生产者明确规则去除保存文件追加的`\n(check-sat)\n`后核对；完整文件另有manifest摘要。五个负控分别为四个refuted和一个rejected_profile。未重新运行solver或扩大证明范围。

reference PLAN/RESULT/逐行文件有19个唯一、有序、与协议一致的ID。每行逐项核对输入/查询/参考回答摘要、实际compiled/native_built、public接受、native/artifact/resource/VM门以及terminal hidden门；stdout的整数观察与记录、期望值一致，资源账目按已登记有限任务规则再次核算。HIA有实际VM观察；Rust的vm_contract_passed只是原验证路径的门标志，hia_vm为null，未把Rust说成经过独立HIA VM。

19个public和19个hidden执行记录包含54个public输入、472个hidden输入。19个实际ELF、8个HIA native object、8份HIA Core均在ZIP中，其长度与SHA匹配记录。reference源码快照170文件逐个吻合声明；结合safety902、scalar7、payload8、broad1580项清单，去重后的2,089个源码路径均与本地79d7 Git blob匹配。

工具可执行文件身份是远端生产者记录，本审查没有下载或执行远端编译器来认证它们。36项native NDU为另一独立job日志中的成功观察摘要，本审查没有重新执行或把它当作NDU净收益结果。

## 边界与复用

这些19项是human reference工程控制，model_requests、Agent successes为0，capacity/model qualified均为false。它们不重跑33c46cd上的模型资格，不证明语言健全性、普遍性能或远端硬件真实性。

`review_ci_artifacts.py`是本次实际运行版本，`REVIEW.json`绑定其摘要。它仅用ZipFile读取，不提取归档。`check_download_metadata.py`是随后实际运行的metadata关联检查。

`review_ci_artifacts_variants.py`只在相同逻辑上增加`--reference-prefix`，用于后续分别检查V8与V9输出目录；它尚未对未完成的新artifact执行，不能据此给未来来源通过结论。后续应给出该来源的真实ZIP摘要、source/local tree、metadata、计数和不同output目录；若有两套19参考，可分别指定各prefix并保留各自结果，不把38个执行行声称为38个不同参考问题。

全部原始检查结果均保留，未发现缺行、实际artifact缺失或源blob不符。科学验收门槛没有因本审查而变更。
