# Hepta v7 与有限原生持续负载证据

当前冻结源码 `f5b6598bdd88db92c4ef2b17e10deda9a90bdd59`：full35 已记录 35/35 项，通过 34 项；外层 ok=false。独立 hosted profile qualified=false。原17条义务当前有限关闭 3 条，开放 14 条；其中14条更广义务保持开放。

**本次正式有限profile未合格。** 完整epochs=150；attempts=4982，starts=4982，confirmed reaps=4982，**completed observations=4981**。入口有观察=4831，入口结果不可用=151，总入口调用数=null。

本包绑定测试源码 `f5b6598bdd88db92c4ef2b17e10deda9a90bdd59`。项目完整P0–P7、生产长期负载、一般Rust性能超越和任意C/C++自动重写均未宣告完成。

- [REPORT.zh-CN.md](REPORT.zh-CN.md)：当前结果、故障修复、边界与成本解释。
- [results.json](results.json)：动态读取的最终结果与精确输入身份。
- [blockers.json](blockers.json)：原17条义务、当前判定条件及独立有限profile closure。
- [source-run-index.json](source-run-index.json)：两个新冻结运行的摘要身份。
- [raw-evidence-manifest.json](raw-evidence-manifest.json)：原始成员及整体归档身份。
- [raw-evidence-parts.json](raw-evidence-parts.json)：有序运输parts；按 [reassemble_raw_evidence.py](reassemble_raw_evidence.py) 校验还原。

旧PR335/de49交付及b921两次NDU计时仍保留原source；本包不重跑、不重标。失败、噪声、退化、缺失入口和未完成状态保留。开发负例、独立审阅、当前完整单元和正式hosted负载有不同分母，不相加。

报告生成器 `build_v7_soak_report_v3.py` 不调用子进程，不执行测试、不读取大型日志/归档数据，不自动授予新资格。所有目标文件以拒绝覆盖方式生成，packager原文件保持不变。真正仍活动或回收未确认的流程不能产出最终报告；已终止但缺少完整producer收尾的流程可以产出明确失败报告。
