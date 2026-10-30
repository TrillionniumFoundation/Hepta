# 运行、资源与原始证据的独立审查

当前源码在本审查范围内没有未解决的发布阻断，可进行一次已注册 CI 复制实验。真实 CI 结果与原始 artifact 尚未由本审查执行；这些控制不能计作模型答题或性能结果。最终源 SHA、分组结果、静态边界与限制见 `REVIEW.json`。

## 最终源码上的控制

| 组 | 结果 | 范围 |
| --- | --- | --- |
| 资源 | 18/18 | 假 kernel/cgroup 元数据、阈值、祖先约束、未知与 hybrid 拒绝 |
| tar/基础 IO | 9/9 | 7 项微型 tar + 2 项重复资源控制 |
| 固定下载 | 8/8 | 假 HTTP、绝对超时、逐块字节上限、SHA、HTTPS 与增量成员限制 |
| 停止 | 11/11 | 模拟 WNOWAIT 锚定、所有退出路径、失锚、cleanup 异常、时间预算 |
| 凭据 | 4/4 | 假 token/HTTP；子环境净化，收据无 Authorization 或临时签名 URL |
| 最终上传 | 11/11 | 微型 raw、payload/链接拒绝、失败部分字节清单、未知关闭与资格拒绝 |

不把历史重跑或重复控制相加为独立用例。最终运行在 `final-source-controls02/`；包含11个受审文件的确切源码快照，运行前后全部 SHA 一致。

## 失败记录保留

最初的 hybrid 准入、进程组 reap 顺序、部分文件漏登记问题及修复前结果全部保留。`HISTORY_FILES.json` 列出原文件大小/SHA。

第一次最终重跑中，我将控制脚本命名为 `resource.py`，遮蔽 Python 标准库，导致其余组在 import 阶段退出。这是审计器自身错误，见 `HARNESS_FIRST_ATTEMPT_FAILURE.json`；失败脚本、stderr 与执行报告原样保留。只将控制脚本改为 `control_resource.py` 等新文件名后，在新目录完成重跑，未为此改动生产或实验源码。

## 资格与成本边界

CI artifact 中 `RECOVERY_RESULT.json` 是最终权威；`FINALIZE.json` 只是最终 inventory/staging 前的检查点。来源复制失败的部分字节仍有实际大小/SHA，但标记 `source_copy_verified=false`，不得获得资格。下载缓存、GGUF、runtime 安装包与符号链接不进入上传目录。

正常原 engine.close 收据保留。冻结的 HIA Clang 可以另开 session，outer 组清理不能声称所有后代都已退出；缺失收据保持未知，外层失败导致不完整，fresh VM 最终回收是剩余边界。

所有审查均为纯模拟和微型文件，没有模型调用、下载或原生工作负载，也没有给真实进程发送信号。真实 CI 的资源、模型响应和最终字节证据仍待实际观察。成本按父子区间关系保留，不重复相加；上传、provider 内部与人工等未知项不填零。
