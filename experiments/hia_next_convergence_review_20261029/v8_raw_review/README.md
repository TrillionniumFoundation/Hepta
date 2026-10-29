# V8 原始账本与根报告独立只读核对

冻结原始来源：`33c46cdef12c60faf0c1dbef02ea20caa3ad7d56`。
原始 RESULT SHA-256：`7f411804f0c161b5ffbc7d54d4065504074e0a3e2acfafac1ba4b1fe009567fe`。

独立脚本只使用 Python 标准库读取 JSON、SSE 和源快照并计算摘要，没有 import/运行实验实现、模型、tokenizer、native、编译器或测试。8份真实payload prompt IDs与preparation、cell响应一致；SSE拼接文本和输出IDs、final prompt_n/predicted_n、完整usage与cell逐项一致。合计19014 input +3398 output =22412，8/8完整，无遗漏失败请求成本。

逐任务为2/3/3次提交。API三次2072bytes/790tokens逐字相同；owner三次794bytes/280tokens逐字相同。它们分别被类型片段与表达式trailing-token规则拒绝，无build/public/hidden；此处不能把独立的overlap披露缺口解释为实际拒绝原因。标量任务第二次是唯一public native和terminal hidden执行，均正确，首次提交正确数为0。资格1/3不通过；main实测拒绝保持0cell/0model；没有HIA模型对照。

实际transport wall合计2015.752181147s，generate包装调用合计2015.920246400s，资格experiment wall为2059.597590950s；这三个嵌套计时不得相加。独立capacity/reference阶段64.003405956s与main拒绝5.690141661s另外保留。三个独立注册阶段计时相加2129.291138567s，仍不含完整开发/人工/取得/外层启动等成本。

166个源快照文件与全部记录绑定一致；plan/result/capacity的模型和工具声明对应，39条runtime文件身份前后相同，三项cell边界均为true。owned server退出依据原始shutdown记录exited=true，不冒称本审查独立观察了历史进程或重新哈希4.7GB模型。

SERVICE_CALLS保留40次未ready的startup health轮询、1次成功health、1次props、8次apply-template、18次tokenize。未ready健康检查不是模型生成请求。初版审查脚本错误要求所有health调用成功，因此停止；初版源码和stderr一并保留，最终版本把health结果单列、要求所有非health调用成功。未改变生产者数据或实验门槛。

`REVIEW.json`给出逐请求核对结果和边界；`READ_FILES.json`绑定所有读取文件；`ROOT_REPORT_REVIEW.json`记录根报告读版本及两个最小修订建议：历史668/735/756均为包含重复模块的执行次数；单列已知capacity计时。新CI结果和新V9结果需要各自来源，不由本审查推定。
