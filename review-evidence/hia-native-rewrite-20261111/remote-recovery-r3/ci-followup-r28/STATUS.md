# 第28轮：原错误文本修复和完整失败定位

整套仍为 OPEN，生产旧实现保持保留。第27轮 `78fff04d3476a70a3513af0606a8c91a945ed6a5` 已完成159/159项源码语法检查；15个实际组件任务在本提交准备时仍在运行。源码语法结果不代表 HIA / B3 / native 通过。

## Worker 读取的确证差异

第25轮实际运行完成5个新HIA image的编译。semantic 115项/3,146 entries、unicode 106项/3,786、large 2项/72、protocol 46项/272 均通过。storage 完成9项/58 entries后，第10项 identity-artifact_id-NoneType 出现完整错误文本差异：原 AgentRejected 的 str 是 `cursor is not bound to this exact artifact`，新HIA多出了 `E_HIA_CURSOR: `。错误代码本来是异常的单独属性。

本修订只删除 literal20 中多出的文本前缀，保留其它作者源码、完整原测试与资源限制。选中新 storage gate 重新编译5个 image，执行原20项storage测试。此前四组269项/7,276 entries不重跑、不算成新修订的通过数。普通 Store 仍在外部边界。

## Wire 失败原件读取

原wire进程实际返回−9，CPU89.959978秒，wall90.2316秒，无terminal summary。只凭这个结果无法判断停在原生入口还是返回后的证据写入。本轮独立读取原ZIP，核对全部9,965个inner成员、完整CAS、每个已完成入口、源码及image绑定，并原样保全stdout、pending标记和最后完成入口，确定实际未结束的case。没有执行新native，没有增加原限额。

## 默认冷自举原件读取

第23轮原reader job成功，但两次读取完整日志遇到transport closed。本轮新reader继续完整读取、核对并保存所有原件；只有明确列出的关键原JSON使用日志base64传送，大型完整qualification原件仍完整保存在artifact，绝不截断、替换或重新生成。

分别读取第23、25轮实际通过与第26轮实际失败的独立原artifact，核对全部成员、580个导出源码和完整阶段ZIP，与先前候选的全部源码manifest比较，回收真实owner、期限、清理、reference/phase时间。通过与失败各自保留，不由reader成功覆盖原结果。

新清单共164个Python源。新修订在提交时的HIA、B3、VM及native执行计数均为0。恢复任务仅选中storage修复和四个原件读取任务；第27轮的15项独立验证继续以各自原HEAD运行。删除旧生产文件数为0。
