# 下一阶段统一资格：原始证据

本次在同一份前后不变的源码上完成 **24/24 门槛**；单元与集成测试
**815 项，0 跳过**。源码快照：

`56b53e2b1273a4b9f14303112a4e90f4793bbf6ea514739f05bbe8ac843b92e6`

编译器身份：`bfda682563f70a99d6c7c3e2de11c614b70c277785cb50f5a5047f93f32c803d`。
完整索引是 `manifest.json`，逐项状态和命令见 `release-validation.json`。
所有报告与日志保持原始字节；原路径映射和 SHA-256 位于索引中。
资源图和生成 C 迁移源码一并保留，许可证与 NOTICE 随生成派生文件保留。

## 本轮完成的增量

- 有限 `Copy` / `Owned` 泛型；三个原生资源项目；独立检查六个抽象泛型函数体、
  十六个调用和十一个图变异拒绝对照。完整的三份序列化 IR 可直接重新验证。
- 完整冻结的 Ring-Buffer C 模块：二十二个活动声明、16,384 次状态转换、
  65,544 次差分调用、543 次零长度 NULL slice 调用、九个实际进程边界拒绝。
  另写的 Buffer owner 有六次真实正常／提前返回／分配失败／恢复调用。
- C++ v2 带参构造接入实际 Boost.Math 与 std::vector；五个合法、三个非法 Boost
  构造输入，八个 vector 案例，五个指针反例，八个 schema/native 拒绝对照。
  生命周期与方法成本分别测量。v1 ABI 独立比较及冷启动／扩容清理审查另有归档。
- channel 单调期限和显式取消；五场景各三轮。取消后仍要求 join，期限没有硬实时保证。
- 五个跨文件任务的 prepared/published 两点真实进程退出：十案、624 个隐藏原生输入。
  普通四臂参考脚本另有二十组、1,248 个输入，严格 workspace 正常路径另有五案。
- 四实现性能矩阵保留默认 C、显式循环展开 C、Hepta/Rust 和独立 Rust 的全部
  224 个样本，所有观察到的退化均保留。新发布门槛核对唯一分母并重算派生统计。

## 有状态 C 模块的本次成本

七次交替顺序样本，中位数为一次完整工作负载的纳秒；包含 ABI、状态复制和检查。

| 工作负载 | 原 C ns | Hepta ABI ns | Hepta / C |
| --- | ---: | ---: | ---: |
| single_byte_enqueue_dequeue | 4.716 | 5.629 | 1.194× |
| 64_byte_enqueue_dequeue | 249.236 | 118.467 | 0.475× |
| count_empty_full_queries | 6.412 | 6.763 | 1.055× |

## C++ 动态 handle 的本次成本

每行七次样本，每次 100,000 次操作。生命周期行包含一次创建与一次销毁；
方法行排除创建／销毁。原生对照在独立 TU 中执行相同库对象操作，无 LTO。

| 路径 | native ns | handle ns | handle / native |
| --- | ---: | ---: | ---: |
| handle_vector_create_destroy | 31.172 | 105.279 | 3.377× |
| handle_student_create_destroy | 13.682 | 82.447 | 6.026× |
| handle_vector_size | 1.354 | 18.844 | 13.922× |
| handle_student_degrees | 1.354 | 19.020 | 14.050× |

这些是本机有限样本；动态生命周期保护有实际成本。没有据此声称普遍快于 C/Rust。

## 历史失败与仍开放的目标

C 游标负索引、混合 char 数据模型、ABI 宏覆盖，以及证据门槛的错误接受和过紧范围
都有修复／反例记录。历史有限通过、失败、审查后修复和当前整轮结果分别保留，
没有重写旧报告的源码身份。详见 `../next_blockers_audits/`、
`../audits/c_record_views/`、`../audits/cpp_constructors/` 和 `../cpp_constructors/`。

`whole_project_blockers_closed=false`。全部 P01–P12 的完整生产目标仍按
`../../docs/BLOCKERS.md` 保留。外部 C/C++ 指针 provenance、借用不保留、分配范围
和线程安全依赖明确契约；抽象证明与 IR 检查没有证明真实编译器整体健全性。
本次没有真机板卡／GPU 资格或普遍性能优势证明。

**真实模型运行数为 0。** 当前 API 凭据缺失、域名解析失败，没有 API 请求；
模型生产力对照、人工修正时间和实际模型费用不能用这些脚本资格替代。
