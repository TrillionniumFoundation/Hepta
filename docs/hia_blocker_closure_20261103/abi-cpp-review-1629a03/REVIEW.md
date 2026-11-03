# 1629a03：14 个宿主 artifact 严格来源复核

**结果：7/7 常规 ABI 宿主和 7/7 C++ 宿主的既有 artifact 均通过本次只读复核；两个 Windows C++ 宿主确实完成原生执行。**

源码 `1629a03dc76c5360550da40a6fc6fcbd80425128`，tree `06edb86c49637015630ce6097dcfd30921760f74`。ABI run 41605635685 的8个jobs全部success（本报告只审常规7项；standalone AArch64由root另审）；C++ run41605635663的7个jobs全部success。

读取14个已存在ZIP的内存副本，核对原始字节数与GitHub SHA-256，未展开归档、未执行其中程序、未触发重跑。`member-sha256.tsv`保留131个关键原始JSON/log成员的字节数与SHA-256；`review.json`保留每个平台的有限分母、来源检查、条件skip和job状态。

## 实际平台矩阵

|系统|架构|编译器|ABI artifact|C++ artifact|
|---|---|---|---:|---:|
|Darwin|aarch64|clang|13216517283|13215889650|
|Linux|aarch64|clang|13216581613|13216796246|
|Linux|aarch64|gcc|13217066116|13215993728|
|Linux|x86_64|clang|13216836269|13215859920|
|Linux|x86_64|gcc|13217080663|13215988319|
|Windows|x86_64|clang|13215959329|13216845972|
|Windows|x86_64|msvc|13216956557|13216492317|

## 严格来源与测试

- 七个ABI artifact均保留前后两个source log，内容精确为上述commit/tree；前后tracked-status原始文件均为0字节。stb报告前后输入一致，403个implementation文件与6个fixture文件逐项匹配该Git tree的原始字节。
- 七个C++ artifact的source_checkout_before与source_checkout_after完全一致，commit/tree正确、tracked_status为空、casefold_collisions为空。路径数量8659，完整路径清单SHA-256为 `62e8d12878e48bb864679944f90b36aa84d3d8a71da0fe26be4ad4e7c165044b`，与Git tree独立重建一致。read-only audit成功。
- C++每宿主16项unit测试均OK、无skip。ABI每宿主11项adapter、16项capture、4项original-type process测试均OK、无单项skip；5个POSIX宿主另各20项ownership测试OK，日志随artifact保留。Windows按既定条件跳过整个POSIX ownership步骤；非Windows按条件跳过Visual Studio环境步骤。
- C++实际输入清单为197项。Linux/macOS全部匹配原始Git blob；Windows189项匹配，另8个authored example输入仅LF→CRLF，清单保留全部路径，无其他不明字节差异。这是正常物化差异，不写成所有平台原始字节完全一致。

## 原生分母与负控制

- ABI每宿主两个优化配置各181次foreign call；3个实际类型编译拒绝和1个实际错误C echo拒绝。
- stb_divide每宿主21453个不同输入、两个宏配置，42906个输入/配置对；514872次原生函数观察、696次独立HIA解释器观察、24个仅进入安全目标的trap进程。三个不支持声明整包拒绝、不发布部分包；实际wrong-code退出2；C++entry以E_CPP_PROJECT_PROFILE拒绝。
- C++每宿主实际运行nlohmann/json 3.11.3和3.12.0。每版本98个direct/Hepta比较案例、32个生命周期案例、1024次并发调用，ordinary_live_delta=0。registry保留分配Linux/macOS为2、Windows为3，单列保留。
- 七个C++宿主均有实际wrong implementation退出2、实际不兼容签名E_CPP_NATIVE拒绝；原8个evidence负控制与新增4个checkout负控制，共12个精确名称的控制全部rejected。新增四项分别为same dirty before/after、缺失final checkout、结束时tree变化、casefold冲突。
- Windows MSVC artifact13216492317与Windows Clang artifact13216845972各自含完整两版本原生结果、native_ok、成功exit状态及上述12控制，均非setup_failed stub。

## 本次可闭合项及边界

本次证据闭合了这14个有限宿主profile的case-only历史路径冲突造成的脏checkout、同一dirty状态被旧validator接受、ABI主matrix缺少全tracked前后门槛，以及Windows产物路径回归误依赖POSIX resource导致原生资格未运行这几项具体问题。

这14项的Hepta原生目标/consumer经Rust后端；HIA解释器观察另列。standalone HIA AArch64与captured-C direct LLVM由root单独审查。报告不把有限宿主观察扩大成任意FFI内存安全、全部C/C++迁移、全语言类型健全性、任意设备/线程安全或完整P0–P7闭合。

旧5c的三个dirty宿主事实及d562两个Windows preflight失败均原样保留于各自目录，未覆写或重新标记。
