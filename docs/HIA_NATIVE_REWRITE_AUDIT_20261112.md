# HIA 全量原生重写审计（2026-11-12，FOLLOW47）

## 当前结论

**整套仍为 OPEN。完整保留版4,157项回归原件已完整核实；固定程序服务、UnixOpen父层和P16私有controls已在各自限定范围通过，Emitter三轮覆盖55组732案。真实FS/Store/SQL、公开上下文、impact大输入CPU、完整工具链/平台/API和HIA原生安装仍待闭合。生产激活0、旧实现删除0。**

## FOLLOW47 最新状态（2026-11-12 11:16:49 UTC）

父状态FOLLOW46 `293e80c81056345b846c42005c45b980fbc5d6fc` / tree `c8b09ac702e61cef04c120b12b7098ced93f8005` /6,383文件。整套仍OPEN、生产激活0、旧实现删除0。以下实际结果与本轮尚未执行的新源码分别记录。

### 完整原件和实际通过的范围

- 全保留回归37的只读reader46 job131135269906正式SUCCESS/PASS_READ_ONLY。原33,465成员、30,113普通文件、3,713,148,003B全量逐字/mode验证，输入before/after相等。根从完整原log无损恢复原QUALIFICATION 1,054,407B（Git51853be69fcb15deaf293dc1ac1a0e68466902e1，SHA25612ee5cb997e3aec1a4c1d235d207d3165ed347231a25f7c9fcb7915d1e3d336f）和原regression178B（Gite9834a7961509fce2f0ae0bb98c0d422c5d55b83），两原文本再次完整Git回读。gzip完整流、CRC32、ISIZE、编码及原始SHA256均核实，没有JSON重序列化。原件明确4,157/4,157、五种非成功列表全空、28阶段全部0退出/无超时，cold_qualified=true，whole_native_delivery_qualified=false。43/45 reader的旧失败及最初187errors/1failure/18skips原FAIL保持不变；本轮不再重跑回归或reader。
- P16剩余17个私有controls job131135269681正式SUCCESS：7次fresh B3、1次HIA packer，17案/65次私有native入口（role51=8、role56=57），0个ELF/public案例；整组实际0.801874 CPU秒。七source/image与45实际原件逐项相同。完整459,596B原log及两段原JSON均保存。45已完成83案/630入口、44其它177成功案仍是各自原结果；四个公开诊断全文失败与groups6/9仍OPEN。本轮只存证，不重复这17案。
- UnixOpen父层job131135272610正式SUCCESS：1次fresh B3、85语义案、42protocol controls、88次原C参考调用，833 VM与833 native入口逐次一致（694 semantic+139protocol），所有源pin不变。新HIA profile为33functions/578blocks/2419ops/max93blocks-per-function/13params。11个目标子进程合计96.33401 CPU/102.170697511 wall，明确是跨进程合计；各原90CPU/180wall及整套900wall门未改。该父层仍有18个foreign effects、实际namespace syscalls=0，不能据此宣布真实文件系统、普通Store或SQL闭合。完整452,771B原log与原console投影已封存，151成员工件的完整disk summaries另由本轮只读reader提取。
- Namespace成本job131135272544正式SUCCESS/PASS_COST_DIAGNOSTIC_ONLY：18个确定性原窗口、6角色、36次fresh原VM执行，0B3/0native。整个诊断19.20321699999998 CPU秒/19,263,307,646ns。未profile的采样子段中，原VM invoke3.631170283CPU秒，首次Machine构造含decode0.142095635秒，第二次as_dict0.175736005秒，完整比较0.001001047秒，hex/JSON0.004003615秒，完整gzip0.015997337秒。gzip细分与总量有重叠，不得重复相加。样本主要在VM执行；这不是对原900秒整套的加权归因，更不能声称去掉第二decode即可解决超时。完整438,276B原log保全，18份cProfile原件待本轮204成员只读读回；没有激活候选优化，也没有重跑原900秒套件。

### 已定位的失败与精确修复

- checked-plan46 job131135270126实际五核B3全部PASS，随后shape0在加载测试依赖时仍硬绑定旧builder摘要而失败，实际semantic entry=0。完整1,300,682B原log、五份完整build JSON及原shape0失败保存。本轮仅改测试BUILD_SHA为已实际使用builder的完整摘要，并同步CI该测试的两身份常量；生产作者、测试体、55组679案119私有controls、全部门不变。
- Type-context46 job131135272555实际3次B3全部PASS，但7组均在进入native前导入错误旧名hepta.hia_composite失败，0完整case/0semantic entry。真正原模块是hepta.hia_program_composite，原Gitb06d009e403e77288a19eb929e6296bf68532db3和SHA256cc5ab4…本来正确。r2只改测试的import与路径两处拼写，逆替换必须逐字恢复旧9,233B；在任何restore/B3前先核原composite/program完整bytes/mode/Git/SHA，三fresh源/像必须与46实际原件相同。原7组118案（54public oracle+64private controls）及所有workspace/output/context比较门不减。
- Worker bridge r3修正实际decoder返回后scratch契约：使用自身保存的issued config，核实际cursor、nodecount、poolend和finaldepth；不再把被原decoder作为key/stack复用的workspace48/56误当保留的入参。旧错误depth私有反例改查实际depth96；原input/type/program/decoder/DataGraph均不改。仍需23fresh B3、3+3+2+121=129案、27实际program ELF及原全缓冲比较，本轮提交前无新执行。

### 大输入性能诊断和后续接线

新增机械timing入口先只读impact41完整3,090成员/150,697,441B，绑定原63个HIA语义源/镜像，逐字复现原prefix与整个旧ELF。四处调用前后hook仅改机械执行器，逆变换必须恢复原全部汇编。只新编译1个原限额HIA packer，并用其真实入口生成新完整ELF、核全部操作数和canary。

采集仅执行三个实际ELF进程：原ELF的小原案、带计时ELF的同案，两者返回码/stdout/stderr都必须逐字等于原件；然后在精确8,370,475B large-valid输入上执行一次带计时ELF。原63语义像不改，不重跑原未计时大案。整采集父子聚合CPU仍<90、wall<180、1GiB；子进程只获剩余额度向下取整再减4秒保全余量，小校准另限12CPU。全部raw stdin/stdout/stderr和128B timing frames保全，独立只读分析器再核每帧/配对/全文件前后摘要。before→after含hook开销；缺失after只能说明没有完整记录，不能断言精确在途HIA调用。三个窄静态审阅均0执行，不冒完整63核验收。任何测量仍不能改写原large-valid的90秒/-9失败；性能修复之后还须回到原未计时13组329案验收。

本轮另只读UnixOpen45原47成员，以及46成本204成员+UnixOpen151成员；不执行被读HIA/B3/VM/native。新FS9空C字符串aliases、raw FS framer和registered-file只读FSTAT续接只作inactive源码检查点，0AST/生成/B3/VM/native。r2元数据次序与r3 generation递增假设的已发现问题均明确保留；后续修订和真实固定issuer、其余10个peer及联测仍在开发，没有接入当前执行门。

本次精确选择6tag：Worker桥、checked-plan、type-context、impact计时、UnixOpen45原件、namespace46原件。136个workflow job保留136个Ubuntu24.04/x86_64域门；663个活动Python源严格ASCII码点有序，新增/替代源中的直接hepta模块引用已静态对照当前原模块路径，未发现悬空名称。50个旧活动路径退出选择，但旧文件、原失败和未执行草稿全部仍在Git。原资源/Profile门、公共1024函数与Bootstrap容量界线均未变。

参考：[FOLLOW46实际CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43204248178)、[完整保留回归37](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43180758665)。完整公开编译/CLI、Worker实际错误上下文与namespace/Store/SQL、各平台/API、HIA安装/恢复和原生冷启动仍须闭合；本轮不删除旧整套。

## FOLLOW46 最新状态（2026-11-12 10:48:42 UTC）

父状态FOLLOW45 `19c9343da44ef5822c02209638b4f24a5dd7e1c2` / tree `46a7bc986926ea84d7efea0523694e43c280ad07` /6,270文件。当前整套OPEN、生产激活0、旧实现删除0。FOLLOW45的642份活动源码预检查实际SUCCESS；本轮656份源码仍须在精确提交上重新检查。

### 已完整核实的实际结果

- 全保留回归37的精确原件现确认：**4,157项加载、4,157项实际执行，errors/failures/skipped/expected failures/unexpected successes均0；28阶段全部成功**。只读45 job131126029128完整读取33,465成员、30,113普通文件和3,713,148,003原字节，所有成员模式/摘要及下载输入before/after相等。原QUALIFICATION全文1,054,407B、原regression JSON178B已在reader工件13935607086完整保存。该reader最终仍FAIL：所有归档/回归断言之后，完整控制台base64超900,000B安全限额；不能把reader终态改成PASS。下一版只对大原件做可逆gzip、核完整解压和编码/原始双摘要，保留全部raw文件及原console限额。旧4157/187errors/1failure/18skips的原FAIL/HOLD仍原样保存。此成功属于完整保留版，whole_native_delivery_qualified仍false。
- Emitter44 job131116461034实际SUCCESS：11次fresh B3，剩余9组60案、3,784次native入口、50私有controls全部PASS。六protocol组共2,345入口，两个late为549/618，profile8案为272。根从39/41完整原JSON文本和44九份原JSON独立计算：三个实际run的成功集合恰好覆盖原55组、732案、1,554,267入口；没有重叠或遗漏。**这是三轮覆盖并集，不是单轮55组PASS**。原39/41失败、完整原日志和原JSON均保留；public backend/外层输入/安装仍OPEN。本轮仅保存该结果，不重跑Emitter。
- checked-plan44原snapshot fresh B3成功；wire_scan在生成profile时maxSSA2187触发原SSA<2048门，wire_scan B3=0、全部语义=0。新修订仅对冻结HIA文档中的SSA标识做双射重命名，要求逆映射后整个原文档严格相等；函数/块/边/ops/types/attrs/literals/order均不变。仍要求5次fresh B3、55组679案和119私有controls。不得新增或声称存在128ops/block门。
- Worker bridge45 job131126028955的23次fresh B3和1次HIA packer通过，四个runtime组均实际尝试，但完整案例为0；每组真实P16成功后，output owner错误核验decoder复用scratch中的旧入参，实际reason1057拒绝。完整513,239B原log及逐字原打印JSON保全；旧SSA修复成功不代表整桥通过。真实decoder scratch契约修复另行继续，本轮不伪造结果。
- P16 private45 job131126029053完成83个controls/630次native入口，第84个child-binding-9触发旧harness硬断首返回NEED；冻结catalog对error999应返回BAD。完整453,707B原log和原JSON保全，具体单次返回寄存器没有从原log猜测。本轮只执行原索引83..99的17个controls，要求实际BAD并将原ACK原样交给真实父层、检查永久拒绝；7个fresh source/image必须同时与44/45原身份相等。原83和其它177成功案不重计。四个公开全文失败、groups6/9及完整上下文仍OPEN。
- UnixOpen45 job131126031828实际FAIL于HIA author的unsupported Break，尚未进入B3、C reference、VM或native；源码不变。完整429,596B原log已保存，console投影明确不是工件中4,954B完整summary。r2仅把唯一break改为原Builder支持的短路while，反向替换必须逐字恢复原25,163B source；六原C函数、全部fixtures/validator、85语义案/42protocol/88原C调用及所有预算均保留。18个effect peers仍foreign，不能称普通Store完成。

### 本轮新增的实际验收入口

- 原namespace参考成本诊断先核完整42工件4,272成员，然后为6角色确定性选择first/last/max-workspace原窗口，至多18个。每个窗口使用两个fresh原Machine执行，分别记录分段CPU/wall与完整cProfile；完整return/input/output/workspace/steps逐字比较。整诊断仍90CPU/180wall/1GiB，0B3、0native，不重跑原900秒套件；尚未以任何候选优化替代原reference。
- 原生type-context owner和reader计划3次fresh原0e09 B3，7组118案（54公共oracle场景、64私有reader controls），33种完整上下文及6个操作。必须先逐字重现旧owner，再比较完整旧/新128MiB workspace和64MiB output；仅明确排除新64B context及5个原error6→公共正确error5的优先级字。真实program/constructor/services的context续接仍待完成，这个独立门不会提前关闭四个公开P16差异。
- 精确选择6个tag：checked-plan、namespace reference成本、type-context、UnixOpen r2、全回归只读证据输出修复、P16剩余17controls。新源码在提交前0新AST/HIA/B3/VM/native；133个workflow job保留133个Ubuntu24.04/x86_64域门。33个被替代旧活动路径只退出当前语法选择，旧文件全部仍在树中。

原B3 10CPU/20wall/256MiB及各1MiB容量、Bootstrap128functions/1536blocks/8192ops/256blocks-per-function/16params/SSA<2048、公共1024函数、整组90CPU/180wall/1GiB和物理900wall全部不变。impact大输入的实际原生90秒CPU阻塞继续用机械计时定位；公开编译/CLI、Worker/namespace/Store/SQL、各平台/API、HIA安装器和原生冷启动仍须逐项闭合。

证据定位：[保留回归37](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43180758665)、[Emitter/checked-plan44](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43198781230)、[实际失败及原件读回45](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43201563676)。完整原JSON/u64保持原字节，计数与解释另列derived文件。

## FOLLOW45 最新状态（2026-11-12 10:25:48 UTC）

父状态FOLLOW44 `f8526c3b6f47f6061564707a9fbaa32d2f52704d` / tree `04dc32f12e9e592bc7de096930e21ae60598f386` /6,136文件。整套OPEN、生产激活0、旧实现删除0。FOLLOW44的638份源码预检查已实际SUCCESS；没有改变原语义门。

### 新的实际证据

- 私有固定诊断目录job131116460812实际PASS：2次fresh原35ee B3、181+11+41=233case、543+11+41=595次真实私有native entry，全文/完整header/容量/u64/异常协议/只读源/guard/canary及source-image before/after全部通过。实际A carrier entry=0、实际public admission entry=0；动态公开类型/字段上下文、group6/9仍OPEN。完整423,488B原log、三原group JSON和独立观察已入库。
- impact41原件reader job131116463745实际PASS_READ_ONLY：完整3,090成员/150,697,441B全bytes/modes检查。large-valid实际原生ELF运行90,058,572,023ns后-9，timed_out=false，stdout/stderr均0；整组CPU由4.889232增至94.892995。该事实确认原生阶段本身触及CPU界限，原FAIL不变。graph-long-report完整14,827,750B输出逐字等于原expected，实际0退出，candidate5,568,715B/receipt619B/impact9,258,352B均全字节相等。下一步需机械阶段计时定位，无预算放宽。
- namespace旧40/41 reader结果的compact43实际PASS_READBACK_ONLY：原114+119+93成员全核。旧reuse37前缀5,349records、2,411已返回VM；adopt38前缀5,435records、2,465已返回VM；两者native记录0。两gzip均没有footer，但完整前缀无JSON错误且末行完整；在途未flush命令保持UNKNOWN。
- 最新issuedFS42原件reader job131116463813实际PASS_READBACK_ONLY：原4,272成员/323,619,640B逐字/mode通过。38tests已有原ok，test39已开始。47个实际native carrier进程全部0退出、源码未变，累计CPU1.230664秒、wall3,428,566,254ns。46个完整replay中4,817 native=4,817 returned VM，六role计数1064/26/24/1126/679/1898。第39测试carrier完成3个请求并0退出，未完成的是随后的outer VM回放。其新gzip0B，不能把第一条未记录请求叫卡住调用。原900秒FAIL不变；具体VM构造/解释/全buffer校验/JSON-gzip成本仍待度量。完整558,298B原log、531,120B原console投影及原stderr已保全，原u64字节未改写。

### 本次新工作

- Worker44初始化program桥的13个依赖B3实际通过；新四核在第一个生成profile被原SSA<2048门拒绝（maxSSA2185，27fn/910blocks/3631ops/max156function-blocks/15params），新四核B3=0、语义=0，原FAIL保全。r3只按原顺序将pb_result_frame的success/failure分支提为HIA helpers；4组129case/27program ELF、23fresh B3及全部原门不变。r2完整active/dependency源已物化，旧r1源仍保存，active选择按实际新版本更新。
- P16严格诊断44实际7fresh B3、151ELF进程、38private entry，177case PASS、4公开全文case实际FAIL；100私有controls在进入native前因bytearray传ctypes失败。原10组完整日志/原JSON保全。新修仅在Buffer两处使用bytes(raw)，100case及oracle/native源完全不改；下一门只补100controls，先要求fresh7 source/image逐项与44实际指纹一致，不重复177成功用例、不继承计数、不将4公开FAIL抹掉。

- 新HIA unixOpen父层，以6个精确原C函数作独立reference，计划1次fresh B3、9批85语义case、42协议control、88次原C调用（含setup及2protocol语义）。18个effects此轮仍明确为foreign；不冒实际namespace或完整Store闭合。7个active Python作者/验证源进入预检查，7份旧草稿仅保存；原10/20/256MiB/1MiB、每进程90CPU/180wall/1GiB、aggregate900wall、4M VM steps/32MiB arena/64depth均保留。新件至提交前0AST/HIA/B3/VM/native。
- 全回归37原件reader43实际FAIL于文件定位：download-artifact把内容放入artifact-name/hia-full-custody目录，原reader错误假定root平铺。此时完整原archive未读、0target执行，原28阶段FULL_RETAINED_PASS不变。新reader只在下载树中要求唯一original-evidence.tar.xz，定位其父目录并继续原完整pin/member/mode/before-after校验；原reader/log/raw summary均保留。此次不重跑全量回归。

本次选四tag：unixOpen、全回归原件reader、Worker桥r3、P16仅100私有controls。44其它原结果继续按实际终态保全。workflow131jobs/131原Ubuntu24域检查，active源码642份严格码点有序。已发布组件证据不等于156旧production模块/API完成替换；原生安装、cold、公开CLI/Worker/Store/Emitter整链和各平台仍须闭合。

## FOLLOW44 最新状态（2026-11-12 10:14:56 UTC）

父状态FOLLOW43 `e2e4789b2dbaa1bf5f7fa7554cc58e2e8d0fef10` / tree `9d25ad9d1c02d39b3895cd970159d9ea0f6cab07` /6,125文件。整套OPEN，生产激活0，旧实现删除0。

FOLLOW43原源码预检查run43197963253/job131113678608真实FAIL，发生于 `paths == sorted(set(paths))`，实际Python AST文件0、HIA/B3/native0。根生成636项清单时使用JS localeCompare，导致同目录 `hia_program_composite.py` 排在 `hia_program.py` 前，与原Python字序不符。原21,046B日志和完整228,067B错误清单均保全；本次仅重排原636项，逐项path/bytes/GitSHA/SHA256/mode完全不变，原checker和全部组件源码不改。新增两份只读reader后共638项，显式验证所有路径ASCII且严格按码点排序。

- 重新选择因共同预检查而阻塞的5个组件tag：Emitter后9组、checked-plan、Worker初始化program桥、私有181诊断目录、P16严格公开诊断。43的两条无target只读任务继续，未重复启动。
- 新issuedFS42只读reader读取已完成run43192344684/artifact13932591885；完整4,272成员、原native trace、已有VM ledger和全缓冲/CAS全部验证。分开观察process是否退出与replay是否完成；未flush的调用保持UNKNOWN，不执行VM/native，不再运行原900秒目标。
- 新impact41只读reader读取run43189935529/artifact13930443158，完整3,090成员/150,697,441原bytes；保全所有文件及mode，解压large-valid/graph-long-report的原stdin/stdout/stderr及完整expected缓冲，确定实际退出和原比较前沿。不执行HIA/B3/VM/native，不把已失败large-valid改记成功。

workflow共130jobs、130原Ubuntu24/x86_64域检查；本次7tags。旧28阶段FULL_RETAINED_PASS、Worker42成功、impact41与issuedFS42失败全部保留。原预算/profile不变；本次源码交付仍不构成整套原生闭合。

## FOLLOW43 最新状态（2026-11-12 10:09:04 UTC）

本提交以 FOLLOW42 `115bf63f3a43959276286348232045598c861e2c`、树 `88ad6a560169409825d0c35515c5dcd44a911182` 的完整5,953文件为唯一父状态。整套 OPEN、生产激活0、删除0；本节更新后文历史状态，所有旧失败和未执行草稿仍保留。

### 已取得的实际结果

- 完整保留版回归 run43180758665/job131055860427 已实际 SUCCESS：28个阶段全部 returncode=0、没有超时、源码保全。原 full discovery runner `9bf24a8b81f26b86ee250c48066f0ce3232b9b35` 20,328B 未改；其通过条件仍要求 tests_loaded=tests_run>0，errors/failures/skips/expected failures/unexpected successes 全空。当前日志只给28阶段，精确测试数必须从已完成原包读取，不能填旧4,157或推算。原封包33,465成员、30,113文件、3,713,148,003原bytes，XZ1,195,190,880B，SHA256 52cb5aefa90e5f022905a2f29a38b1541a789444925b83f7e8c301bc6a866ebb。新增只读全包reader，0目标重执行。最初4,157/187errors/1failure/18skips的FAIL/HOLD仍原样保留。
- Worker42 P16/P17/P18 job131094562109 SUCCESS：6次原0e09 B3（含实际HIA packer）、5组113新case，83个实际ELF进程和38次私有entry。全payload比较和源码/镜像before-after完成。这只证明固定服务面板，不等于普通Worker、全部peer或初始化整链已通过。
- impact41 job131086386743 实际FAIL：13组中12组PASS，共328个完整case，329个实际ELF进程。graph-long-report现已通过，整组CPU80.319085秒；large-valid完整组CPU94.990324秒、0已完成case，仍超过原90秒。完整原log398,336B与13原JSON已保全；该case原process退出/流字节需读既有artifact，当前不猜。没有扩大预算或去掉oracle CPU。
- Emitter41 原11次fresh B3和两份既有source/image/invariant比较通过；late4、late5完成2case/731entry。late6原fixture名abort被精确Core以E_HIA_NAME提前拒绝，0该case原生entry，原FAIL保留。只把fixture改成必须先证明Core允许、wrapper禁止的_init，下一轮只跑后9组60case/50private controls。39/41两个完整原包先后读回，先前成功组不重跑、不混成单轮55组成功。
- issuedFS42 job131094562125实际FAIL：6次fresh role B3、1次HIA packer/33entry、84×旧VM/新VM/原生对照均通过；后续physical+完整trace replay在原900秒处被终止，900.009650691秒wall、897.888822秒CPU、-9、stdout/stderr均0、完整physical结果INCOMPLETE。具体最后case和等待命令UNKNOWN，必须读取已有4,272成员包；不重复900秒目标、不声称超时根因。
- diagnostic42原件reader实际SUCCESS/PASS_READ_ONLY：73份原件、70份与旧40原字节相同、3份新增真实program admission/publication/lower-stream作者；3包完整成员与before-after校验完成。只是读取，0HIA/B3/native。原reader40失败仍保留。

### 本提交新增且尚未执行的接入

- Worker初始化→实际program桥：23次fresh原0e09 B3，4组129新case/27个实际program ELF进程的计划；从Registry BORROW完整插入顺序GraphWire进入固定服务，再把真实receipt/Core/raw input导入为issued values。普通Worker的其它8个Store/effect peers仍未闭合。
- checked machine plan：5次fresh原35ee B3、55组679case/119private controls的计划；原1024函数、4096block、262144node、8MiB、64depth、各+1和原数字限制均保留。完整输入、输出、三operand逐entry前后缓冲和CAS纳入实际验证。15份active Python作者只是开发作者，不等于已原生通过。
- 私有固定诊断目录：181条原native-adapter enum全文，3组233case/595实际私有entry的计划；2次fresh B3包含一个只构建、不执行的A continuation。已确认适配器通用文本并不覆盖公开类型名/字段上下文；其PASS也不能证明公开错误全文等价。group6/9与A实际carrier接入仍OPEN。
- 实际P16诊断接入：7次fresh原0e09 B3、10组281case/151实际ELF进程的计划；真实child终止后调role51 R/W/W，只修该权限位并要求其它carrier字节反向恢复。4个已知公开context差异保持严格原oracle，实际不一致必须FAIL；62个候选固定文本也不能在host先断言而跳过native。各group独立继续，全部失败原件保全。
- namespace已完成reader压缩输出器只读取既有40/41 artifacts；完整原件仍保全，console控制在900,000B内，不再盲目拉取已触发Transport closed的巨型日志。不执行原target。

新源码到本次发布前均为0 AST/0 HIA generation/0 B3/0 native；实际状态由该提交CI产生。selected syntax共636份，workflow128 jobs/128个原Ubuntu24.04 x86_64域检查；本次选择7个明确tag。原B3 10CPU/20wall/256MiB、完整组90CPU/180wall/1GiB、physical900wall和全部profile未变；不存在128 ops/block新门槛。全量原生安装、冷启动、各平台/API、普通Store/SQL/unixOpen、完整公开CLI和真实Emitter整链仍须完成。下面保留历史审计与原始异常记录。

## FOLLOW42 最新状态（2026-11-12 09:30:41 UTC）

本提交以 FOLLOW41 `3eaba785ca9a9b31795b3c3ca39a546ec5c5ffea`、树 `1df2005cb5e91989931774249c554515820314e2` 的完整5,799文件为唯一父状态。整套 OPEN、生产激活0、删除0；下列最新状态更新后文历史提交的“待执行”描述，原失败原件不改写。

- FOLLOW41 源码语法 run43189935524 已 SUCCESS。该结果不等于原生语义通过。
- FOLLOW40 Worker P16/P17/P18 job131079272197 实际 FAIL，首错为 namespace package 的 `_NamespacePath` 没有 `insert`。尚未生成或编译新 HIA，实际0 B3、0 native案例。本提交仅将路径操作改为保留全部原路径的 list prepend，并同步精确index/CI摘要。完整338,668字节原日志与失败观察保留在worker-program-services-r2/observations。仍要求6次新B3、5组113案例、83实际ELF进程/38私有入口，全部原预算保持。
- FOLLOW41 issued-FS job131086387406 实际 FAIL：10项精确DMS9源控制已执行，6个角色全部真实B3完成；随后packer对执行器摘要的严格检查拒绝旧R6绑定，因此实际0 packer入口、0物理案例。新r4仅修正两份packer的FS8执行器精确摘要及传递依赖，并加入全字节反向恢复控制。仍要求42物理组、33packer控制、84组三方对照和6+1次新B3；原90/180/1GiB与900秒总墙钟不变。完整382,894字节原日志与6项原始/派生证据保留。不能将本轮计作42组已通过。
- FOLLOW41 Emitter job131086387011 实际 FAIL；正在保存完整原件并修正下一处参考夹具。完整新结果须以其精确交付读回为准；旧44组/670案例不改写成新整轮通过。
- FOLLOW41 ordinary-impact job131086386743、FS8原件reader131086386894、FOLLOW40 reuse/adopt原件reader131079272150尚无已读取终态。完整保留回归43180758665/job131055860427仍未取得最终报告；原4,157项FAIL/HOLD不变。

### 已恢复的完整影响分析原件与公共诊断源

FOLLOW40 impact/diagnostic reader131079272223取到了70份完整原件（46份UTF8、24份二进制），随后因最后要求了不存在的`generate_hia_program_driver.py`而FAIL。实际原始诊断驱动明确引用`generate_hia_program_admission_driver.py`。本提交保存606,247字节完整原日志、原样发出的summary及全部70原件，逐件完整验证GitSHA、SHA256、字节；24份二进制通过不可变暂存提交`70f1fdafdfb4fe17d73b453c3b2e4d08cbe1916d`实际GET读回。原始JSON不经JS解析再编码。旧reader在最终输入after-check前触发错误，不能声称其before/after完整通过；新reader改正真实文件名，并将全部输入after-check放入finally，仍0目标执行。

完整原件证实：六个正常返回的影响分析案例中，candidate及receipt原字节均等于原oracle，impact完整对象相等但字段序列不同。原合同要求canonical，FOLLOW41仅修正测试的错误序列化；旧结果仍FAIL。另两项large-valid和graph-long-report的native子进程确实返回-9，分别经过90,023,926,570及90,017,284,820纳秒，stdout/stderr均为空；它们实际碰到90秒CPU门，不只是外围计时。FOLLOW41 SHA32字访问优化是否足够仍须该真实运行的终态。

公共A入口原生root已确认对部分group1..6/9只保留编号而拒绝完整文本输出。已完整取得与role40源码摘要一致的原lower-main作者，以及原Core诊断驱动、消息表与text作者；正在将实际错误路由与原完整文本接入HIA生成器/返回链。该工作没有被当成公共诊断或安装闭合。

FOLLOW37恢复点为e3ea7f33f1d7bf3350e4b54a9a8d3522746223c7，树f13b040a6f98ee39bef6f4db81f60d33a0dbd098、5,249文件。FOLLOW38已发布为86c3e60966085f9aefde1170fbbb737c20a52422，树fc5737b2d001163aba37d57f2e1244668feeddd8、5,366文件；FOLLOW39已发布为f3d17aac2caabd1a077fee0848707f3a50ac3b46，树e01d092ffe2dbba5aba01f62a7be77ab0f0fb0a2、5,546文件；FOLLOW40已发布为3a230c96c7ab0c0c12ed8caa552691ab226bcd05，树00331bbcfa30977f1d7ecd6578be0cdc51662e9e、5,680文件；此前FOLLOW41以FOLLOW40为唯一父提交。独立完整基线始终固定为 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5，树 6ef9e1713065436a3b1886fe9edcf0a4a1120773，共2,798文件。FOLLOW37完整新增/恢复文件身份见 ci-followup-r37/publication-manifest.json；FOLLOW38、FOLLOW39及本轮新增/替换源码分别见对应ci-followup目录中的publication-manifest.json。

本地计算环境在本轮工作中容量耗尽，随后正式 unavailable。失联前未取得终态的任务保持 UNKNOWN，不重放或推断成功。已落入 Git 的源码/证据继续用于独立 CI；尚未完成封包的本地记录不被描述为完整可恢复证据。

## 全量盘点与恢复出的真实缺口

对FOLLOW36完整父树的只读审计实际读了5,025文件、558,946,765字节：1,917个Python文件中1,914个可解析，153个生产Python模块均可解析；另有60个.hiaasm和12个.hia。全部原始Git blob、模式、SHA256在读取前后相等。3个历史语法错误被逐项报告并保留，不通过删除历史失败来获得通过。

完整9,445,685字节本地静态清单的SHA256为 e0df484a5318eec4aaf73bfc082aca13dc352a9ad7bafb06df4dc7c252b2926d；该大清单尚未取得持久化回读点时环境离线，不能据此声称文件目前可恢复。该清单的离线缺口随后由FOLLOW37实际CI重新生成的完整清单及全部生产模块投影补足；新清单原件身份与工件见下文。静态解析不等于逐函数语义审计或完整HIA替代。

随后对照完整基线，发现非review-evidence树有48个缺失文件和51个被修改文件。本提交精确恢复48个缺失文件和50个被修改文件，保留恢复分支已有的进程dumpability修复。恢复内容包括：

- Worker请求、Agent日志、composite outer三个已经存在的原生适配模块，以及相应HIA源、构建器、安装资源和测试。
- 动态链接ELF观测器、调用图固定点提前收敛优化。
- JSON前置诊断、构造/外层生命周期和完整原始测试工作流。

恢复后生产包为156个Python模块。这是恢复覆盖范围，不是减少原生工作量或宣称完成比例。未归因于任何具体删除者。

47项原始源生成器在独立副本执行完成；生成合同检查通过，另13项所选恢复源控制通过。这些是本地观察。保留的allocator child文件SHA256为 c40e809af7d213daacb2bf066b5177784aa09c9b5c1b528ee76353b1e5c4fb9e；再生合同Git为 e6da630f6244f3c227ba2541f8a5e8e68b1c239d，129,034字节，SHA256为 d684f22bcfe86be1d359aef9c30307d316fd1136a14d2795d0f203070682b139。环境离线后从基线合同精确重建，身份与先前实际再生文件相等。

pyproject.toml仍使用setuptools、Python >=3.11，hia入口仍为hepta.cli:hia_main。当前交付不能被称为全量HIA原生整套。

## 原始4,157项完整回归仍为 FAIL/HOLD

原始结果是 **4,157项、187 errors、1 failure、18 skips**。原始压缩包Git为 2aae1a9fc536d476cf02f32d40b7c3a34335cf34，666,816字节，SHA256为 5595532d3fc1d8e8b5021236b30217b85ec53a1452d4b23a98b378996e67cee5。124个原始归档成员已完整回读。

| 原始异常分组 | 数量 |
| --- | ---: |
| 旧调试桥绝对路径不存在 | 1 error |
| 有界普通文件读取失败 | 19 errors |
| 无法以no-follow打开原生工件 | 2 errors |
| raw-model release/hia-ndu-bridge不存在 | 155 errors |
| raw-model target不存在 | 10 errors |
| 预期native evaluator failed，实际文件读取失败 | 1 failure |
| 缺实际native NDU bridge路径 | 14 skips |
| 缺实际Z3与固定native NDU build | 4 skips |

全部187个错误与1个失败的原始异常链包含ENOENT。造成依赖消失的行为主体仍为UNKNOWN。原结果不因新组件或读回器通过而改变。

原完整执行器是20,328字节、28步骤的版本，Git为9bf24a8b81f26b86ee250c48066f0ce3232b9b35。本提交将其原字节复制到ci-full-retained-r1/run_original_retained.py，并保留原相邻workflow_process.py。完整discover仍要求加载数等于执行数，errors/failures/skips/expected failures/unexpected successes全部为零。完整回归5400秒和冷启动180秒内部门均未修改。

新增独立CI重新构建六组NDU桥，保留固定源码、原Cargo锁与真实原生身份；配置Rust 1.90.0/1.95.0、固定Lean/QEMU、Clang20、Boost1.83及原Python包版本。原prepare观察器必须实际READY才能启动原完整执行器。构建前后完整源码不变、实际工具/二进制hash与全部stdout/stderr均保留。新准备/流式封包脚本是在环境离线后从已审草稿重建的明确新版本，必须接受新的AST和实际CI，不能继承旧草稿的运行结果。

即使该完整保留回归通过，也只是完整功能基线通过；全HIA入口及旧实现不可调用时的完整验收仍是另一项必需条件。

## 已确认的真实执行结果及范围

| 范围 | 实际结果 | 仍开放的边界 |
| --- | --- | --- |
| Function35完整降级组合 | 原39组、718例、129私有控制、43,156次native入口；580条成功Code链与4条预期Code错误 | 完整Emitter、公共入口和安装不能继承此结果 |
| 普通patch固定ELF协调器 | FOLLOW36 job131016969400 SUCCESS；原9组293例，293实际native进程，5次新B3和1次原生packer | Python对象输入API、公开CLI、整套patch激活仍未验收 |
| scalar/borrowed wrapper | 原FOLLOW36首组因trap fixture缺code失败，0语义入口；最小fixture修复后本地26组502例/79私有控制/55,083入口通过 | 本地复用原4个B3镜像；新CI须4次重编；182,656原件的本地封包未完成，完整新raw不冒称已持久化 |
| URI/创建模式 | FOLLOW36正式222语义、389协议、8直接边界；1,255 VM =1,255 native，37个C策略调用，2次B3+1次C编译 | 受控provider，实际OS策略syscall为0；不是完整unixOpen或Store |
| 六角色物理链r6修复 | 本地新6角色+1packer B3、33packer、84组三方对照通过；原test10+test12的322次VM/native全缓冲区相等 | 原18项物理门仍待新CI；本地SQLite3.53.1与原CI3.45.1分别记录 |
| Store35 | 原9次B3；5组269例、10,268入口完成；两个90CPU大值组失败 | 失败发生时storevalues/scan/emit没有实际入口，不能将pending文件解释为卡住native |
| initializer/Store组合36 | 原11次B3；effects/catalog/growth共16案、14,298入口完成；semantic前5案完成，第6案未终态 | 原90CPU FAIL保留；新缓存尝试的8案exit0伴随95.352369 CPU秒，预算未解，不能计90CPU PASS |
| 可复用DB描述符 | 新精确C与HIA语料、原32个方法体和8个新组已提交 | 本地40组VM部分运行后环境离线，终态UNKNOWN；新CI须原40+40、900秒聚合门 |

Function独立读回校验了完整ZIP、144,598内层成员、所有39个入口账本、CAS页和计数；没有把逐页核验夸大为再次重建每一个逻辑完整工作区。完整原始日志/摘要及作用域分别保存。

普通patch的失败原因已由新九组实际重跑闭合：收据完成结果在64..95字节写元数据，旧协调器错误要求该区域全部为零。修复严格绑定实际prepare版本/策略/编辑数，约束变化数≤2048；NEED路径仍校零。未改收据内核、执行器、原oracle、原用例或限制。九组数量分别为semantic113、errors58、interfaces48、input67、identity3以及四个各1例的大边界组。完整原工件2,608成员、143,620,345字节已在离线前逐成员核验。

物理r5原FAIL已完整读回：10项完成PASS，test10 error，test12在SQLite WAL链上未完成并出现SIGBUS。第一个确定缺陷是机械载体错误把action按跨call递增比较；HIA会在新call重置action。新载体绑定(call,action)，保留重放门。第二个是测试父进程用Path.read_bytes打开并关闭相同inode，释放其POSIX锁；改为新的只读子进程观察。独立锁witness和真实test12证明父DMS锁保持，前后32,768字节相等；没有修改六角色HIA策略以绕过旧失败。该修复完整本地644文件、174,132,446原字节已封入3,199,908字节Git归档。

Store35两个大值原组完成前沿分别为293/294次入口，属于sequence、registry和merge；两个pending均是最后已完成调用。原fixture把约8MiB字符串复用于7个profile，形成约58.7MB图；原实际profile为字典。后续须分别保留原对抗案例和验证真实profile数据，不能用新正常案例覆盖原FAIL。

robust_open原90CPU失败保留：完整前沿为117个语义例、2,139对VM/native相等；后续协议控制未完成，不能宣称完整gzip或整个域通过。

源码复核已纠正全局 inode/FSTAT 的范围判断：现有六角色 outer 已有全局 dev/ino 索引，j_pre_stat 保存真实 FSTAT 的 request/result，再在注册阶段回送同一结果；注册链没有重复发出该 FSTAT。新增 completed-receipt adoption 是待验证的接口方案，不是已确认双调用缺陷的修复。完整 unixOpen 的描述符复用、创建/只读回退与真实 FS7 仍需接入；verifyDbFile 的后续独立 stat 不在上述单次注册 FSTAT 声明内。精确源码绑定与撤回记录见 namespace-ci/db-global-reuse-r1/single-fstat-scope-correction.json。

## 冷启动与只读审计

FOLLOW34原冷启动完整读回为11/11、38/38阶段，164.068272474秒；FOLLOW35为6/11、34/38阶段，180.164994456秒超时。FOLLOW36 Core source成功、native失败。所有原始成功和失败分别保存。

恢复源码后的新本地冷启动仍失败：6/11、26/38完成，180.414209434秒，返回-9。本地生成的B3镜像为669,556字节，原始镜像、请求和收据均包含在归档中；这不代替整次冷启动通过。完整本地冷启动及13项源控制原件已逐字节封存：2,689归档成员、2,612普通文件、266,536,395原字节；归档22,409,344字节、SHA256为19c0f613dd43da62d1918a5e3cb7d46fe88c5e8b9e8130f8b488e3a6e0f63d6e，以43个有序Git片段保存。归档内容与观测到的失败保持原样。

独立字节校验分支的原 Core 工作流也运行了相同恢复源码：提交 0d6ca7d450128032c7e7dc67a14b370647c47e41、run43178823310 的 source job131049505021 正式SUCCESS，47项再生成、合同检查、git diff均通过，331项源控制在489.709秒完成。native job131049504192 的冷启动步骤已返回success，完整native job随后正式SUCCESS；完整原始job日志已保存，冷启动终端原样记录为11/11。完整冷启动JSON及内含阶段仍由严格只读工件读回器核验，不从步骤状态猜测耗时。原本地冷启动FAIL保持不变。这是校验分支的实际结果，后续主恢复提交仍接受自己的精确CI。

FOLLOW36全树审计读回器在读取Git pack时受原1GiB地址空间限制而失败，未进入AST扫描。新修复只为各Git命令设置16MiB映射窗口和64MiB映射总量，不改资源门、不修改全局Git配置。此前本地含相同修复的版本完成静态与原始失败档案读回；该精确CI版已在FOLLOW37 job131055866771实际完成，下文记录其完整边界。

## FOLLOW38提交时：新增组合源码与精确验收入口

本轮新增组合均为**源码已完整Git回读、0次新AST/生成/B3/native执行**。完整Emitter的早期单案本地观察、原八案initializer的超预算exit0和其它旧组件结果均不继承到新组合。391项活动Python源将在新提交上独立解析；112个恢复工作流job保留同一Ubuntu24.04/x86_64强制域门，本次只选择五个新组合job。

| 新组合 | 必须实际执行的门 | 当前未闭合范围 |
| --- | --- | --- |
| initializer完整剩余八案 | 11次fresh B3、原八案逐案完整比较、实测父子聚合CPU严格<90秒 | 原95.352369 CPU秒观察不改成PASS；普通Worker/Store未闭合 |
| P12资源初始化 | 13次fresh B3；2 semantic、1 capacity、52 protocol；实际HIA metadata op3与registry reserve/merge | 其余11种initializer peer及实际put/SQL结果仍foreign |
| completed-FSTAT adoption | 原40组加20组，60 VM与60 paired；1 B3、1原C参考 | 私有接口方案，真实OS syscall为0；不是既有双FSTAT缺陷修复 |
| 全局描述符复用物理链 | 6角色+1packer B3，33packer与84组三方；原18 physical加10新组 | 实际TAKE_UNUSED/复用绑定，空C字符串stat、完整unixOpen回退仍OPEN |
| 完整Emitter十一核 | 11 fresh B3、55组732案、50私有控制、2个全缓冲区双载体交叉 | 外层原输入再验、checked machine plan、独立对象检查与public build发布仍OPEN |

Emitter的大边界载体保存完整命令/ACK与最终全部slots；该覆盖不被描述为每次入口全部工作区快照。原Function39组与wrapper26组的完整旧证据门仍保留。新增重复临时证据只有在无损编码后完整解压逐字节核验通过才回收原临时副本，原raw身份及编码件目录保留；不删除旧回归证据。

最新源码复核还确认了公共错误路径缺口：当前private program terminal的composite groups1..6/9只传数值拒绝，缺少原上下文的完整诊断文本。正向程序链通过不能覆盖这部分公共行为。后续Worker P16/P17/P18、public CLI B/C/D与原生对象检查继续独立推进，不以宿主猜测诊断来填补。

FOLLOW37的49个二进制文件已在只读CI43180354999/job131054530017全部回读，32,054,646字节的大小、Git SHA、SHA256和模式一致。完整保留回归已由FOLLOW37 run43180758665启动；在其终态及完整原件未读取前，原4,157项结果仍为FAIL/HOLD。

## FOLLOW39：精确实际结果、修复与下一组组合

以下为08:37 UTC前已从精确run/job读取的结果；新源码不是已执行结果。

| 精确执行 | 实际结果 | 限定 |
| --- | --- | --- |
| FOLLOW37全源码审计，job131055866771 | 5,249文件、601,276,293字节，1,985 Python中1,982可解析，156生产模块全可解析；前后全部Git字节/模式相等 | 3份历史无效草稿保留；这不是逐函数语义审计 |
| FOLLOW37 Core，run43180758678 | source/native均SUCCESS；source331测试，351.929秒；原冷启动11/11，实际B3连续三代35ee92b7… | Core子集工作流通过，不是全量HIA安装验收；旧本地冷启动FAIL不变 |
| FOLLOW37 wrapper，job131055867030 | fresh原四核；26组502例、79私有控制、55,083实际native入口全部PASS | 完整5,510,971字节job日志已按顺序无损分片入Git；原本地seal失败不改 |
| FOLLOW37 physical r6，job131055866693 | 18组全PASS；22固定进程；2,562 native=完整VM轨迹，266实际primitive ACK；6+1 B3、33packer、84×三方全通过 | 315.322761 CPU秒是跨进程聚合，逐进程90CPU/180wall门不变；全原JSON另由只读reader完整读回 |
| FOLLOW38全局复用，job131058484920 | 28组=原18+新10全PASS；35固定进程；4,461 native=VM、454 primitive ACK；6+1 B3、33、84×三方通过 | 跨进程619.422734 CPU秒不冒称单一90秒组；完整unixOpen仍未闭合 |
| FOLLOW38剩余initializer八案，job131058485019 | 8案、10,592实际入口PASS；完整组实测CPU47.039588秒、wall52.607秒 | 旧95.352369秒原观察不变；不证明整个Worker/Store |
| FOLLOW38 P12资源，job131058484994 | 13fresh B3通过；三组均在resource-begin-1以717失败，0完成案，实际入口647/747/647 | 新r3仅明确接纳合法完整HIAWPE01/action4返回，不缓存旧registry事件、不伪造头 |
| FOLLOW38完整Emitter，job131058485079 | 11B3通过；39完整组630案PASS；manifest组前6案通过、第7案失败，总969,488实际入口含失败调用 | InheritedStr空值capture tag11被prepare私有node门提前拒绝；整体FAIL，后续新r2全部55组重新执行 |

完整静态清单为9,847,160字节，Git身份9d8a36fcd6627abcdb02bc802f1507941da89f75，SHA256 a08a7f1f3d5c9a35b7bef58987597b80e1f592b27b920c640fe4c054addaf7e9，实际工件13926322477。全部生产模块投影179,152字节已从分片逐字节恢复并Git保存。156个模块共1,957个定义条目（含类/函数/方法），1,007个public命名条目；该计数不等于公共API承诺。新增production-installed-replacement-register.json逐模块绑定当前/基线Git、静态调用者、公开命名和原生selector。156个生产模块均仍保留，已验收安装替换数为0；独立组件进展与安装替换状态分别记录。

本轮新增或修复：

- FS8固定网关复用已经实际编译过的精确源5c64683d…，新组合仍要求6+1fresh B3、33packer、84×三方，以及原28物理组加6实际内核原语组。先前等价手写草稿原样保留，不继承其执行结果。
- ordinary impact新固定ELF接实际第三次Core admission，再对candidate作完整256字节分块比较，之后调用实际role60影响分析。三输出为复验candidate、实际patch receipt、完整impact。6fresh B3、13组329案必须在原限额下独立通过；包含1024函数、4096边和大于8MiB完整报告。原293 patch案例在新组合重跑，不借单独leaf结果。
- ELF64对象检查新HIA owner接原结构/符号/闭合导入导出语义，2fresh B3、20组579案、27私有控制与8条实际ELF writer→inspector。COFF/MachO/shared和完整public build不在此结果内。
- P12 r3保留原registry分支与原51协议故障，新增真实registry正控和35个错误pure返回控制，协议组共88例；其余原2 semantic/1 capacity不减，13fresh B3及90/180/1GiB不变。
- Emitter r2仅在prepare的原node校验接纳已定义tag10/11并对tag10要求zero aux，未修改原ELF owner、原normalize oracle或原55组732案50私有控制；新目录与证据scope单独标识。
- 两个独立只读工作流分别取完整静态清单和成功Core原报告，以及physical37完整原件。它们不执行被读HIA/VM/native，不会把原失败变成成功。

475项活动Python源将对本轮提交重新作语法检查；117个恢复job保留同一Ubuntu24.04/x86_64硬门，本轮仅显式选择所需新门。以上新源码在提交前为0新AST、0生成、0B3和0native。P16/P17/P18、真实unixOpen后续发行FS请求续接、完整checked-plan/公开编译链继续开发，尚未纳入本轮新PASS。

参考实际工作流：[全量原保留回归](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43180758665)、[Core37](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43180758678)、[恢复37](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43180758618)、[恢复38](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43181547044)。全量原保留回归已完成fresh依赖/六桥和READY，仍在原完整runner内执行；没有原全量终态时不得宣布4,157项PASS。

## FOLLOW40：实际P12与对象检查通过，失败保持可追溯

FOLLOW39在精确提交f3d17aac2caabd1a077fee0848707f3a50ac3b46上的恢复run43184755381已结束。以下结果分别来自实际job，不能合并成全量安装通过。

| 组件与精确job | 实际结果 | 作用域 |
| --- | --- | --- |
| P12资源初始化，131069068422 | 13次fresh B3；2 semantic、1 capacity、88 protocol，共91案、7,637实际native入口全部PASS | 三组CPU分别23.749902、13.483815、12.726759秒；P12 owner283、metadata8，其余11类initializer peer仍foreign |
| ELF64对象检查，131069068695 | 2次fresh B3；20组579案、1,097实际入口全部PASS，其中inventory1,073与producer24 | 27个私有控制、8条实际HIA writer→inspector；COFF/MachO/shared、完整public build及安装仍OPEN |
| FS8固定物理组合，131069068418 | FAIL；生成role4时旧fixed-header helper要求旧完整源码摘要，0 fresh B3、0 packer、0 physical案例 | 原roles1..3 document/profile已生成；不会把前置失败描述为运行时原语失败 |
| ordinary impact，131069068426 | 6次fresh B3和1次packer通过；13组中5组全部PASS、8组FAIL | errors58、input67和三个各1案边界通过；interfaces前2案通过后第3案失败，其余差异与预算原件全部保留 |
| 完整Emitter，131069068249 | GitHub终态FAIL | 尚待完整后段失败原件审阅；不能将前序组通过写成整套Emitter通过 |
| 完整inventory/Core原件reader，131069068481 | PASS_READ_ONLY | 全ZIP/member字节校验；0被读目标执行 |
| physical37全原件reader，131069068584 | PASS_READ_ONLY | 原2,280个成员、259,051,592字节完整校验；0新B3/VM/native |

ordinary impact的5个完整PASS组共128案，另interfaces有2个完成案；其余组的已调用进程不能计为成功案例。成功返回的完整字节不等问题正在读取实际stdout与原期望CAS定位。large-valid与graph-long-report两组实测父子CPU分别96.399365和95.195808秒，均超原90秒门。旧FAIL保留，不能靠增加限额或排除原始参考执行时间取得通过。该CI从原root overlay搜到的诊断作者为0，只表示该选择范围未包含文件；完整诊断作者另从精确原归档读取。

本提交完整保存P12、对象检查及FS8/impact的原日志。原始JSON文本和u64数字保持原字节，不经JavaScript浮点解析重写；派生的小计数观察单独标为derived。FS8原完整23,429字节build报告仍在精确工件13928371900；14122字节console字段明确不是完整报告。对象检查原CI已流式逐成员校验，当前Git交付不冒称另行下载ZIP完成复验。

### 完整审计清单与Core原件已取得Git二进制回读点

只读reader把完整9,847,160字节静态清单、179,152字节生产投影、原审计摘要与完整ZIP成员索引，以及成功Core的cold/language/callers三个原报告封为一个7成员tar.xz。该归档1,006,864字节，Git为3b2ebf37e4f3f54b15d57fc0ca17b675def6517b，SHA256为abfcceeb168157fbc0bcc4ac6eef42fbe3c0ec514a32d6ba10b987b1ea9ee793。根已从完整base64分片重建并核三项身份，再在不可变暂存提交d18e564729acfa7f7c033e0b1ba05053e533771d通过认证文件读取取回全部二进制，三项相等。此操作未移动分支。

physical37 reader的完整原日志2,886,486字节、原summary23,914字节及56份原JSON/日志2,040,950字节均完整Git回读。最大原物理报告678,746字节，Git e891a280ea6c064d7d5ec28e0a307a2e7a975974，SHA256 00afd2787cdee947fcce02130d7e26b197fbf5df3a959fbfee0a97f18de482aa。reader读取的是download-artifact解包后的原工件，不声称验证该外层ZIP字节/CRC。源、镜像及receipt的977,372字节规范子归档仍仅在CI工件中，不冒称已保存为Git二进制。

### 本轮新执行入口

P16/P17/P18新固定服务组合有25项源/依赖文件，加完整交付manifest。原63槽位中41为live，原36个peer均绑定完整源和像，其余22槽为空且不可调用。新6次B3须使用原0e09ccca…668,608字节编译器；服务必须完成原输入验证→完整render→assemble→新Core admission→完整canonical字节比较。五组113案包括45 semantic、22 assembly boundary、8 object boundary、35 private protocol、3 example chain；预期83个实际ELF进程和38次直接私有入口分别计数。全部逐组原90CPU/180wall/1GiB、B3原10/20/256MiB及容量门不变。没有预借P12或早期program子组件的PASS。

另外两个新入口只读原件：一项读取reuse37/adoption38原900秒超时账本前沿；一项读取impact39原失败CAS和r3/r10/r12精确原诊断作者。它们不启动被读目标、不补写成功案例，也不将原超时的已完成数量猜成零或任意前缀。实际只读代码也要在本轮CI中执行后才能记PASS。

当前493项活动Python源将重新检查语法；120个恢复job均保留Ubuntu24.04/x86_64硬门，本轮只选择worker-program-services、namespace-reuse-adopt-timeout-readback、impact-and-diagnostic-originals三项。所有新源在提交前仍是0新AST、0生成、0B3和0native。

截至本轮提交前，[完整原保留回归](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43180758665)仍在原runner步骤中；原4157项FAIL/HOLD不变。[FOLLOW39恢复CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43184755381)的实际PASS/FAIL边界如上。公共composite完整诊断、Worker完整初始化服务桥、unixOpen及Store、checked-plan与完整公开编译/安装仍分别推进。

## FOLLOW41：精确失败修复与尚未完成的组合门

FOLLOW40的程序服务和两个只读任务仍排队，未产生新目标执行结论。此处只报告已取得原始日志的FOLLOW39实际观察，以及本轮新源码需要接受的门。

完整Emitter原日志591,319字节（Git 1e984ce18eadce6bee730078e011d9dba8cd6511）及45份实际组摘要106,026字节（Git 238cd0299b2663a0793f0b2359ae19902ce77daf）已全文Git回读。原11次B3后，前44组670例、1,549,752次native入口全部PASS。第45组late4尚未创建Emitter、0 native入口，原fixture的资源参数显式exports先被Core以“E_HIA_TYPE: public exports cannot carry resource descriptors”拒绝。新fixture仅改为Core可接受的scalar参数加双scalar返回，仍要求原Emitter的完整错误“E_HIA_PROGRAM_ABI: explicit exports have signatures outside the native C ABI: aa, zz”。全部其它测试和11个生产作者不变。

本轮Emitter先读取原43,774个成员、1,012,497,507原字节，保存完整归档和账本，再验证原44组实际明细。原包在解析与语义断言前即复制保全；任何读回失败都保留原错误和partial状态。随后11个新B3源、像、profile、稳定编译字段及全部原源码快照必须与原件逐字节相等，才执行剩余11组62例/50私有控制。原55组调度表完整保留，用精确组名验证两轮覆盖集合。原run仍FAIL，两个run的覆盖并集不能描述为一次55组PASS；完整public backend、外层入参及安装仍OPEN。

FS8 r3只修正已经触发的DMS9精确源证明：新DSL70,707字节，SHA256 95e13ccf13d9780c06e089773133479a44fd83e6d9fc9fe5f0a40820c7946e3e；唯一op上限29→24逆转后必须严格等于旧SHA256 7fe09da5b8d59c14d1b5cd6fbc65b4c937677e410356d843a74affc62770d310。原4,046字节origin/Builder尾部完全不变。独立10个纯源码控制先于B3，两个接受与八个拒绝都要实际执行。不会放开任意新源或删掉旧fixed-header证明门。

新的issued-FS r3固定组合在唯一DMS/FS上下文中承接完整caller/action/sequence与256字节已发行FS请求，逐项绑定实际结果。原18物理组、10全局复用组、6 FS8原语组的方法体均完整保留，再加8个续接组，共42组。本轮只选择这个42组组合，不重复运行独立34组变体；后者精确修正源和CI仍可审阅。两个变体均保留6角色+1packer fresh B3、33packer控制、84×旧VM/新VM/native和所有原预算。该门仍是private发行请求fixture，完整unixOpen、临时名/随机与普通Store/SQL不能继承其结果。

ordinary impact r2保留原协议的canonical impact view。原r1协议和原static-impact对照使用规范JSON，整链测试却对report用了插入顺序编码；新测试只把该report视图改用原canonical helper，receipt仍保留原序列。原analyze_patch_impact完整语义oracle、所有输入、13组329例、错误顺序均不改。根还在独立读取r1实际CAS，未在未读全字节前将原差异归因为“仅顺序”或重标旧PASS。

r2原生性能修订只涉及SHA私有字宽。原SHA所有64个常数、8个状态字、输入四字节词和每个扩展/压缩更新均为32位；新hash_get读取每个原八字节槽的低四字节，hash_put保持低四字节和四个zero高字节。其它64位元数据、完整哈希、三次实际Core admission、逐字节候选比较、receipt/graph/report行为和缓冲区范围不变。原95/96秒预算失败保留，修订尚无实际性能测量；新6次B3和全部13组必须接受原90CPU/180wall门。

本轮活动语法清单为531项。被新r3/r2替代的44项旧活动路径只从当前选择中移出，旧源码和原失败均留在Git。122个恢复job全部保留Ubuntu24.04/x86_64域门，显式选择issued-FS42、FS8原93member只读、Emitter剩余11组、impact r2四项。提交前新源码仍为0 AST/生成/B3/VM/native。当前156个生产模块保持完整，安装替换数仍为0。

## 最终闭合和清理门

B3保持10CPU秒/20wall秒/256MiB，源/输出/工作区各1MiB。Bootstrap保持128functions、1536blocks、8192operations、每函数256blocks、每block16参数、SSA<2048；不存在额外128operations/block门。公共1024函数与Bootstrap容量分别验收。普通配对原90CPU/180wall/1GiB、物理原900秒聚合门不变。

完整公开入口、编译/执行/存储/Worker、工具链、安装、更新与恢复都必须有实际HIA承接。随后需要在旧业务实现不可调用的环境中执行完整功能、冷启动、故障、平台和安装验收，并绑定可重建的HIA源、镜像、安装包与精确提交。Python作者、现有安装器、机械汇编和当前产品入口仍是待替换依赖。

**FOLLOW41保留所有旧失败和旧实现，继续提交实际HIA组合、精确修复和完整原件。整套仍OPEN，激活0个新生产入口，删除0个仓库文件。**
