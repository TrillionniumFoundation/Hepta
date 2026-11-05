# OpenVPN 2.7.8 / HIA：目标机真实 TUN 与 DCO 验收

## 状态和适用范围

**本文件是目标机操作规程，下面的 namespace、TUN、DCO 和流量命令尚未在本轮执行环境运行。它不构成已通过的隧道或性能证据。**

本轮执行环境的 `/dev/net/tun` 不存在，effective/bounding capabilities 均为零；实际读取的内核配置为 `# CONFIG_OVPN is not set`。内核版本号或 OpenVPN 编译出的 `[DCO]` 标识不能覆盖这个事实。原始配置与测量范围保存在 [review/kernel-config.txt](review/kernel-config.txt) 和 [review/host-scope.json](review/host-scope.json)。

本规程固定官方 OpenVPN **v2.7.8**，源码 commit
`dc1f569087135894ac2703aeabd7a960ee9452d4`，官方 archive SHA-256
`c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36`。
HIA 对象、adapter、最终两个应用二进制、Clang/OpenSSL 及实际目标机配置必须另存精确 SHA/版本；不能把本机对象测试的通过结论直接转移给另一套构建。

目标机应已具备可用 `/dev/net/tun`、创建与操作隔离 network namespace 所需权限，以及已准备好的 Linux `ovpn` DCO 实现。`CAP_NET_ADMIN` 用于设备/路由操作；创建命名 namespace 还需要相应的 namespace/mount 管理权限。这里不提供加载模块、修改宿主默认路由、NAT 或防火墙的自动脚本。以下命令由具备这些权限的目标机操作者逐段审查、手动执行；所有接口、地址、流量和 qdisc 操作均指定本次独占 namespace。

OpenVPN 2.7 在 Linux 上使用的新模块名称/接口类型是 `ovpn`。仅有旧 `ovpn-dco` 模块不满足这套冻结组合。依据：[官方 README.dco.md](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/README.dco.md)、[2.7.8 disable-dco 选项](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/doc/man-sections/advanced-options.rst)。

## 一、三个层次和实际协议差异

| 层次 | 对照 | 能回答的问题 |
| --- | --- | --- |
| 原生 codec | 官方 C、HIA 原始 byte ABI、HIA application adapter，以及显式 C byte-ABI control | 小内核及 marshalling 成本；继续使用本目录的 differential/benchmark，保留所有退化 |
| 实际用户态端点 | 同一固定 peer 下，官方 C `--disable-dco` 与 HIA `--disable-dco` | 改动端点的真实隧道互操作、CPU/内存、吞吐和延迟 |
| 官方 DCO 端点 | 同一固定 peer 下，未修改官方 C，省略 `--disable-dco`，并实证 DCO 激活 | 官方内核路径相对用户态路径的部署价值 |

**同一文本配置不保证三个路径协商出相同 packet-ID 格式。** 2.7.8 的
`dco_linux.c:dco_supports_epoch_data()` 返回 `false`，而 `init.c` 为 DCO-off 设置
`data_epoch_supported=true`。两个 DCO-off 2.7.8 peer 可以协商 epoch 数据格式，Linux DCO 则不会。依据：[dco_linux.c](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/dco_linux.c)、[init.c](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/init.c)、[ssl_ncp.c](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/ssl_ncp.c)。

主三组实验因此固定 **server 为未修改官方 C、DCO 实际启用**，只改变 client：

- A：官方 C client，DCO off。
- B：HIA client，DCO off。
- C：官方 C client，DCO on。

固定 DCO peer 不支持 epoch，可使三组协商共同的非 epoch profile；每次仍须保存实际 cipher、peer/protocol flags 证明。之后交换测试角色，以固定官方 DCO client 测试三个 server 路径。另做 C/C、C/HIA、HIA/C、HIA/HIA **两端 DCO off** 的普通 2.7.8 epoch 互操作组。后者与两端 DCO 的部署比较必须披露真实协商差异。

不要添加臆造的 `no-epoch` 选项。源码中的 `protocol-flags aead-epoch` 是 NCP-only 推送内容，不是给普通配置文件使用的开关。

## 二、冻结目标机和检查官方测试的真实范围

将以下变量改为实际绝对路径。两个应用必须为同一源码/依赖/编译选项组合；HIA 应用只额外链接本轮最终对象和 adapter，**性能二进制不能链接计数/trace wrapper**。

```bash
ovpn_src=/absolute/path/openvpn-2.7.8
ovpn_build=/absolute/path/openvpn-build
ovpn_c=/absolute/path/openvpn-official
ovpn_hia=/absolute/path/openvpn-hia
case_root=$(mktemp -d /tmp/openvpn-hia-accept-20261105-XXXXXX)
umask 077
mkdir "$case_root/freeze"
uname -a > "$case_root/freeze/uname.txt"
cat /proc/self/status > "$case_root/freeze/process-status.txt"
ls -l /dev/net/tun > "$case_root/freeze/tun-device.txt"
modinfo ovpn > "$case_root/freeze/ovpn-module.txt" 2>&1
"$ovpn_c" --version > "$case_root/freeze/openvpn-c-version.txt" 2>&1
"$ovpn_hia" --version > "$case_root/freeze/openvpn-hia-version.txt" 2>&1
openssl version -a > "$case_root/freeze/openssl.txt"
ip -Version > "$case_root/freeze/iproute2.txt"
iperf3 --version > "$case_root/freeze/iperf3.txt" 2>&1
sha256sum "$ovpn_c" "$ovpn_hia" > "$case_root/freeze/binaries.sha256"
ip netns list
```

保存每条命令的真实 exit code；读取不到模块信息不自动等于失败或成功（例如 built-in 情形），实际 link/netlink/流量证据仍必需。另存 CPU 型号、允许的 affinity、频率策略、内核 config、相关内核/module hash、NIC/veth offload 设置、全部 configure/CFLAGS/LDFLAGS、OpenSSL 实际链接库、HIA native receipt。固定 C 与 HIA 对照使用相同 `-O3`、PIC/LTO/目标 ISA 设定；不能把不同优化可见性当作语言收益。

实际检查到的官方测试脚本：

| 官方测试 | 可复用部分 | 不能因此宣称 |
| --- | --- | --- |
| `tests/t_cltsrv.sh` | 官方 TLS loopback、约每 10 秒 renegotiation、约两分钟退出；`openvpn` 环境变量可以选 C 或 HIA | 两份 sample config 都是 `dev null`，不是实际 TUN 或 DCO；脚本还可能重试端口冲突，须保留退出/重试 |
| `tests/t_net.sh` | 比较 SITNL test driver 与 iproute2 操作后的 link/address/route 状态 | 需要真正构建 `networking_testdriver`；只验证 dummy interface/networking API，不验证 VPN、认证或 DCO |
| `tests/t_server_null.sh` | multi-client/TCP/UDP/cipher negotiation，以及预定失败组 | 默认 server 创建 TUN，但默认 client 为 `dev null`；不存在 lwipovpn 时 LWIP 组会跳过，不能算端到端 payload 通过 |

本次官方 release archive **未包含** `t_server_null_default.rc` 引用的
`tests/null_client_up.sh` 和 `tests/lwip_client_up.sh`，且 `t_server_null.sh` 需要运行目录中的
`t_server_null.rc`。这些依赖须按准确上游来源补齐并冻结后，才可执行该官方组；不要创建永远成功的替身或隐藏 skip。默认 `1b` 是错误端口、`3b` 是 cipher 不相容，不能冒充证书认证失败试验。

来源：[t_cltsrv.sh](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/tests/t_cltsrv.sh)、[t_net.sh](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/tests/t_net.sh)、[t_server_null_default.rc](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/tests/t_server_null_default.rc)。

## 三、只创建本次隔离网络

确认下列两个名称尚不存在。遇到同名资源停止本组操作，不能删除别人的 namespace 来继续。

```bash
ip netns add ovpn-hia-s-1105
ip netns add ovpn-hia-c-1105
ip -n ovpn-hia-s-1105 link add ovpn-us type veth peer name ovpn-uc netns ovpn-hia-c-1105
ip -n ovpn-hia-s-1105 link set lo up
ip -n ovpn-hia-c-1105 link set lo up
ip -n ovpn-hia-s-1105 address add 192.0.2.1/30 dev ovpn-us
ip -n ovpn-hia-c-1105 address add 192.0.2.2/30 dev ovpn-uc
ip -n ovpn-hia-s-1105 link set ovpn-us up
ip -n ovpn-hia-c-1105 link set ovpn-uc up
ip -n ovpn-hia-s-1105 address show
ip -n ovpn-hia-c-1105 address show
ip -n ovpn-hia-s-1105 route show
ip -n ovpn-hia-c-1105 route show
```

不配置宿主接口、宿主 route/NAT、默认 gateway 或 forwarding。应用端点就在两个 namespace 内，因此不需要替宿主开启转发。

可先在 server namespace 运行官方 loopback 组，保留原始输出和 deadline：

```bash
mkdir "$case_root/official-loopback-c"
cd "$case_root/official-loopback-c"
ip netns exec ovpn-hia-s-1105 env \
  srcdir="$ovpn_src/tests" top_srcdir="$ovpn_src" top_builddir="$ovpn_build" openvpn="$ovpn_c" \
  timeout --signal=TERM --kill-after=10s 600s sh "$ovpn_src/tests/t_cltsrv.sh" \
  > suite.stdout 2> suite.stderr
printf '%s\n' "$?" > suite.exit
```

为 HIA 使用新的运行目录并改 `openvpn`，不覆盖 C 结果。退出 `77` 是 skip，`124` 是外部 timeout，均不计通过。该脚本的约两分钟/端口重试是官方行为，不能缩短后继承原退出条件。

`t_net.sh` 必须在构建目录的 `tests` 工作目录执行，且已启用/编译真正 unit test driver：

```bash
cd "$ovpn_build/tests"
ip netns exec ovpn-hia-s-1105 env \
  srcdir="$ovpn_src/tests" top_builddir="$ovpn_build" openvpn="$ovpn_c" RUN_SUDO= \
  timeout --signal=TERM --kill-after=10s 120s bash "$ovpn_src/tests/t_net.sh" \
  > "$case_root/networking.stdout" 2> "$case_root/networking.stderr"
printf '%s\n' "$?" > "$case_root/networking.exit"
```

当前 build 若未启用 unit tests，先使用相同冻结源码建立有真实 cmocka/test driver 的独立构建，保留该构建差异；脚本的 “driver unavailable / 77” 不能关闭此门禁。该脚本会操作名为 `ovpn-dummy0` 的设备，只能留在上述独占 namespace。

## 四、一次生成实验 PKI，三组复用同一配置

所有新文件均在本次目录；私钥不输出到报告。

```bash
mkdir "$case_root/pki" "$case_root/ccd"
openssl req -new -newkey rsa:2048 -nodes -x509 -days 2 \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -subj /CN=HIA-Lab-CA -keyout "$case_root/pki/ca.key" -out "$case_root/pki/ca.crt"
openssl req -new -newkey rsa:2048 -nodes -subj /CN=HIA-Lab-Server \
  -keyout "$case_root/pki/server.key" -out "$case_root/pki/server.csr"
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' > "$case_root/pki/server.ext"
openssl x509 -req -in "$case_root/pki/server.csr" -CA "$case_root/pki/ca.crt" \
  -CAkey "$case_root/pki/ca.key" -set_serial 1 -days 2 -extfile "$case_root/pki/server.ext" \
  -out "$case_root/pki/server.crt"
openssl req -new -newkey rsa:2048 -nodes -subj /CN=HIA-Lab-Client \
  -keyout "$case_root/pki/client.key" -out "$case_root/pki/client.csr"
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' > "$case_root/pki/client.ext"
openssl x509 -req -in "$case_root/pki/client.csr" -CA "$case_root/pki/ca.crt" \
  -CAkey "$case_root/pki/ca.key" -set_serial 2 -days 2 -extfile "$case_root/pki/client.ext" \
  -out "$case_root/pki/client.crt"
"$ovpn_c" --genkey secret "$case_root/pki/ta.key"
printf '%s\n' 'ifconfig-push 10.77.0.2 255.255.255.0' > "$case_root/ccd/HIA-Lab-Client"
```

建立共同 server/client 配置。这里没有 `redirect-gateway`、compression、fragment、自定义 replay-window 或其它会改变 DCO 可用性的选项。

```bash
cat > "$case_root/server.conf" <<SERVER
proto udp4
local 192.0.2.1
port 1194
dev tunbench-s
dev-type tun
topology subnet
server 10.77.0.0 255.255.255.0 nopool
client-config-dir $case_root/ccd
ca $case_root/pki/ca.crt
cert $case_root/pki/server.crt
key $case_root/pki/server.key
dh none
verify-client-cert require
remote-cert-tls client
tls-auth $case_root/pki/ta.key 0
data-ciphers AES-256-GCM
tun-mtu 1400
reneg-sec 3600 3600
verb 3
SERVER
cat > "$case_root/client.conf" <<CLIENT
client
proto udp4
remote 192.0.2.1 1194
nobind
dev tunbench-c
dev-type tun
ca $case_root/pki/ca.crt
cert $case_root/pki/client.crt
key $case_root/pki/client.key
remote-cert-tls server
verify-x509-name HIA-Lab-Server name
tls-auth $case_root/pki/ta.key 1
data-ciphers AES-256-GCM
tun-mtu 1400
reneg-sec 3600 3600
connect-retry-max 3
server-poll-timeout 5
verb 3
CLIENT
sha256sum "$case_root/server.conf" "$case_root/client.conf" "$case_root/pki/ca.crt" \
  "$case_root/pki/server.crt" "$case_root/pki/client.crt" > "$case_root/freeze/config-public-inputs.sha256"
```

## 五、真实设备与 DCO 路径确认（独立诊断组）

为每次运行新建目录，例如 `run_dir=$case_root/path-check-A`，然后 `mkdir "$run_dir"`。
固定 server 以官方 C 启动，诊断阶段用 `verb 6/status 1` 取得实际 peer 统计：

```bash
ip netns exec ovpn-hia-s-1105 "$ovpn_c" --config "$case_root/server.conf" \
  --verb 6 --status "$run_dir/server.status" 1 --status-version 3 \
  --writepid "$run_dir/server.pid" --log "$run_dir/server.log" --daemon hia-lab-server
```

下面三条 client 命令**每次只执行一条**，上一个进程完全退出后才换组，并使用新 `run_dir`。A/B 的差别仅为二进制；C 则省略 `--disable-dco`：

```bash
# A: official C, DCO off
ip netns exec ovpn-hia-c-1105 "$ovpn_c" --config "$case_root/client.conf" --disable-dco \
  --verb 6 --status "$run_dir/client.status" 1 --writepid "$run_dir/client.pid" \
  --log "$run_dir/client.log" --daemon hia-lab-client
# B: HIA, DCO off
ip netns exec ovpn-hia-c-1105 "$ovpn_hia" --config "$case_root/client.conf" --disable-dco \
  --verb 6 --status "$run_dir/client.status" 1 --writepid "$run_dir/client.pid" \
  --log "$run_dir/client.log" --daemon hia-lab-client
# C: official C, DCO enabled opportunistically; actual use must be checked
ip netns exec ovpn-hia-c-1105 "$ovpn_c" --config "$case_root/client.conf" \
  --verb 6 --status "$run_dir/client.status" 1 --writepid "$run_dir/client.pid" \
  --log "$run_dir/client.log" --daemon hia-lab-client
```

在预定的 30 秒连接截止前检查双方日志、status 和虚拟地址；失败/timeout 保留全部文件。不要将创建了 interface 等同于认证成功。连接后采集：

```bash
ip -n ovpn-hia-s-1105 -d -s -j link show dev tunbench-s > "$run_dir/server-link-before.json"
ip -n ovpn-hia-c-1105 -d -s -j link show dev tunbench-c > "$run_dir/client-link-before.json"
ip -n ovpn-hia-s-1105 -j address show dev tunbench-s > "$run_dir/server-address.json"
ip -n ovpn-hia-c-1105 -j address show dev tunbench-c > "$run_dir/client-address.json"
ip netns exec ovpn-hia-c-1105 ping -n -I 10.77.0.2 -c 20 10.77.0.1 \
  > "$run_dir/ping.stdout" 2> "$run_dir/ping.stderr"
ip -n ovpn-hia-s-1105 -d -s -j link show dev tunbench-s > "$run_dir/server-link-after.json"
ip -n ovpn-hia-c-1105 -d -s -j link show dev tunbench-c > "$run_dir/client-link-after.json"
```

通过条件至少同时满足：

1. 实际应用完成 TLS/证书校验并能双向传输到预定虚拟地址；双方协商 AES-256-GCM，保存 protocol flags/peer 信息。
2. A/B client 的 link 类型为 `tun`；C client 与固定 server 的 `linkinfo.info_kind` 实际为 **`ovpn`**。fallback warning 或只有 `[DCO]` 编译标记时，C 组记为 `DCO_NOT_ACTIVE`，不得并入 DCO 性能样本。
3. 同一活跃 `ovpn` ifindex 的 RX/TX packet/byte counters 在真实流量前后增长，记录 drops/errors。
4. DCO 诊断日志包含从内核 netlink peer reply 获得的 `dco_read_bytes`、`dco_write_bytes`、`tun_read_bytes`、`tun_write_bytes`，且增量和测试流量相符；缺失 peer 字段/错误不能忽略。

上述第 4 条对应官方 `dco_update_peer_stat()` 对 `OVPN_A_PEER_LINK_*` / `OVPN_A_PEER_VPN_*` 的读取。`multi_print_status()` 会查询 DCO peer stats，server status 的 Bytes Received/Sent 是用户态 control 与 DCO bytes 的合计，**不能单独当作纯内核计数器**。依据：[dco_linux.c](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/dco_linux.c)、[multi.c](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/multi.c)、[errlevel.h](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/errlevel.h)。

## 六、认证失败、重放、重连、rekey

每种行为同时运行官方和 HIA 对照，保持同一输入/预算；使用新的运行目录，恢复正常配置后再进入下一组。

| 行为 | 具体动作 | 必须观察 |
| --- | --- | --- |
| 正常互操作 | 两端 DCO off，分别 C/C、C/HIA、HIA/C、HIA/HIA；再测固定官方 DCO peer 的 A/B/C | 正常连接、双向 payload、真实 cipher/epoch 协商、完整日志与退出状态 |
| 证书认证失败 | 用独立 self-signed client cert/key 覆盖 client 配置中的 cert/key，CA/server verification/tls-auth 保持；用原版 `--tls-exit` 与固定 30 秒截止 | 服务端实际证书拒绝；不能建立有效 payload 通路；timeout、TLS/auth 原因分别记录。错误端口/错误 cipher 不替代此项 |
| 重放/重排 | 握手完成后，只在本次 client veth 上加 `netem duplicate 100%`；单独一组再加 delay/reorder | 同一已认证密文重复到达；应用序号不能重复交付；C/HIA 的拒绝与后续合法流量一致。DCO kernel replay 与用户态 replay 分别取证 |
| 重连 | 对本次 client pid 发送 `SIGUSR1`；另做停止并重新启动 client，server 保持 | 新会话完成、旧会话退出、后续 payload 恢复；不能把旧会话重放当成新合法流量 |
| TLS rekey | 双方在新运行中追加 `--reneg-sec 10 10`，持续有限真实流量至少 75 秒 | 多次实际 key update/renegotiation、key install/swap 和成功解密，丢包/断流/重复/错误全部保留；退出超时不能算通过 |

示例负证书和只作用于本次 namespace 的网络扰动：

```bash
openssl req -new -newkey rsa:2048 -nodes -x509 -days 2 -subj /CN=HIA-Lab-Untrusted \
  -keyout "$case_root/pki/untrusted.key" -out "$case_root/pki/untrusted.crt"
# Start a fresh negative client with the common config plus:
# --cert "$case_root/pki/untrusted.crt" --key "$case_root/pki/untrusted.key" --tls-exit

ip netns exec ovpn-hia-c-1105 tc qdisc add dev ovpn-uc root netem duplicate 100%
ip netns exec ovpn-hia-c-1105 ping -n -I 10.77.0.2 -c 100 -i 0.05 10.77.0.1
ip netns exec ovpn-hia-c-1105 tc -s qdisc show dev ovpn-uc
ip netns exec ovpn-hia-c-1105 tc qdisc del dev ovpn-uc root

# Separate run; do not combine with the duplicate case or performance run:
ip netns exec ovpn-hia-c-1105 tc qdisc add dev ovpn-uc root netem delay 20ms 5ms reorder 25% 50%
ip netns exec ovpn-hia-c-1105 ping -n -I 10.77.0.2 -c 100 -i 0.05 10.77.0.1
ip netns exec ovpn-hia-c-1105 tc -s qdisc show dev ovpn-uc
ip netns exec ovpn-hia-c-1105 tc qdisc del dev ovpn-uc root
```

不要在缺少对应权限或已有非本次 qdisc 时自动覆盖它。上面的统计流量是有限 payload 检查；严格密文 replay/跨 rekey replay 仍需保存、重新注入同一已认证 UDP datagram并验证应用唯一序号。该 capture/reinject 辅助器本轮未实现或执行，**这一项在获得实际证据前保持 OPEN**。已经完成的 codec→官方 replay-window differential 不替代此网络级门禁。

## 七、无 trace 的公平流量比较

先结束诊断进程，使用同一二进制和配置重启。三个性能组都恢复 `verb 3`、统一 status 周期（例如 5 秒）；没有 trace wrapper、packet capture、perf sampler、debug DCO 日志或 netem。先冻结组次、包长、并发、deadline、重复次数，随后保留每一个样本，不挑选最快值。

主实验使用上文固定官方 DCO server 的 A/B/C，六种顺序 ABC/ACB/BAC/BCA/CAB/CBA 各执行三次。至少分别保存 TCP 单流正/反向，UDP 相同 offered load 的 64/256/1200-byte payload 组。64/256/1200、100/500/1000 Mbit/s、60 秒只是一组待目标机预注册的起始网格；一旦运行后不能为回避失败修改它。隔离单机 veth 结果不代表真实 NIC、WAN、丢包或跨主机性能。

一次 TCP 流量示例（每次 iperf server `-1` 接收一组便退出）：

```bash
ip netns exec ovpn-hia-s-1105 timeout --signal=TERM --kill-after=5s 100s \
  iperf3 -s -1 -B 10.77.0.1 -J \
  > "$run_dir/iperf-server.json" 2> "$run_dir/iperf-server.stderr" &
iperf_server_pid=$!
ip netns exec ovpn-hia-s-1105 ss -H -ltn 'sport = :5201' \
  > "$run_dir/iperf-listen-before-client.txt"
```

在预定启动期限内确认上述监听输出包含 `10.77.0.1:5201`；未监听时保存失败并结束该样本。确认就绪后启动 client：

```bash
ip netns exec ovpn-hia-c-1105 timeout --signal=TERM --kill-after=5s 75s \
  iperf3 -c 10.77.0.1 -B 10.77.0.2 -t 60 -J \
  > "$run_dir/iperf-client.json" 2> "$run_dir/iperf-client.stderr"
printf '%s\n' "$?" > "$run_dir/iperf-client.exit"
wait "$iperf_server_pid"
printf '%s\n' "$?" > "$run_dir/iperf-server.exit"
```

对新启动的 iperf server，反向组在 client 命令增加 `-R`；UDP 例子增加
`-u -b 100M -l 1200`。不能复用已因 `-1` 退出的 server，然后把连接失败删除。
确保 server 已监听再启动 client；监听失败和启动 deadline 是原始样本的一部分。

同步记录：双方 OpenVPN 与流量进程的 user/system CPU、RSS、affinity；内核 softirq/总 CPU 增量；接口/peer RX/TX、drop/error；iperf receiver goodput、UDP loss/jitter、TCP retransmits、实际传输字节/时间、退出码。DCO 的工作发生在内核，不能只比较两个 daemon 的 CPU。RTT 使用单独同样条件的逐包样本计算分位数，不能从 60 秒吞吐平均值或 codec batch ns/call 推导 p95/p99。

官方 baseline 的热点 profile 在独立重复运行采集，例如拥有 perf 权限时对实际 C endpoint 采样，并另对保留的测试 CPU 集合采集内核/softirq 栈；保存 `perf.data`、事件/权限/丢样信息。**该 profile 运行与没有 profiler 的计时样本分开**。若实际热点不是 packet ID，报告其占比和优化上限；不要用微内核比例推导整个隧道收益。

## 八、退出条件、失败保留和清理

每个 run 保存：源/配置/对象/二进制 identity，主机/内核/module identity，两个 namespace 的完整 link/address/route 状态，真实 cipher/epoch/peer 协商，进程 stdout/stderr/退出码，原始流量输出，所有计数器 before/after，样本序号/顺序/预算和结果分类。将 `PASS`、应用失败、DCO fallback、skip、timeout、崩溃、未完成分别记录；不要只收集有完整结束的成功请求。

只有真实 TUN、互操作、证书拒绝、重放/重连/rekey 与性能各自满足原定条件后才能关闭相应项。DCO 未活跃时应保留 `DCO_NOT_ACTIVE`；HIA 比 C 慢时保留所有退化，不改基线/只报 raw kernel。第一次失败、后继修复和重新测量使用不同目录，不能覆盖或把旧结果改成绿灯。

结束每次应用 run，先读取并核对该 run 的 pid/命令行，对本次两个 OpenVPN 进程发送 TERM 并确认退出；不要使用全局 `pkill openvpn`。确认 namespace 中没有本次遗留进程后，才删除这两个独占 namespace：

```bash
ip netns pids ovpn-hia-s-1105
ip netns pids ovpn-hia-c-1105
# Only after the above lists are empty and all evidence has been copied:
ip netns delete ovpn-hia-s-1105
ip netns delete ovpn-hia-c-1105
```

namespace 名称和 PID 归属必须来自本次创建记录。该清理不会移除证据目录，不触碰宿主默认路由。
