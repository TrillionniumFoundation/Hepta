#!/usr/bin/env python3
"""Future-host OpenVPN/iperf trial; current-host preflight is read-only.

Requires an administrator-provisioned peer running OpenVPN and iperf3, an
explicit local OpenVPN configuration, and a dedicated tun/ovpn interface name.
It never grants privileges, loads modules or constructs network namespaces.
--preflight-only writes blockers and cannot report a tunnel passed.
Actual trials run the supplied OpenVPN configuration, which may create a device
and apply its configured addresses/routes; use only on the provisioned test host.
"""
import argparse
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def preflight(mode):
    status = Path('/proc/self/status').read_text()
    caps = int(re.search(r'^CapEff:\s*(\w+)',status,re.M).group(1),16)
    config = gzip.decompress(Path('/proc/config.gz').read_bytes()).decode() if Path('/proc/config.gz').exists() else ''
    flags = {k: next((line for line in config.splitlines() if line.startswith(k+'=') or line == '# '+k+' is not set'),None)
             for k in ('CONFIG_TUN','CONFIG_OVPN','CONFIG_NET_NS')}
    blockers = []
    if not caps & (1<<12): blockers.append('CAP_NET_ADMIN is absent')
    if mode == 'userspace' and not Path('/dev/net/tun').exists(): blockers.append('/dev/net/tun is absent')
    if mode == 'dco' and flags['CONFIG_OVPN'] == '# CONFIG_OVPN is not set' and not Path('/sys/module/ovpn').exists():
        blockers.append('running kernel CONFIG_OVPN is disabled and no ovpn module is loaded')
    for tool in ('ip','iperf3'):
        if not shutil.which(tool): blockers.append(tool+' is unavailable')
    return {'mode':mode,'cap_eff':hex(caps),'tun_exists':Path('/dev/net/tun').exists(),'kernel_flags':flags,
            'kernel_config_sha256':hashlib.sha256(config.encode()).hexdigest() if config else None,
            'blockers':blockers,'available':not blockers}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--mode',choices=['userspace','dco'],required=True)
    p.add_argument('--preflight-only',action='store_true');p.add_argument('--binary',type=Path)
    p.add_argument('--config',type=Path);p.add_argument('--interface');p.add_argument('--peer-tun');p.add_argument('--local-tun')
    p.add_argument('--seconds',type=int,default=20)
    a=p.parse_args()
    if a.out.exists() and any(a.out.iterdir()):p.error('output must be a new empty directory')
    a.out.mkdir(parents=True,exist_ok=True)
    result={'schema':'hepta.openvpn-hia.real-tunnel-trial.v1','preflight':preflight(a.mode),
            'real_tun_tunnel_passed':False,'dco_runtime_passed':False,'performance_qualified':False}
    def save(): (a.out/'trial.json').write_text(json.dumps(result,indent=2)+'\n')
    if a.preflight_only or not result['preflight']['available']:
        save();print(json.dumps(result));return 2 if result['preflight']['blockers'] else 0
    if not all((a.binary,a.config,a.interface,a.peer_tun,a.local_tun)):p.error('actual trials require binary, config, interface, peer-tun, local-tun')
    if not 1<=a.seconds<=120:p.error('seconds must be 1..120')
    for addr in (a.peer_tun,a.local_tun):
        if ipaddress.ip_address(addr).is_loopback:p.error('tunnel addresses must not be loopback')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,15}',a.interface):p.error('invalid dedicated interface name')
    result['binary_sha256']=sha(a.binary);result['config_sha256']=sha(a.config)
    command=[str(a.binary.resolve()),'--config',str(a.config.resolve()),'--dev',a.interface,'--verb','4',
             '--status',str((a.out/'status.txt').resolve()),'1','--status-version','3']
    if a.mode=='userspace':command+=['--disable-dco']
    result['openvpn_argv']=command
    result['traffic_argv']=['iperf3','-c',a.peer_tun,'-B',a.local_tun,'-J','-t',str(a.seconds),'-P','1']
    log=a.out/'openvpn.log';proc=None
    try:
        with log.open('wb') as stream:
            proc=subprocess.Popen(command,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
            until=time.monotonic()+30
            while time.monotonic()<until and proc.poll() is None and 'Initialization Sequence Completed' not in log.read_text(errors='replace'):time.sleep(0.1)
            text=log.read_text(errors='replace')
            if proc.poll() is not None or 'Initialization Sequence Completed' not in text:raise RuntimeError('tunnel did not initialize')
            link=subprocess.run(['ip','-details','-json','link','show','dev',a.interface],capture_output=True,text=True,check=True)
            route=subprocess.run(['ip','-json','route','get',a.peer_tun],capture_output=True,text=True,check=True)
            result['link']=json.loads(link.stdout);result['route']=json.loads(route.stdout)
            if not result['route'] or result['route'][0].get('dev')!=a.interface:raise RuntimeError('traffic route does not use the tunnel device')
            kinds=[x.get('linkinfo',{}).get('info_kind') for x in result['link']]
            if a.mode=='dco':
                if 'ovpn' not in kinds or not re.search(r'DCO device .* opened',text):raise RuntimeError('no actual DCO interface/open evidence; fallback is rejected')
            elif 'tun' not in kinds or not re.search(r'TUN/TAP device .* opened',text):raise RuntimeError('no TUN device/open evidence')
            stats_before=Path('/proc',str(proc.pid),'stat').read_text().split();t=time.monotonic()
            traffic=subprocess.run(result['traffic_argv'],capture_output=True,text=True,timeout=a.seconds+15)
            elapsed=time.monotonic()-t
            stats_after=Path('/proc',str(proc.pid),'stat').read_text().split()
            (a.out/'iperf.json').write_text(traffic.stdout);(a.out/'iperf.stderr').write_text(traffic.stderr)
            result['traffic_exit_code']=traffic.returncode;result['traffic_elapsed_seconds']=elapsed
            result['openvpn_cpu_user_seconds']=(int(stats_after[13])-int(stats_before[13]))/os.sysconf('SC_CLK_TCK')
            result['openvpn_cpu_system_seconds']=(int(stats_after[14])-int(stats_before[14]))/os.sysconf('SC_CLK_TCK')
            measurement=json.loads(traffic.stdout)
            if traffic.returncode or 'error' in measurement or proc.poll() is not None:raise RuntimeError('traffic trial failed')
            result['sum_received']=measurement.get('end',{}).get('sum_received')
            if not result['sum_received'] or result['sum_received'].get('bytes',0)<=0:raise RuntimeError('no received tunnel bytes')
            result['real_tun_tunnel_passed']=True;result['dco_runtime_passed']=a.mode=='dco'
            # One trial is never a fair paired performance qualification.
    except Exception as e:result['failure']=str(e)
    finally:
        if proc and proc.poll() is None:
            os.killpg(proc.pid,signal.SIGTERM)
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
        if log.exists():result['log_sha256']=sha(log)
        save()
    print(json.dumps({'real_tun_tunnel_passed':result['real_tun_tunnel_passed'],'dco_runtime_passed':result['dco_runtime_passed'],'failure':result.get('failure')}))
    return 0 if result['real_tun_tunnel_passed'] else 1
if __name__=='__main__':raise SystemExit(main())
