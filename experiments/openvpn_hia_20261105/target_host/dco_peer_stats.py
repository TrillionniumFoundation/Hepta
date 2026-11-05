#!/usr/bin/env python3
"""Read actual ovpn generic-netlink peer counters in the calling namespace.

Wire constants follow OpenVPN 2.7.8 ovpn_dco_linux.h and the locked ovpn
backports include/uapi/linux/ovpn.h. This read-only helper sends PEER_GET, never
NEW/SET/DEL or key material. Missing attributes and malformed replies fail.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import time

NLHDR = struct.Struct('=IHHII')
GENLHDR = struct.Struct('=BBH')
NLAHDR = struct.Struct('=HH')
NLM_F_REQUEST, NLM_F_DUMP, NLM_F_MULTI = 1, 0x300, 2
NLMSG_ERROR, NLMSG_DONE, GENL_ID_CTRL = 2, 3, 0x10
# Per request, before journaling or accumulating untrusted multipart replies.
# Exceeding either limit is a rejected measurement, never a partial peer result.
MAX_NETLINK_WIRE_BYTES = 4 * 1024 * 1024
MAX_NETLINK_MESSAGES = 4096
COUNTERS = {16: 'vpn_rx_bytes', 17: 'vpn_tx_bytes', 18: 'vpn_rx_packets', 19: 'vpn_tx_packets',
            20: 'link_rx_bytes', 21: 'link_tx_bytes', 22: 'link_rx_packets', 23: 'link_tx_packets'}


def aligned(n): return (n + 3) & ~3


def attr(kind, payload):
    raw = NLAHDR.pack(4 + len(payload), kind) + payload
    return raw + bytes(aligned(len(raw)) - len(raw))


def attrs(data):
    result = {}; pos = 0
    while pos < len(data):
        if len(data) - pos < 4: raise ValueError('truncated netlink attribute header')
        size, kind = NLAHDR.unpack_from(data, pos)
        if size < 4 or pos + size > len(data): raise ValueError('invalid netlink attribute extent')
        kind &= 0x3fff
        if kind == 0 and size == 4:
            pos += aligned(size); continue
        if kind in result: raise ValueError('duplicate netlink attribute')
        result[kind] = data[pos+4:pos+size]
        pos += aligned(size)
    if pos != len(data): raise ValueError('invalid netlink padding')
    return result


def uint(data, widths=(4, 8)):
    if len(data) not in widths: raise ValueError('unexpected unsigned attribute width')
    return int.from_bytes(data, byteorder=__import__('sys').byteorder)


def request(sock, family, cmd, payload, sequence, dump=False, journal=None):
    body = GENLHDR.pack(cmd, 1 if family != GENL_ID_CTRL else 2, 0) + payload
    flags = NLM_F_REQUEST | (NLM_F_DUMP if dump else 0)
    raw = NLHDR.pack(16+len(body), family, flags, sequence, sock.getsockname()[0]) + body
    sock.send(raw); replies = []; finished = False
    if journal is not None: journal.append({'direction':'request','sequence':sequence,'hex':raw.hex()})
    until = time.monotonic() + 3
    received_bytes = 0
    received_messages = 0
    for _ in range(256):
        sock.settimeout(max(0.01, until-time.monotonic()))
        data, ancillary, recvflags, address = sock.recvmsg(1 << 20)
        received_bytes += len(data)
        if received_bytes > MAX_NETLINK_WIRE_BYTES:
            raise ValueError('netlink reply wire budget exceeded')
        if journal is not None: journal.append({'direction':'reply','sequence':sequence,'hex':data.hex(),
                                                'sender_port_id':address[0],'recv_flags':recvflags})
        if address[0] != 0 or recvflags & socket.MSG_TRUNC: raise ValueError('non-kernel or truncated netlink reply')
        pos = 0
        while pos < len(data):
            received_messages += 1
            if received_messages > MAX_NETLINK_MESSAGES:
                raise ValueError('netlink message budget exceeded')
            if len(data) - pos < 16: raise ValueError('short netlink message')
            size, kind, flags, seq, pid = NLHDR.unpack_from(data, pos)
            if size < 16 or pos + size > len(data): raise ValueError('invalid netlink message extent')
            body = data[pos+16:pos+size]; pos += aligned(size)
            if seq != sequence: continue
            if flags & 0x10: raise ValueError('interrupted netlink dump')
            if kind == NLMSG_ERROR:
                if len(body)<4: raise ValueError('short netlink error')
                error = struct.unpack_from('=i',body)[0]
                if error: raise OSError(-error, os.strerror(-error))
                continue
            if kind == NLMSG_DONE:
                if len(body)>=4 and struct.unpack_from('=i',body)[0]: raise RuntimeError('netlink dump reported an error')
                finished = True; break
            if kind != family or len(body)<4: raise ValueError('unexpected generic-netlink reply family')
            reply_cmd, version, reserved = GENLHDR.unpack_from(body)
            if reply_cmd != (1 if family == GENL_ID_CTRL else cmd) or version != (2 if family == GENL_ID_CTRL else 1):
                raise ValueError('unexpected generic-netlink command/version')
            replies.append(attrs(body[4:]))
            if not dump and not flags & NLM_F_MULTI: finished = True
        if finished: return replies
        if time.monotonic() >= until: break
    raise TimeoutError('ovpn netlink reply deadline exceeded')


def query(interface, journal=None):
    index = socket.if_nametoindex(interface)
    ns = os.stat('/proc/self/ns/net').st_ino
    if journal is None: journal = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_GENERIC if hasattr(socket,'NETLINK_GENERIC') else 16) as s:
        s.bind((0,0))
        family_rows = request(s, GENL_ID_CTRL, 3, attr(2,b'ovpn\0'), 1, journal=journal)
        if len(family_rows)!=1 or 1 not in family_rows[0]: raise ValueError('missing ovpn family ID')
        family = uint(family_rows[0][1], (2,))
        rows = request(s, family, 3, attr(1,struct.pack('=I',index)), 2, dump=True, journal=journal)
    peers=[]; seen=set()
    for row in rows:
        if 1 in row and uint(row[1], (4,)) != index: raise ValueError('reply belongs to another interface')
        if 2 not in row: raise ValueError('missing nested peer attributes')
        peer=attrs(row[2])
        if 1 not in peer or not all(key in peer for key in COUNTERS): raise ValueError('missing peer ID or counters')
        identity=uint(peer[1], (4,))
        if identity in seen: raise ValueError('duplicate peer ID in dump')
        seen.add(identity)
        peers.append({'peer_id':identity, **{name:uint(peer[key]) for key,name in COUNTERS.items()}})
    if not peers: raise ValueError('no actual ovpn peer returned')
    return {'schema':'hepta.openvpn-hia.ovpn-netlink-peer.v1','interface':interface,'ifindex':index,
            'netns_inode':ns,'family_id':family,'peers':peers,'monotonic_ns':time.monotonic_ns(),
            'source':'kernel OVPN_CMD_PEER_GET; eight native peer counters; no status-file totals',
            'helper_sha256':__import__('hashlib').sha256(Path(__file__).read_bytes()).hexdigest(),
            'netlink_wire_records':journal}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--interface',required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    # Exclusive creation is the final file-system authorization check: Path.exists()
    # is false for dangling links and cannot protect against a replacement race.
    journal = []
    try: result=query(a.interface, journal); code=0
    except Exception as e:
        result={'schema':'hepta.openvpn-hia.ovpn-netlink-peer.v1','failure':str(e),'interface':a.interface,
                'netns_inode':os.stat('/proc/self/ns/net').st_ino,'netlink_wire_records':journal,
                'helper_sha256':__import__('hashlib').sha256(Path(__file__).read_bytes()).hexdigest()};code=1
        try:result['ifindex']=socket.if_nametoindex(a.interface)
        except OSError:pass
    a.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        # Mode 'x' uses O_CREAT|O_EXCL: never follow or replace a leaf symlink,
        # hard link, or file inserted between preflight and evidence publication.
        with a.out.open('x', encoding='utf-8') as f:
            f.write(json.dumps(result,indent=2)+'\n')
    except FileExistsError:
        p.error('output exists')
    print(json.dumps(result));return code
if __name__=='__main__':raise SystemExit(main())
