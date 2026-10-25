#!/usr/bin/env python3
"""Independent dual-C-compiler *host-only* ABI differential preflight.

Checks the host's GCC/Clang agreement, NOT any Hepta ABI or Rust soundness.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

HEADER = '''#ifndef HEPTA_ABI_ORACLE_H
#define HEPTA_ABI_ORACLE_H
#include <stdint.h>
typedef struct { uint32_t tag; double scale; uint64_t lanes[2]; } Packet;
Packet abi_transform(Packet p, uint32_t key);
#endif
'''
PRODUCER = '''#include "packet.h"
Packet abi_transform(Packet p, uint32_t key) {
    p.tag ^= key;
    p.scale += 0.5;
    p.lanes[0] += p.lanes[1];
    p.lanes[1] ^= (uint64_t)key;
    return p;
}
'''
CONSUMER = '''#include "packet.h"
#include <stdio.h>
#include <stddef.h>
_Static_assert(offsetof(Packet, scale) == 8, "Packet offset");
_Static_assert(offsetof(Packet, lanes) == 16, "Packet offset");
int main(void) {
    Packet p = {0xaabbccddu, 3.0, {1000, 71}};
    const uint32_t key = 0x10203040u;
    Packet r = abi_transform(p, key);
    if (r.tag != (0xaabbccddu ^ key) || r.scale != 3.5 ||
        r.lanes[0] != 1071 || r.lanes[1] != (71ull ^ key) ||
        p.tag != 0xaabbccddu || p.lanes[0] != 1000) {
        fputs("independent ABI oracle mismatch\n", stderr);
        return 42;
    }
    puts("{\"status\":\"passed\",\"cases\":1}");
    return 0;
}
'''

def sha(b): return hashlib.sha256(b).hexdigest()

def command(argv):
    result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=45)
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise RuntimeError("Tool output exceeds 64 KiB budget")
    return result

def main():
    tools = {name: shutil.which(name) for name in ("gcc", "clang")}
    if any(x is None for x in tools.values()):
        raise RuntimeError("Real host GCC and Clang are both required; never use silent fallback")
    tools = {name: str(Path(value).resolve()) for name, value in tools.items()}
    reports = []
    negatives = []
    with tempfile.TemporaryDirectory(prefix="hepta-host-abi-pair-") as tmp:
        root = Path(tmp)
        (root / "packet.h").write_text(HEADER)
        (root / "consumer.c").write_text(CONSUMER)
        for producer_name in tools:
            for consumer_name in tools:
                for optimization in ("-O0", "-O2"):
                    ident = f"{producer_name}-{consumer_name}-{optimization[1:]}"
                    (root / "producer.c").write_text(PRODUCER)
                    obj = root / f"{ident}.o"
                    exe = root / f"{ident}.exe"
                    for argv in (
                        [tools[producer_name], "-std=c11", optimization, "-Wall", "-Wextra", "-Werror", "-pedantic-errors", "-c", root / "producer.c", "-o", obj],
                        [tools[consumer_name], "-std=c11", optimization, "-Wall", "-Wextra", "-Werror", "-pedantic-errors", root / "consumer.c", obj, "-o", exe],
                    ):
                        proc = command(argv)
                        if proc.returncode:
                            raise RuntimeError("Native compiler failed: " + proc.stderr[:300])
                    result = command([exe])
                    if result.returncode or json.loads(result.stdout) != {"status":"passed", "cases":1}:
                        raise RuntimeError(f"Native ABI pair failed: {ident}: {result.stderr}")
                    reports.append({"producer":producer_name,"consumer":consumer_name,"opt":optimization,"status":"passed","program_sha256":sha(exe.read_bytes()),"object_sha256":sha(obj.read_bytes())})
                    if producer_name != consumer_name and optimization == "-O2":
                        (root / "producer.c").write_text(PRODUCER.replace("p.tag ^= key;", "p.tag += key;"))
                        obj_bad = root / f"{ident}-wrong.o"
                        exe_bad = root / f"{ident}-wrong.exe"
                        for argv in ([tools[producer_name],"-std=c11","-O2","-c",root / "producer.c","-o",obj_bad],
                                     [tools[consumer_name],"-std=c11","-O2",root / "consumer.c",obj_bad,"-o",exe_bad]):
                            res = command(argv)
                            if res.returncode: raise RuntimeError("Wrong-control build did not compile")
                        bad = command([exe_bad])
                        if bad.returncode == 0 or "oracle mismatch" not in bad.stderr:
                            raise RuntimeError("Wrong implementation was not detected")
                        negatives.append({"producer":producer_name,"consumer":consumer_name,"status":"rejected_as_expected","exit":bad.returncode})
    receipt = {"schema":"hepta.independent-dual-c-host.v1","scope":"GCC/Clang C11 host-only, not Hepta ABI or hardware","host":platform.platform(),"toolchains":{key:{"path":v,"sha256":sha(Path(v).read_bytes()),"version":command([v,"--version"]).stdout.splitlines()[0]} for key,v in tools.items()},"sources":{key:sha(val.encode()) for key,val in {"header":HEADER,"producer":PRODUCER,"consumer":CONSUMER}.items()},"pairs":reports,"negative_controls":negatives,"counts":{"positive":len(reports),"negative":len(negatives)},"claims":{"hepta_compiler_used":False,"foreign_cpp_abi_qualified":False,"physical_host_baremetal":False,"real_cross_compiler_c_abi_pairs_executed":True,"complete_c_abi_proved":False}}
    print(json.dumps(receipt,indent=2,sort_keys=True))

if __name__ == '__main__': main()
