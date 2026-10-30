#!/usr/bin/env python3
"""Apply the registered equal native-process limits, record them, then exec."""
from __future__ import annotations
import json
import os
from pathlib import Path
import resource
import sys
import time

ADDRESS_SPACE_BYTES=256*1024*1024

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt",required=True)
    parser.add_argument("binary")
    args=parser.parse_args(argv)
    binary=Path(args.binary).resolve(strict=True)
    receipt=Path(args.receipt)
    if receipt.exists():raise ValueError("do not replace an execution-limit receipt")
    before={"RLIMIT_AS":list(resource.getrlimit(resource.RLIMIT_AS)),
            "RLIMIT_CORE":list(resource.getrlimit(resource.RLIMIT_CORE))}
    resource.setrlimit(resource.RLIMIT_AS,(ADDRESS_SPACE_BYTES,ADDRESS_SPACE_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    after={"RLIMIT_AS":list(resource.getrlimit(resource.RLIMIT_AS)),
           "RLIMIT_CORE":list(resource.getrlimit(resource.RLIMIT_CORE))}
    if after!={"RLIMIT_AS":[ADDRESS_SPACE_BYTES]*2,"RLIMIT_CORE":[0,0]}:
        raise RuntimeError("registered native process limits unavailable")
    record={"schema":"hepta.agent.v8.native-exec-limit.v1","pid":os.getpid(),
        "binary":str(binary),"before":before,"after":after,"created_unix_ns":time.time_ns(),
        "scope":"virtual address space limit, not peak RSS, allocation safety proof or complete OS isolation"}
    with receipt.open("x") as stream:
        json.dump(record,stream,sort_keys=True,separators=(",",":"));stream.write("\n")
    os.execv(str(binary),[str(binary)])

if __name__=="__main__":main()
