"""Minimal portable CLI. This is intentionally NOT the production hepta CLI."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import verify,catalog,Refused
from .runtime import run
from .migrate_c import migrate
from .optimizer import eliminate_wrapping_add_zero

def main():
    p=argparse.ArgumentParser(description="Bounded standalone HIA research pilot")
    sub=p.add_subparsers(dest="cmd",required=True)
    sub.add_parser("catalog")
    for cmd in ("check","optimize","run","migrate-c"):
        c=sub.add_parser(cmd);c.add_argument("source")
        if cmd=="run":c.add_argument("--inputs",required=True)
    args=p.parse_args()
    try:
        if args.cmd=="catalog": result=catalog()
        elif args.cmd=="migrate-c":
            m=migrate(args.source);result={"evidence":m.evidence(),"core":m.verified.unpack()}
        else:
            v=verify(Path(args.source).read_bytes())
            if args.cmd=="check":
                result={"status":"FINITE_CORE_ACCEPTED","core_sha256":v.core_digest,
                        "catalog_sha256":v.catalog_digest,"effects":v.effects}
            elif args.cmd=="run":
                inputs=json.loads(args.inputs)
                result=run(v,inputs).json()
            else:
                change=eliminate_wrapping_add_zero(v)
                result={"found":change is not None,
                        "candidate_core":change.candidate.unpack() if change else None,
                        "candidate_digest":change.candidate_digest if change else None}
        print(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False))
    except (Refused,OSError,ValueError) as exc:
        p.exit(2,f"REFUSED: {exc}\n")

if __name__=="__main__":main()
