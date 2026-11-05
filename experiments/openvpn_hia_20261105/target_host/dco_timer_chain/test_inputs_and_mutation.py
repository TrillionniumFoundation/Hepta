#!/usr/bin/env python3
"""Seven canonical-source refusal checks and disabled-hook mutation controls."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import run_timer_chain as chain


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_dir',type=Path)
    parser.add_argument('--cc',default='cc')
    args=parser.parse_args()
    sources=chain.load_sources(args.source_dir)
    with tempfile.TemporaryDirectory(prefix='timer-chain-controls-') as tmp:
        tmp=Path(tmp);source_dir=tmp/'source';source_dir.mkdir()
        for name in chain.SOURCES:shutil.copyfile(args.source_dir/name,source_dir/name)
        for name in chain.SOURCES:
            path=source_dir/name;raw=path.read_bytes();path.write_bytes(raw+b'\n')
            run=subprocess.run([sys.executable,'-B',str(Path(chain.__file__)),str(source_dir),
                                '--cc',str(tmp/'compiler-must-not-start')],
                               capture_output=True,text=True,timeout=5)
            if run.returncode!=2 or 'source differs from pinned official bytes: '+name not in run.stderr:
                raise RuntimeError(f'altered {name} not rejected before compilation: {run}')
            path.write_bytes(raw)
        candidate=chain.build_source(sources,True)
        anchor='        candidate_promotion_timer(c->c2.tls_multi, &wakeup);'
        if candidate.count(anchor)!=1:raise RuntimeError('mutation anchor changed')
        mutant=candidate.replace(anchor,'        if (0) candidate_promotion_timer(c->c2.tls_multi, &wakeup);')
        c=tmp/'disabled-hook.c';c.write_text(mutant)
        for level in ['-O0','-O3']:
            binary=tmp/('mutant'+level[1:])
            subprocess.run([args.cc,'-std=c11','-Wall','-Wextra','-Werror',level,'-fsanitize=undefined',
                            '-fno-sanitize-recover=all',str(c),'-o',str(binary)],check=True,timeout=30)
            run=subprocess.run([str(binary),'--require-promotion-deadline'],capture_output=True,text=True,timeout=5)
            if run.returncode!=23 or 'initial_timeout=10' not in run.stdout:
                raise RuntimeError(f'disabled candidate hook did not reproduce RED: {run}')
    print('PASS seven modified-source refusals before compilation; disabled-hook mutation returns RED 23 at O0/O3.')


if __name__=='__main__':main()
