"""Build a trusted-local HIA SHA-256 candidate from a completed cold compiler."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_selfhost_contract import PROFILE

ROOT=Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path, *, candidate='sha256') -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    if candidate not in ('sha256', 'sha256_stream'):
        raise ValueError('unknown HIA SHA-256 candidate')
    raw=cold_report.read_bytes()
    compiler_bytes=compiler.read_bytes()
    compiler_sha=sha256(compiler_bytes).hexdigest()
    sources=admit_cold_build(compiler_bytes,raw)
    source_name='examples/hia_bootstrap/'+candidate+'.hiaasm'
    source_path=ROOT/source_name
    source=source_path.read_bytes()
    if source_name not in sources or sha256(source).hexdigest()!=sources[source_name]:
        raise ValueError('native candidate source differs from admitted cold source')
    output.mkdir(mode=0o700)
    image,receipt=compile_stage(output,candidate,compiler,source)
    image_bytes=image.read_bytes()
    if (source_path.read_bytes()!=source or compiler.read_bytes()!=compiler_bytes
            or cold_report.read_bytes()!=raw or current_sources()!=sources
            or image.read_bytes()!=image_bytes):
        raise ValueError('native candidate build inputs changed')
    kind=candidate.replace('_','-')
    manifest={'schema':'hepta.hia.'+kind+'-native.v1','source_sha256':sha256(source).hexdigest(),
        'image_path':image.name,'image_sha256':sha256(image_bytes).hexdigest(),
        'compiler_sha256':compiler_sha}
    path=output/'manifest.json'
    path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    (output/'build.json').write_text(json.dumps({'schema':'hepta.hia.'+kind+'-build.v1',
        'status':'NATIVE_CANDIDATE_BUILT','profile':PROFILE,'source_manifest':sources,'manifest':manifest,
        'cold_report_sha256':sha256(raw).hexdigest(),'native_compile_receipt':receipt,
        'production_activated':False,'all_input_equivalence_proved':False,
        'whole_stack_rewritten_in_hia':False},indent=2,sort_keys=True)+'\n')
    return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler',type=Path,required=True)
    parser.add_argument('--cold-report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--candidate',choices=('sha256','sha256_stream'),default='sha256')
    args=parser.parse_args()
    print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve(),candidate=args.candidate))


if __name__=='__main__':
    main()
