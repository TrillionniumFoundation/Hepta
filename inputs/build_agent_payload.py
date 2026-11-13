"""Explicit development payload; no call to, or bypass of, the cold builder."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).parent/'source'
sys.path.insert(0,str(ROOT))
from tools.qualify_hia_selfhost import compile_stage,invoke
from tools.qualify_hia_selfhost_cli import inspect_executable
from tools.generate_hia_agent_stdio import MAGIC,LIMIT
from tests.test_hia_agent_stdio import packed_reference

out=Path(sys.argv[1]).resolve();out.mkdir(mode=0o700)
compiler=Path(__file__).parent/'development-build-r1/B3.image.bin'
compiler_raw=compiler.read_bytes()
assert sha256(compiler_raw).hexdigest()=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
sources={};images={};receipts={}
for name in ('agent_stdio_dispatch','core_json_frontend','agent_stdio_packer','bytesum'):
    raw=(ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes();sources[name]=raw
    images[name],receipts[name]=compile_stage(out,name,compiler,raw)
payloads=[images[name].read_bytes() for name in ('agent_stdio_dispatch','core_json_frontend')]+[compiler_raw]
frame=struct.pack('<5Q',MAGIC,*map(len,payloads),0)+b''.join(payloads)
assert len(frame)<=LIMIT
report,raw=invoke(out,'agent-pack',images['agent_stdio_packer'],frame)
assert report['status']=='returned' and 0<report['core_u32']<=LIMIT
executable=raw[:report['core_u32']]
assert executable==packed_reference(*payloads,profile=0)
inspection=inspect_executable(executable)
path=out/'hia-native';path.write_bytes(executable);path.chmod(0o700)
assert compiler.read_bytes()==compiler_raw
assert all((ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes()==data for name,data in sources.items())
record={'schema':'hia.release-launch.agent-payload-development.v1','status':'DEVELOPMENT_HIA_AGENT_PAYLOAD',
        'compiler_sha256':sha256(compiler_raw).hexdigest(),
        'source_sha256':{name:sha256(data).hexdigest() for name,data in sources.items()},
        'compile_receipts':receipts,'pack_receipt':report,'executable_inspection':inspection,
        'path':str(path),'sha256':sha256(executable).hexdigest(),'bytes':len(executable),
        'sample_image':str(images['bytesum']),'sample_image_sha256':sha256(images['bytesum'].read_bytes()).hexdigest(),
        'whole_native':False,'matching_cold':False,'source_and_compiler_unchanged':True}
(out/'AGENT.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps({key:record[key] for key in ('status','sha256','bytes','whole_native','matching_cold')},sort_keys=True))
