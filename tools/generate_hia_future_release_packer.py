"""Author the fixed HIA ABI adapter for the three Future observer packers.

The original packers return a status and put the image extent in workspace[0].
Native release filters return the extent. This adapter preserves the original
packer functions and error statuses, checks the extent, and selects only the
three source-bound packers. No executable address comes from a request.
"""
from copy import deepcopy
from pathlib import Path
from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly

ROOT = Path(__file__).resolve().parents[1]
BOOT = 'examples/hia_bootstrap/'
TARGET = BOOT + 'background_optimizer_future_release_packer.hepta'
PACKERS = (
    ('notify', BOOT + 'background_optimizer_future_public_observers_notify_packer.hepta', b'HIABFNPK'),
    ('array', BOOT + 'background_optimizer_future_public_observers_packer.hepta', b'HIABFOPK'),
    ('iterable', BOOT + 'background_optimizer_future_public_observers_iterable_packer.hepta', b'HIABFAPK'),
)

ENTRY = '''hia-asm.v1 hepta.hia.program.v9 background_optimizer_future_release_packer
fn release_extent(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(start)
block start(s:readbuf,o:mutbuf,w:mutbuf)
  sn:usize = buffer.len(s)
  eight:usize = const() {"value":8}
  short:bool = compare.lt(sn,eight)
  branch short invalid() check_workspace(s,o,w)
block check_workspace(s:readbuf,o:mutbuf,w:mutbuf)
  wn:usize = buffer.len(w)
  minimum:usize = const() {"value":64}
  short:bool = compare.lt(wn,minimum)
  branch short invalid() check_notify(s,o,w)
block check_notify(s:readbuf,o:mutbuf,w:mutbuf)
  zero:usize = const() {"value":0}
  magic:u64 = buffer.load.u64.le(s,zero)
  expected:u64 = const() {"value":NOTIFY_MAGIC}
  same:bool = compare.eq(magic,expected)
  branch same notify(s,o,w) check_array(s,o,w,magic)
block check_array(s:readbuf,o:mutbuf,w:mutbuf,magic:u64)
  expected:u64 = const() {"value":ARRAY_MAGIC}
  same:bool = compare.eq(magic,expected)
  branch same array(s,o,w) check_iterable(s,o,w,magic)
block check_iterable(s:readbuf,o:mutbuf,w:mutbuf,magic:u64)
  expected:u64 = const() {"value":ITERABLE_MAGIC}
  same:bool = compare.eq(magic,expected)
  branch same iterable(s,o,w) invalid()
block notify(s:readbuf,o:mutbuf,w:mutbuf)
  status:u32 = call(s,o,w) {"function":"notify_f0"}
  jump status(o,w,status)
block array(s:readbuf,o:mutbuf,w:mutbuf)
  status:u32 = call(s,o,w) {"function":"array_f0"}
  jump status(o,w,status)
block iterable(s:readbuf,o:mutbuf,w:mutbuf)
  status:u32 = call(s,o,w) {"function":"iterable_f0"}
  jump status(o,w,status)
block status(o:mutbuf,w:mutbuf,status:u32)
  zero:u32 = const() {"value":0}
  good:bool = compare.eq(status,zero)
  branch good extent(o,w) failed(status)
block extent(o:mutbuf,w:mutbuf)
  zero:usize = const() {"value":0}
  n:u64 = buffer.load.u64.le(w,zero)
  cap:usize = buffer.len(o)
  limit:u64 = int.cast(cap) {"mode":"wrap"}
  big:bool = compare.gt(n,limit)
  branch big invalid() return_extent(n)
block return_extent(n:u64)
  limit:u64 = const() {"value":4294967292}
  big:bool = compare.gt(n,limit)
  branch big invalid() success(n)
block success(n:u64)
  result:u32 = int.cast(n) {"mode":"wrap"}
  ret(result)
block failed(status:u32)
  ret(status)
block invalid()
  result:u32 = const() {"value":4294967293}
  ret(result)
end
'''


def document():
    source = ENTRY
    for name, _, magic in PACKERS:
        source = source.replace(name.upper() + '_MAGIC', str(int.from_bytes(magic, 'little')))
    result = _parse_assembly_document(source)
    # Assembly SSA identifiers are function-wide, including block parameters.
    entry = result['functions'][0]
    for index, block in enumerate(entry['blocks']):
        values = [*block['params'], *(v for op in block['ops'] for v in op['out'])]
        names = {v['name']: 'entry_' + str(index) + '_' + v['name'] for v in values}
        for op in block['ops']:
            op['args'] = [names[arg] for arg in op['args']]
        term = block['term']
        if term['op'] == 'branch':
            term['cond'] = names[term['cond']]
            for side in ('then', 'else'):
                term[side]['args'] = [names[arg] for arg in term[side]['args']]
        elif term['op'] == 'jump':
            term['args'] = [names[arg] for arg in term['args']]
        elif term['op'] == 'ret':
            term['values'] = [names[arg] for arg in term['values']]
        for value in values:
            value['name'] = names[value['name']]
    entry['params'] = deepcopy(entry['blocks'][0]['params'])
    for name, path, _ in PACKERS:
        original = _parse_assembly_document((ROOT / path).read_bytes())
        names = {fn['name']: name + '_' + fn['name'] for fn in original['functions']}
        assert original['functions'][0]['name'] == 'f0'
        for fn in deepcopy(original['functions']):
            fn['name'] = names[fn['name']]
            for block in fn['blocks']:
                for op in block['ops']:
                    if op['op'] == 'call':
                        op['attrs']['function'] = names[op['attrs']['function']]
            result['functions'].append(fn)
    return result


def main():
    path = ROOT / TARGET
    path.write_text(render_assembly(document()))
    print(path.relative_to(ROOT), path.stat().st_size)


if __name__ == '__main__':
    main()
