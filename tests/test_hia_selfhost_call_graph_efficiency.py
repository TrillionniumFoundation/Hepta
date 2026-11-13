"""Native graph convergence preserves the previous bounded graph verifier."""
import ast
import ctypes
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from tools.generate_hia_selfhost import Builder, source_program, compact_authoring_cfg
from hepta.hia_agent_assembly import render_assembly, assemble_program

# Exact pre-optimization Core authoring routine; not a new graph oracle.
PREVIOUS = 'def check_calls(w:mutbuf) -> u64:\n    n = get(w, 64)\n    step = 0\n    f = 0\n    target = 0\n    ready = 0\n    while step < n:\n        f = 0\n        while f < n:\n            ready = 1\n            target = 0\n            while target < 128:\n                if byte(w, CBASE + f * 128 + target) != 0:\n                    if target >= n:\n                        return fail(w, 55)\n                    if get(w, CSTATE + target * 8) == 0:\n                        ready = 0\n                target = target + 1\n            if ready == 1:\n                put(w, CSTATE + f * 8, 1)\n            f = f + 1\n        step = step + 1\n    f = 0\n    while f < n:\n        if get(w, CSTATE + f * 8) == 0:\n            return fail(w, 56)\n        f = f + 1\n    return 0\n\n'
CBASE, CSTATE, WORKSPACE = 858368, 874752, 1 << 20


def sources():
    text = source_program()
    nodes = {n.name:n for n in ast.parse(text).body}
    previous = PREVIOUS.replace('CBASE',str(CBASE)).replace('CSTATE',str(CSTATE))
    previous = previous.replace('get(w, 64)', 'byte(w, 64)')
    result = {}
    entry = ast.parse('def probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    check_calls(w)\n    return 0\n').body[0]
    for label, graph in [('previous',ast.parse(previous).body[0]), ('candidate',nodes['check_calls'])]:
        selected = [entry,graph] + [nodes[n] for n in ('get','put','fail','state_get32','state_put32')]
        names={n.name:'f'+str(i) for i,n in enumerate(selected)}
        signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in selected}
        functions=[]
        for node in selected:
            builder=Builder(node,names,signatures);builder.statements(node.body)
            functions.append(dict(name=names[node.name],params=[builder.param(p) for p in builder.params],
                returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
        doc=dict(schema='hepta.hia.program.v8',module='graph_probe',functions=functions)
        result[label]=render_assembly(compact_authoring_cfg(doc)).encode()
    return result


def state(count,edges,marked=False):
    work=bytearray(WORKSPACE)
    work[64:72]=count.to_bytes(8,'little')
    work[24:32]=(123).to_bytes(8,'little')
    for a,b in edges:work[CBASE+a*128+b]=255
    if marked:
        for i in range(count):work[CSTATE+i*8:CSTATE+i*8+8]=(1).to_bytes(8,'little')
    return bytes(work)


def vm(source,work):
    from hepta.hia_program_runtime import _Machine,_Owner,_View
    checked=assemble_program(source)
    machine=_Machine(checked,4000000,16<<20,None,128)
    roots=[_Owner(-1,bytearray()),_Owner(-2,bytearray()),_Owner(-3,bytearray(work))]
    result=machine.invoke(checked.as_dict()['functions'][0],[_View(roots[0],False),_View(roots[1],True),_View(roots[2],True)])
    return result,bytes(roots[0].data),bytes(roots[1].data),bytes(roots[2].data)


class CallGraphSourceTests(unittest.TestCase):
    def test_scanner_exact_ASCII_membership_and_full_u64_non_ASCII_refusal(self):
        from hepta.hia_program import execute_program
        node=next(n for n in ast.parse(source_program()).body if n.name=='is_word')
        builder=Builder(node,{},{});builder.statements(node.body)
        function=dict(name='f0',params=[builder.param(p) for p in builder.params],returns=['u64'],
                      effects=['read','write','trap'],entry='b0',blocks=builder.blocks)
        document=dict(schema='hepta.hia.program.v8',module='word_classifier',functions=[function])
        for value in [*range(256),*(1<<bit for bit in range(8,64)),(1<<64)-1]:
            expected=int(value<128 and value in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_')
            self.assertEqual(execute_program(document,'f0',[value])['values'],[expected])

    def test_VM_late_invalid_edges_cycles_and_opposite_topological_orders(self):
        programs=sources()
        cases=[(0,[]),(1,[]),(1,[(0,0)]),(2,[(0,1)]),(2,[(1,0)]),
               (2,[(0,1),(1,0)]),(3,[(0,1),(1,2)]),(3,[(2,1),(1,0)]),
               (3,[(0,0)]),(3,[(2,127)])]
        for count,edges in cases:
            for marked in (False,True):
                with self.subTest(count=count,edges=edges,marked=marked):
                    work=state(count,edges,marked)
                    self.assertEqual(vm(programs['previous'],work),vm(programs['candidate'],work))


class CallGraphNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.folder=Path(tempfile.mkdtemp(prefix='hia-graph-convergence-'))
        seed,_=build_seed(cls.folder)
        cls.images={}
        for label,source in sources().items():
            image,_=compile_stage(cls.folder,label,seed,source,image_format='seed-shared')
            raw=image.read_bytes();cls.images[label]=NativeHiaJsonImage(raw,sha256(raw).hexdigest())

    def compare(self,work):
        observations=[]
        for label in ('previous','candidate'):
            source=ctypes.create_string_buffer(b'Q');output=ctypes.create_string_buffer(b'Z')
            buffer=ctypes.create_string_buffer(work,len(work))
            result=self.images[label]._entry(source,0,output,0,buffer,len(work))
            observations.append((result,source.raw,output.raw,buffer.raw))
        self.assertEqual(observations[0],observations[1])

    def test_all_directed_graphs_up_to_three_functions(self):
        for count in range(4):
            for mask in range(1<<(count*count)):
                edges=[(a,b) for a in range(count) for b in range(count) if mask & (1<<(a*count+b))]
                with self.subTest(count=count,mask=mask):self.compare(state(count,edges))

    def test_original_128_function_domain_and_marked_invalid_last_row(self):
        for count in (4,16,64,128):
            graphs=[[],[(i,i+1) for i in range(count-1)],[(i+1,i) for i in range(count-1)],
                    [(0,i) for i in range(1,count)],[(i,(i+1)%count) for i in range(count)]]
            if count<128:graphs.append([(count-1,127)])
            for edges in graphs:
                for marked in (False,True):
                    with self.subTest(count=count,edges=edges,marked=marked):self.compare(state(count,edges,marked))


if __name__=='__main__':unittest.main()
