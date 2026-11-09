"""Batch independent straight-line VM witnesses without embedding input values.

Only qualification fixtures are transformed. Every operand remains loaded from
caller bytes and every result remains separately observable in the output.
Identical typed scalar constants may share an SSA definition after byte-offset
relocation; no load, arithmetic operation, store or call is removed.
"""
from collections import defaultdict
from copy import deepcopy
from hashlib import sha256
import json


def batch_cases(cases, maximum=12):
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    groups, documents = defaultdict(list), {}
    for case in cases:
        source = case["source"]
        if source not in documents:
            documents[source] = assemble_program(source.encode()).as_dict()
        document = documents[source]
        helper_key = sha256(json.dumps(document["functions"][1:],sort_keys=True).encode()).hexdigest()[:12]
        groups[case.get("batch_group",case["program"]) + "-" + helper_key].append(case)
    result = []
    for name, group in groups.items():
        chunks=[]
        start=0
        while start<len(group):
            chunk=[];definitions=4;instructions_count=1
            for case in group[start:start+maximum]:
                entry=documents[case["source"]]["functions"][0]
                local_ops=entry["blocks"][0]["ops"]
                additional=sum(len(op["out"]) for op in local_ops)
                if definitions+additional>2048 or instructions_count+len(local_ops)>8192:
                    break
                chunk.append(case);definitions+=additional;instructions_count+=len(local_ops)
            if not chunk:raise ValueError("one witness exceeds the unchanged native profile capacity")
            chunks.append(chunk);start+=len(chunk)
        for batch_index,chunk in enumerate(chunks):
            original = documents[chunk[0]["source"]]
            fn = original["functions"][0]
            ops,serial,source_base,output_base = [],3,0,0
            constants = {}
            for case in chunk:
                document = documents[case["source"]]
                entry = document["functions"][0]
                if len(entry["blocks"]) != 1 or entry["params"] != fn["params"] or entry["returns"] != ["u32"]:
                    raise ValueError("batching requires a compatible straight-line public entry")
                if document["functions"][1:] != original["functions"][1:] or entry["effects"] != fn["effects"]:
                    raise ValueError("batching cannot change helper or effect identity")
                instructions = entry["blocks"][0]["ops"]
                offsets = {}
                for op in instructions:
                    if op["op"] == "buffer.load": offsets[op["args"][1]] = "input"
                    if op["op"] == "buffer.store": offsets[op["args"][1]] = "output"
                definitions = {p["name"]:op for op in instructions for p in op["out"]}
                for index in offsets:
                    defining = definitions[index]
                    uses = [op for op in instructions if index in op["args"]]
                    if defining["op"] != "const" or defining["out"][0]["type"] != "usize" or len(uses) != 1:
                        raise ValueError("fixture buffer indices must be unshared constant usize values")
                names={"v0":"v0","v1":"v1","v2":"v2"}
                for instruction in instructions:
                    op=deepcopy(instruction)
                    op["args"]=[names[v] for v in instruction["args"]]
                    for old,out in zip(instruction["out"],op["out"]):
                        fresh="v"+str(serial);serial+=1
                        names[old["name"]]=fresh;out["name"]=fresh
                        if old["name"] in offsets:
                            op["attrs"]["value"] += source_base if offsets[old["name"]]=="input" else output_base
                    if op["op"] == "const" and len(op["out"]) == 1:
                        key = (op["out"][0]["type"], json.dumps(op["attrs"],sort_keys=True))
                        if key in constants:
                            names[instruction["out"][0]["name"]] = constants[key]
                            serial -= 1
                            continue
                        constants[key] = op["out"][0]["name"]
                    ops.append(op)
                source_base+=len(bytes.fromhex(case["source_hex"]))
                output_base+=len(bytes.fromhex(case["expected_hex"]))
            zero="v"+str(serial)
            ops.append({"op":"const","args":[],"out":[{"name":zero,"type":"u32"}],"attrs":{"value":0}})
            block={**fn["blocks"][0],"ops":ops,"term":{"op":"ret","values":[zero]}}
            updated={**original,"functions":[{**fn,"blocks":[block]},*original["functions"][1:]]}
            # render_assembly itself fully verifies the document AND checks
            # its parsed canonical round trip. The VM later rechecks the actual
            # wrapper plus this program before B0; do not duplicate that parse.
            source=render_assembly(updated)
            result.append({**chunk[0],"id":name+"-batch-"+str(batch_index)+"-sample",
                "program":name+"-batch-"+str(batch_index),"source":source,
                "source_hex":"".join(c["source_hex"] for c in chunk),
                "initial_hex":"".join(c["initial_hex"] for c in chunk),
                "expected_hex":"".join(c["expected_hex"] for c in chunk),
                "fixture_transform": "rebase-input/output-byte-indices; share-identical-typed-constants-only",
                "input_cases":[{"id":c["id"],"source_hex":c["source_hex"],"expected_values":c["expected_values"]} for c in chunk]})
    return result
