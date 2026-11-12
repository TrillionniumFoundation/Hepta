"""Reference-only capacity/native controls. Never imported by model prompts.

These translate retained human reference implementations into actual node edits
using the public source catalogue. They are neither model output nor hints.
"""
import copy
from difflib import SequenceMatcher

from experiments.hia_agent_structured_v7_20261029.rust_syntax import tokens


def rust_reference(session, query, desired):
    changes = []
    originals = session.files
    for file, target in desired.items():
        source = originals[file]
        before, after = tokens(source), tokens(target)
        nodes = [n for n in query["edit_query"]["nodes"] if n.get("file") == file and n["fields"]]
        mutations = []
        selected = {}
        matcher = SequenceMatcher(a=[t.text for t in before], b=[t.text for t in after], autojunk=False)
        for action, a,b,c,d in matcher.get_opcodes():
            if action == "equal":
                continue
            replacement = target[after[c].start:after[d-1].end] if c != d else ""
            if a == b:
                positions = sorted(set(([before[a-1].end] if a else []) + ([before[a].start] if a < len(before) else [])))
                candidates = [(n,position,position) for position in positions for n in nodes if n["start"] <= position <= n["end"]]
            else:
                start,end = before[a].start,before[b-1].end
                candidates = [(n,start,end) for n in nodes if n["start"] <= start and end <= n["end"]]
            if not candidates:
                raise ValueError("reference needs an unsupported source edit outside an authorized node: " + file)
            node,start,end = min(candidates,key=lambda item:(item[0]["end"]-item[0]["start"],item[0]["start"],item[1]))
            selected[node["id"]] = node
            mutations.append((start,end,replacement))
        # One enclosing node absorbs its descendants; overlapping edit requests
        # themselves are never sent to the tool.
        retained = [n for n in selected.values() if not any(m["id"] != n["id"] and m["start"] <= n["start"] and n["end"] <= m["end"] for m in selected.values())]
        for node in sorted(retained,key=lambda n:n["start"]):
            replacement = source[node["start"]:node["end"]]
            relevant = [m for m in mutations if node["start"] <= m[0] and m[1] <= node["end"]]
            for start,end,text in sorted(relevant,reverse=True):
                replacement = replacement[:start-node["start"]]+text+replacement[end-node["start"]:]
            replacement = replacement.strip()
            # Explicit grouping is part of this human reference construction,
            # not a runtime/model repair or normalization performed by the tool.
            if node["category"] == "expression":
                replacement = "(" + replacement + ")"
            changes.append({"node":node["id"],"changes":{"text":replacement}})
    return {"edits":changes}


def hia_reference(session, query, desired):
    changes=[]
    originals=session.files
    for file,target in desired.items():
        before=originals[file];name=before["name"]
        signature={key:copy.deepcopy(target[key]) for key in ("params","returns") if before[key]!=target[key]}
        if signature:
            changes.append({"node":name+"/signature","changes":signature})
        if (before["name"]!=target["name"] or before["entry"]!=target["entry"]
                or before["effects"]!=target["effects"] or [b["id"] for b in before["blocks"]]!=[b["id"] for b in target["blocks"]]):
            raise ValueError("reference requires an unsupported function/effect/block edit")
        for old,new in zip(before["blocks"],target["blocks"]):
            prefix=name+"/"+old["id"]+"/"
            if old["params"]!=new["params"]:
                changes.append({"node":prefix+"parameters","changes":{"params":copy.deepcopy(new["params"])}})
            # Align existing SSA output identities, not a gold-node whitelist.
            def key(op):
                return tuple(out["name"] for out in op["out"]) if op["out"] else (op["op"],tuple(op["args"]))
            matcher=SequenceMatcher(a=[key(op) for op in old["ops"]],b=[key(op) for op in new["ops"]],autojunk=False)
            for action,a,b,c,d in matcher.get_opcodes():
                paired=min(b-a,d-c)
                for offset in range(paired):
                    was,now=old["ops"][a+offset],new["ops"][c+offset]
                    delta={field:copy.deepcopy(now[field]) for field in ("op","args","out","attrs") if was[field]!=now[field]}
                    if delta:
                        changes.append({"node":prefix+"instruction"+str(a+offset),"changes":delta})
                for index in range(a+paired,b):
                    changes.append({"node":prefix+"instruction"+str(index),"changes":{"delete":True}})
                if c+paired<d:
                    changes.append({"node":prefix+"insert"+str(a+paired),"changes":{"operations":copy.deepcopy(new["ops"][c+paired:d])}})
            if old["term"]!=new["term"]:
                changes.append({"node":prefix+"terminator","changes":{"term":copy.deepcopy(new["term"])}})
    return {"edits":changes}


def reference(session, query, task):
    desired=task["correct_"+session.language]
    return (rust_reference(session,query,desired) if session.language=="rust" else hia_reference(session,query,desired))


def identity_response(query):
    for node in query["edit_query"]["nodes"]:
        if not node["fields"]:
            continue
        if "text" in node["fields"]:
            return {"edits":[{"node":node["id"],"changes":{"text":node["text"]}}]}
        if node.get("kind")=="operation":
            return {"edits":[{"node":node["id"],"changes":{"op":node["operation"]["op"]}}]}
    raise ValueError("no source-derived identity edit")
