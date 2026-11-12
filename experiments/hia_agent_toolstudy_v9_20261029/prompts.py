"""Public-source-only model presentation for full files versus real node edits."""
from experiments.hia_agent_factorial_v4_20261028 import fixtures, calibration
from experiments.hia_agent_factorial_v6_20261028.prompts import prompt as v6_prompt
from experiments.hia_agent_structured_v7_20261029.editing import digest
from experiments.hia_agent_structured_v7_20261029.rust_syntax import parsed_signature
from tools.provider_adapter.llama_cpp_engine import canonical

REPAIR = ("The previous submission was rejected; the project's original source has NOT changed. This includes a candidate that compiled but returned wrong public values or resources. Recheck all stated requirements, type widths and owner lifetime. Return a new COMPLETE response in the same interface. For node edits, use the SAME original query and resubmit the ENTIRE required edit set, not an increment on the rejected candidate. No previous edits are retained or automatically merged. Only public observations have run.\n")


def render_nodes(query,task):
    inner=query["edit_query"]
    lines=["Actual source revision is retained by the host. Submit only the named node edits; the host attaches this exact revision and complete query digest.",
           "Interface policy: "+query["interface_policy"]+". All node IDs below come from public source, not selected repair sites."]
    if query["language"]=="rust":
        sources={**task["unchanged_rust"],**task["original_rust"]}
        if digest(sources)!=query["source_revision"]:
            raise ValueError("source presentation and actual query revision differ")
        lines.append("Actual editable source, including binding/statement context: "+canonical(task["original_rust"]).decode())
        lines.append("Actual parsed interfaces: "+canonical({name:parsed_signature(text) for name,text in sorted(sources.items())}).decode())
        for node in inner["nodes"]:
            mark="edit" if node["fields"] else "read-only"
            role=" "+node["role"] if node.get("role") else ""
            parameter=" parameter="+node["parameter"] if node.get("parameter") else ""
            lines.append(node["id"]+" "+mark+" "+node["category"]+role+parameter+" bytes="+str(node["start"])+":"+str(node["end"])+" = "+canonical(node["text"]).decode())
    else:
        lines.append("Function/callee interfaces: "+canonical(inner["signatures"]).decode())
        lines.append("Each current function has a single entry block. Function names, effects, entry labels and block identities are fixed; only listed fields are editable. Signature changes are explicit container rebuilds with all unselected fields preserved.")
        for node in inner["nodes"]:
            kind=node["kind"]
            if kind=="operation":
                op=node["operation"]
                value=(",".join(out["name"]+":"+out["type"] for out in op["out"])+"=" if op["out"] else "")+op["op"]+"("+",".join(op["args"])+") "+canonical(op["attrs"]).decode()
            elif kind=="insert":
                value="insert complete operations before original index "+str(node["index"])
            elif kind=="terminator":
                value=canonical(node["term"]).decode()
            else:
                value=canonical({key:node[key] for key in ("params","returns") if key in node}).decode()
            lines.append(node["id"]+" fields="+canonical(node["fields"]).decode()+" "+value)
    return "\n".join(lines)


def prompt(task,arm,query=None):
    language,interface=("rust","node") if arm=="calibration" else arm.split("_")
    if interface=="full":
        text=fixtures.prompt(task,language+"_full").replace("full and query interfaces", "full and node interfaces")
    else:
        if query is None or query["language"]!=language:
            raise ValueError("actual structured tool query required")
        rules=('Every Rust edit uses changes:{"text":"complete replacement fragment"}. For a type node, text is only one allowed type expression; for an expression node, text is only one complete expression. Rust edit spans in the same file must be disjoint: choose a parent expression or its descendants, never both. Preserve unselected syntax; include explicit parentheses when needed to keep surrounding precedence. Parameter/return types are read-only unless policy is migrate.'
               if language=="rust" else
               "HIA replacements are instruction fields op/args/out/attrs, terminators, or explicitly enabled signature/block parameter types. Inserts use complete operation objects with op,args,out,attrs; delete is true by itself. All edits apply atomically and the complete program is reverified.")
        text=("Use the real structured edit tool. Return ONLY JSON {\"edits\":[{\"node\":\"an actual node ID from the source catalogue\",\"changes\":{}}]}. No fences or prose. One to sixteen node edits; every node ID appears at most once. No whole files or whole functions.\n"
              +task["specification"]+"\nThe task's references to files mean their editable symbols; this interface accepts node edits only.\n"+rules
              +"\nPublic examples [arguments,[entrypoint,provider_probe]]: "+canonical(list(zip(task["public_cases"],task["public_expected"]))).decode()
              +"\nComplete public source node catalogue:\n"+render_nodes(query,task))
    original=fixtures.prompt(task,language+"_full")
    language_rules=original.split(task["specification"]+"\n",1)[1].split("\nOnly these two files",1)[0]
    if language=="hia":
        language_rules="HIA resulting functions retain their declared identity. int.cast must"+language_rules.split("int.cast must",1)[1]
    if interface=="node":
        text += "\nComplete resulting-source language rules (response still consists only of node edits): "+language_rules
    if language=="hia":
        text += "\nBoth interfaces preserve the existing function names, entry labels, effect declarations and block identities. Each current function has one entry block. All resulting instructions and ownership flows are reverified together."
    if language=="rust":
        text += ("\nBoth interfaces use the same finite ASCII Rust parser/profile: scalar/Vec<u8> declarations, arithmetic, method/call/index/cast expressions, simple let bindings, assignments, returns and if/block expressions. No Unicode, comments, attributes, strings, closures, custom macros or declarations. The sole allowed macro form is vec![byte;length]. Parser/AST depth <=64; source <=16384 ASCII bytes/file. Signatures are fixed except the declared API migration, which can change types while retaining parameter names and arity.")
    if language=="rust":
        text = text.replace(",".join(fixtures.RUST_METHODS), ",".join((*fixtures.RUST_METHODS, "into")))
        # Reuse the exact reviewed finite primitive conversion disclosure.
        disclosed=v6_prompt(task,"calibration" if arm=="calibration" else "rust_full")
        text += "\nThe into conversion method"+disclosed.split("\nThe into conversion method",1)[1]
    return text


def messages(initial,previous=None,feedback=None):
    if previous is None:
        return [{"role":"user","content":initial}]
    return [{"role":"user","content":initial},{"role":"assistant","content":previous},
            {"role":"user","content":REPAIR+canonical(feedback).decode()}]


def plain_qwen_template(items):
    """Pinned plain-role template, checked against actual server renderings.

    Actual generation will still call the owned server's /apply-template. This
    function is only for the offline capacity check, with no tool-call messages.
    """
    if not items or any(set(item)!={"role","content"} or item["role"] not in {"user","assistant"} or type(item["content"]) is not str for item in items):
        raise ValueError("plain user/assistant messages required")
    return ("<|im_start|>system\nYou are Qwen, created by Alibaba Cloud. You are a helpful assistant.<|im_end|>\n"
            +"".join("<|im_start|>"+item["role"]+"\n"+item["content"]+"<|im_end|>\n" for item in items)
            +"<|im_start|>assistant\n")
