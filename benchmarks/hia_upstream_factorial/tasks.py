"""Two real stb overflow fixes, with explicit HIA and Rust port provenance.

Both functions come from one upstream change and are correlated samples.
Reference and hidden answers are never placed in the public prompt.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
MIN, MAX = -(1 << 31), (1 << 31) - 1

OLD_FLOOR = '''pub fn target(v1:i32,v2:i32)->i32 {
    if v1 >= 0 && v2 < 0 {
        if (-v1)+v2+1 < 0 { return -((-v1+v2+1)/v2); }
        else { return -((-v1)/v2) + if (-v1)%v2 != 0 {-1} else {0}; }
    }
    if v1 < 0 && v2 >= 0 {
        if v1 != i32::MIN {
            if v1-v2+1 < 0 { return -((v1-v2+1)/(-v2)); }
            else { return -((-v1)/v2) + if v1%(-v2) != 0 {-1} else {0}; }
        } else {
            return -((-(v1+v2))/v2) + if (-(v1+v2))%v2 != 0 {-2} else {-1};
        }
    } else { return v1/v2; }
}
'''
NEW_FLOOR = '''pub fn target(v1:i32,v2:i32)->i32 {
    let a=v1 as i64; let b=v2 as i64;
    let q=a/b; let r=a%b;
    if (r>0 && b<0) || (r<0 && b>0) { (q-1) as i32 } else { q as i32 }
}
'''
OLD_MOD = '''pub fn target(v1:i32,v2:i32)->i32 {
    let r=v1%v2;
    if r >= 0 { r } else { r + if v2>0 {v2} else {-v2} }
}
'''
NEW_MOD = '''pub fn target(v1:i32,v2:i32)->i32 {
    let r=v1%v2;
    if r >= 0 { r } else { r - if v2<0 {v2} else {-v2} }
}
'''


def oracle(task, values):
    a, b = values
    if b == 0 or (a == MIN and b == -1):
        raise ValueError("outside this declared source-domain maintenance task")
    return a // b if task == "stb_floor_overflow" else a % abs(b)


def make_fixtures():
    provenance = json.loads((HERE / "UPSTREAM_TASKS.json").read_text())
    if provenance["ok"] is not True:
        raise ValueError("upstream capture incomplete")
    definitions = [
        ("stb_floor_overflow", "c_stb_div_floor", OLD_FLOOR, NEW_FLOOR,
         "Repair the historical stb_div_floor overflow bug. For all signed i32 a,b where b is nonzero and (a,b) is not (INT_MIN,-1), return floor(a/b) using mathematical signed division, without trapping or overflowing intermediate operations. The current attempts to detect overflow can themselves overflow. Preserve target(i32,i32)->i32; inputs outside this stated domain are not scored.",
         [[8, 3], [8, -3], [-8, 3], [-8, -3], [1, MIN], [MIN+1, MAX]]),
        ("stb_euclidean_int_min", "c_stb_mod_eucl", OLD_MOD, NEW_MOD,
         "Repair the historical stb_mod_eucl overflow bug. For all signed i32 a,b where b is nonzero and (a,b) is not (INT_MIN,-1), return the unique nonnegative remainder r with 0 <= r < abs(b) and a=q*b+r for some integer q. Handle b=INT_MIN without trapping or overflowing intermediate operations. Preserve target(i32,i32)->i32; inputs outside this stated domain are not scored.",
         [[8, 3], [-8, 3], [-8, -3], [-1, MIN], [MIN+1, MIN], [0, MIN]])]
    tasks = []
    for name, function, old_rust, new_rust, description, public in definitions:
        assembly = {}
        for label in ("before", "after"):
            expected = provenance["versions"][label]["selected"][function]
            path = HERE / expected["path"]; raw = path.read_bytes()
            if sha256(raw).hexdigest() != expected["sha256"]:
                raise ValueError("captured upstream fixture changed")
            assembly[label] = raw.decode()
        edges = (MIN, MIN+1, MIN+2, -MAX//2, -255, -8, -3, -2, -1, 0, 1, 2, 3, 8, 255, MAX//2, MAX-1, MAX)
        hidden = [[a,b] for a in edges for b in edges if b and (a,b)!=(MIN,-1) and [a,b] not in public]
        rng = random.Random(0x5B094 if name == "stb_floor_overflow" else 0x5B095)
        for _ in range(128):
            a, b = rng.randint(MIN, MAX), rng.randint(MIN, MAX)
            if b and (a,b)!=(MIN,-1) and [a,b] not in public + hidden:
                hidden.append([a,b])
        task = {"id": name, "function": function, "specification": description,
                "original_assembly": {"target.hepta": assembly["before"]},
                "correct_assembly": {"target.hepta": assembly["after"]},
                "original_rust": {"target.rs": old_rust}, "correct_rust": {"target.rs": new_rust},
                "public_cases": public, "hidden_cases": hidden,
                "provenance": {"upstream_repository": "https://github.com/nothings/stb",
                    "before_commit": "dcb1116f1351bc8edad059d9ca432e8f322ba922",
                    "fix_commit": "c38ec91d229cbe56167f8af865c05b3d92db705f",
                    "after_header_commit": "003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5",
                    "hia": "actual complete C capture; original selected functions and updated remainder have independently checked inlining/representation; updated floor reference is a separately authored mathematical repair, not an approved captured-Core rewrite",
                    "rust": "reviewed manual scalar port; overflow checks enabled; native controls required",
                    "whole_upstream_repository_maintenance": False,
                    "new_or_unseen_to_models_claimed": False}}
        for split in ("public", "hidden"):
            task[split + "_expected"] = [oracle(name, case) for case in task[split + "_cases"]]
        tasks.append(task)
    return tasks


def prompt(task, language):
    if language == "assembly":
        guide = ("The file is one complete explicit primitive HIA assembly module, including its shown header and exports(target). "
            "Exactly one scalar function target with two i32 parameters and one i32 result; only trap effects permitted. "
            "Instruction syntax: result:type = opcode(arg_names) followed by optional JSON attributes. All operands must name values; constants use const() with {\"value\":integer}. "
            "Scalar types i32,i64,u32,u64,bool. int.add/sub/mul/neg/div/rem.checked reject arithmetic overflow or zero division; signed division truncates toward zero. "
            "int.cast needs {\"mode\":\"checked\"} or {\"mode\":\"wrap\"}; compare.eq/ne/lt/le/gt/ge return bool; select(condition,true_value,false_value). "
            "Block parameters and results are explicit name:type. Terminators: ret(names), jump block(names), branch condition yes_block(names) no_block(names), trap code. End the function with end. "
            "Every edge must supply the complete target block parameter list. No loops, recursion, resources, extra functions, FFI or inferred repair.")
    elif language == "rust":
        from benchmarks.hia_upstream_factorial.evaluator import METHODS
        guide = ("The file is one complete Rust source with exactly one public target(i32,i32)->i32 function. "
            "Use only safe scalar integer/Boolean code, let bindings, if/else, return, casts and primitive arithmetic methods. "
            "No comments, imports, external or indirect calls, closures, arrays, macros, attributes, unsafe, allocation, loops, recursion or additional functions. "
            "i32/i64/u32/u64 MIN and MAX constants are allowed. The native evaluator enables overflow checks. "
            "The exact permitted method names are: " + ", ".join(sorted(METHODS)) + ".")
    else:
        raise ValueError("unregistered language")
    return ("Return only the requested JSON source edit.\n" + task["specification"] + "\n" + guide +
        "\nProvenance: two language ports of a real upstream fix; this task does not ask for a whole-library rewrite.\nPublic cases (arguments, expected):\n" +
        json.dumps(list(zip(task["public_cases"], task["public_expected"])), separators=(",", ":")) +
        "\nStarting files:\n" + json.dumps(task["original_" + language], separators=(",", ":")))
