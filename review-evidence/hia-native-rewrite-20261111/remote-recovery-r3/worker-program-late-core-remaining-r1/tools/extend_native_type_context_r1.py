"""Exact type-owner first-error context and public name-order correction.

New independent authoring revision. No generated/native result is inherited.
The old generator and old source remain byte-for-byte preserved dependencies.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256
from pathlib import Path

ORIGINAL_SHA="8989302bfd890ca9fa43662413a27c88c740c0060cb7631b7c1e4ef332cfa3e7"
ORIGINAL_BYTES=68113
ORIGINAL_HIA_SHA="33969ee0fdec37c27ebf017c52d01e20748118d643589cf280042a39f68e3d6b"
CONTEXT_MAGIC=int.from_bytes(b"HIATDX01","little")
CONTEXT_OFFSET=96*1024*1024+192
CONTEXT_BYTES=64
# Numeric IDs are transport data issued by the actual native call site.
WHERE={
 1:"nominal type",2:"type parameter",3:"enum variant",4:"variant",
 5:"task poll function",6:"task cancellation function",7:"nominal field",
 8:"field",9:"type reference",10:"partial record type",
 11:"initialized record field",12:"generic type reference",13:"generic type name",
 14:"nominal parameter",15:"parameter",16:"nominal returned-loan origin",
 17:"returned-loan parameter",18:"returned-loan field"}
NAME_CONTEXTS=(1,2,4,5,6,8,9,11,13,15,17,18)
SHAPE_CONTEXTS={
 1:(("name","params","kind","fields"),("name","params","kind","variants"),
    ("name","params","kind","state","result","poll","cancel")),
 3:(("name","fields"),),7:(("name","type"),),
 10:(("partial","initialized"),),12:(("name","args"),),
 14:(("name","type"),),16:(("param","fields"),)}
BODY=r'''
def diagnostic_context(w:mutbuf, code:u64, where:u64, expected:u64, node:u64) -> u64:
    put(w, TYPE_DIAGNOSTIC + 8, 1)
    put(w, TYPE_DIAGNOSTIC + 16, code)
    put(w, TYPE_DIAGNOSTIC + 24, where)
    put(w, TYPE_DIAGNOSTIC + 32, expected)
    put(w, TYPE_DIAGNOSTIC + 40, node)
    put(w, TYPE_DIAGNOSTIC + 48, 0)
    put(w, TYPE_DIAGNOSTIC + 56, 0)
    put(w, TYPE_DIAGNOSTIC, TYPE_DIAGNOSTIC_MAGIC)
    return 0

def diagnostic_name(w:mutbuf, node:u64, where:u64) -> u64:
    before = error(w)
    result = name_ok(w, node)
    if before == 0 and result == 0:
        diagnostic_context(w, error(w), where, 0, node)
    return result

def diagnostic_shape(w:mutbuf, node:u64, expected:u64, where:u64) -> u64:
    if error(w) == 0:
        diagnostic_context(w, 1, where, expected, node)
    return reject(w, 1)
'''

def replace_once(text,before,after,label):
    assert text.count(before)==1,(label,before,text.count(before))
    return text.replace(before,after,1)

def apply(original):
    raw=Path(original.__file__).read_bytes()
    assert (len(raw),sha256(raw).hexdigest())==(ORIGINAL_BYTES,ORIGINAL_SHA)
    tree=ast.parse(original.BODY)
    assert all(isinstance(node,ast.FunctionDef) for node in tree.body)
    nodes={node.name:copy.deepcopy(node) for node in tree.body}
    assert len(nodes)==len(tree.body)
    before={name:ast.dump(node,include_attributes=False) for name,node in nodes.items()}
    patches={}
    def edit(name,replacements):
        text=ast.unparse(nodes[name])
        for old,new in replacements:text=replace_once(text,old,new,name)
        nodes[name]=ast.parse(text).body[0]
        patches[name]=len(replacements)
    edit("types_main",[
       ("    copy_words(o, w, Q, decoded_size)",
        "    copy_words(o, w, Q, decoded_size)\n    fill_range(w, TYPE_DIAGNOSTIC, 64, 0)")])
    # _name calls the complete public _ident grammar before checking the
    # elaborator prefix. Preserve all old reads/limits but move this test
    # after the complete ASCII loop, so h2internal_bad$ has the original
    # invalid-name priority instead of the old native namespace priority.
    reserved="    if n >= 11 and same(w, start, 11, L_reserved_nominal) == 1:\n        return reject(w, 6)\n"
    edit("name_ok",[(reserved,""),("    return 1",reserved+"    return 1")])
    edit("register_definition",[
       ("return reject(w, 1)","return diagnostic_shape(w, item, fields, 1)"),
       ("name_ok(w, name)","diagnostic_name(w, name, 1)"),
       ("name_ok(w, param)","diagnostic_name(w, param, 2)")])
    edit("validate_definition",[
       ("return reject(w, 1)","return diagnostic_shape(w, variant, K_name | K_fields, 3)"),
       ("name_ok(w, name)","diagnostic_name(w, name, 4)"),
       ("name_ok(w, field(w, item, K_poll))","diagnostic_name(w, field(w, item, K_poll), 5)"),
       ("name_ok(w, field(w, item, K_cancel))","diagnostic_name(w, field(w, item, K_cancel), 6)")])
    edit("validate_fields",[
       ("return reject(w, 1)","return diagnostic_shape(w, item, K_name | K_type, 7)"),
       ("name_ok(w, name)","diagnostic_name(w, name, 8)")])
    edit("validate_ref",[
       ("name_ok(w, ref)","diagnostic_name(w, ref, 9)"),
       ("                if get(w, S + 64) == 0 or shape(w, ref, K_partial | K_initialized) == 0:\n                    return reject(w, 1)",
        "                if get(w, S + 64) == 0:\n                    return diagnostic_shape(w, ref, K_name | K_args, 12)\n"
        "                if shape(w, ref, K_partial | K_initialized) == 0:\n                    return diagnostic_shape(w, ref, K_partial | K_initialized, 10)"),
       ("name_ok(w, item)","diagnostic_name(w, item, 11)"),
       ("                if shape(w, ref, K_name | K_args) == 0:\n                    return reject(w, 1)",
        "                if shape(w, ref, K_name | K_args) == 0:\n                    return diagnostic_shape(w, ref, K_name | K_args, 12)"),
       ("name_ok(w, name)","diagnostic_name(w, name, 13)")])
    edit("resolve_parameters",[
       ("return reject(w, 1)","return diagnostic_shape(w, item, K_name | K_type, 14)"),
       ("name_ok(w, name)","diagnostic_name(w, name, 15)")])
    edit("resolve_origin",[
       ("return reject(w, 1)","return diagnostic_shape(w, annotation, K_param | K_fields, 16)"),
       ("name_ok(w, name)","diagnostic_name(w, name, 17)"),
       ("name_ok(w, item)","diagnostic_name(w, item, 18)")])
    added=ast.parse(BODY).body
    assert len(added)==3 and all(isinstance(n,ast.FunctionDef) for n in added)
    assert not({node.name for node in added}&set(nodes))
    assert all(ast.dump(nodes[name],include_attributes=False)==old
               for name,old in before.items() if name not in patches)
    # The public first-error register, descriptor commit/render logic,
    # private task/origins admission and all remaining functions are intact.
    for name in ("reject","shape","error","render_result","render_parameters",
                 "render_origins","task_protocol","admit_origins"):
        assert ast.dump(nodes[name],include_attributes=False)==before[name],name
    assert original.CONSTANTS["S"]+184<CONTEXT_OFFSET
    assert CONTEXT_OFFSET+CONTEXT_BYTES<original.CONSTANTS["DEFS"]
    assert "TYPE_DIAGNOSTIC" not in original.CONSTANTS
    original.CONSTANTS.update(TYPE_DIAGNOSTIC=CONTEXT_OFFSET,
                             TYPE_DIAGNOSTIC_MAGIC=CONTEXT_MAGIC)
    changed=ast.Module(body=[nodes[node.name] for node in tree.body]+added,type_ignores=[])
    original.BODY=ast.unparse(ast.fix_missing_locations(changed))+"\n"
    return dict(schema="hia-native-type-context-authoring-r1",
       original_generator_bytes=ORIGINAL_BYTES,original_generator_sha256=ORIGINAL_SHA,
       original_HIA_sha256=ORIGINAL_HIA_SHA,changed_methods=patches,
       added_methods=[node.name for node in added],
       all_other_method_AST_equal=True,original_private_render_and_commit_AST_equal=True,
       context_offset=CONTEXT_OFFSET,context_bytes=CONTEXT_BYTES,
       context_only_on_first_public_name_or_shape_rejection=True,
       context_reset_after_actual_successful_decode=True,
       private_header_errors_not_promoted_to_public_text=True,
       type_name_ascii_validation_now_precedes_elaborator_prefix=True,
       expected_old_new_difference_for_mixed_bad_prefix_is_error6_to5=True,
       native_context_is_not_foreign_workspace_authentication=True,
       namespace_authority=False,full_program_integration=False)
