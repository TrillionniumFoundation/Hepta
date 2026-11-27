"""Static call-chain review only; never import or execute product modules."""
from pathlib import Path
import ast
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parent
AUTHOR = Path('/tmp/hia-u32-entry-layout-r1-dda7')
SOURCE = Path('/workspace/scratch/dda74a4fae35/v121-selfhost-small-constant-r1/candidate/source')
INPUTS = {}


def read(path):
    raw = path.read_bytes()
    INPUTS[str(path)] = {
        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'mode': stat.S_IMODE(path.stat().st_mode),
    }
    return raw


def tree(path):
    return ast.parse(read(path), filename=str(path))


def function(module, name):
    return next(n for n in module.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name)


def method(cls, name):
    return function(cls, name)


def calls(node, name):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)
            and ((isinstance(n.func, ast.Name) and n.func.id == name)
                 or (isinstance(n.func, ast.Attribute) and n.func.attr == name))]


def literal_keyword(call, name):
    return ast.literal_eval(next(k.value for k in call.keywords if k.arg == name))


def original_text(path, name):
    text = read(path).decode()
    node = function(ast.parse(text), name)
    return ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def anchor(path, node):
    return {'path': str(path), 'function': node.name, 'first_line': node.lineno, 'last_line': node.end_lineno}


def main():
    runner_path = AUTHOR / 'run_entry_layout.py'
    support_path = AUTHOR / 'entry_support.py'
    transport_path = AUTHOR / 'entry_transport.py'
    projection_path = AUTHOR / 'entry_projection.py'
    loader_path = AUTHOR / 'hia_selfhost_child_frames.py'
    runner = tree(runner_path)
    support = tree(support_path)
    transport = tree(transport_path)
    projected_tree = tree(projection_path)
    loader = tree(loader_path)
    plan = json.loads(read(AUTHOR / 'EXECUTION-PLAN.json'))
    expected = json.loads(read(AUTHOR / 'EXPECTED-IDS.json'))
    spec = json.loads(read(AUTHOR / 'PROJECTION-SPEC.json'))
    source_manifest = json.loads(read(AUTHOR / 'FROZEN-3180-SOURCE.json'))

    names_path = SOURCE / 'tools/hia_selfhost_names.py'
    q_path = SOURCE / 'tools/qualify_hia_selfhost.py'
    cfg_path = SOURCE / 'tools/hia_selfhost_cfg_worklist.py'
    program_path = SOURCE / 'hepta/hia_program.py'
    vm_path = SOURCE / 'hepta/hia_program_runtime.py'
    cli_path = SOURCE / 'tools/qualify_hia_selfhost_cli.py'
    owner_path = SOURCE / 'tools/hia_selfhost_process_owner.py'
    q, cfg, program, vm, cli, owner = [tree(p) for p in
        (q_path, cfg_path, program_path, vm_path, cli_path, owner_path)]
    old = original_text(names_path, 'qualify_entry_layout')
    new = original_text(projection_path, 'qualify_entry_layout_explicit')
    inverse = new
    for replacement in reversed(spec['replacements']):
        assert inverse.count(replacement['after']) == 1
        inverse = inverse.replace(replacement['after'], replacement['before'], 1)
    assert len(spec['replacements']) == 3 and inverse == old == spec['original_function']
    assert ast.dump(ast.parse(inverse), include_attributes=False) == ast.dump(ast.parse(old), include_attributes=False)

    projection = function(projected_tree, 'qualify_entry_layout_explicit')
    cfg_fn = function(cfg, 'qualify')
    cfg_cases = function(cfg, 'cases')
    facade = function(program, 'execute_program')
    vm_fn = function(vm, 'execute_program')
    q_compile = function(q, 'compile_stage')
    q_invoke = function(q, 'invoke')
    q_tool = function(q, 'observe_native_tool')
    cli_execute = function(cli, 'execute')
    owner_run = function(owner, 'run_owned')
    owner_supervise = function(owner, 'supervise')
    child = function(runner, 'child')
    driver = function(runner, 'driver')
    admission = function(runner, 'report_admission')
    journal = function(support, 'GateJournal')
    journal_call = method(journal, 'call')
    inventory = function(support, 'frame_inventory')

    # The projection imports consumers when invoked INSIDE the installed journal.
    assert any(isinstance(n, ast.ImportFrom) and n.module == 'hepta.hia_program'
               and any(a.name == 'execute_program' for a in n.names) for n in projection.body)
    assert any(isinstance(n, ast.ImportFrom) and n.module == 'tools.qualify_hia_selfhost'
               and {'compile_stage', 'invoke', 'observe_native_tool'} <= {a.name for a in n.names}
               for n in cfg_fn.body)
    with_calls = [n for n in ast.walk(child) if isinstance(n, ast.With)
                  and any(isinstance(i.context_expr, ast.Call)
                          and isinstance(i.context_expr.func, ast.Attribute)
                          and i.context_expr.func.attr == 'GateJournal' for i in n.items)]
    assert len(with_calls) == 1
    actual_gate_calls = [n for n in ast.walk(with_calls[0]) if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Subscript)
                        and isinstance(n.func.slice, ast.Constant)
                        and n.func.slice.value == 'qualify_entry_layout_explicit']
    assert len(actual_gate_calls) == 1

    # Two actual resource case rows; original loop and three direct checks stay exact.
    selected = ('queued-owner-and-local-loan', 'queued-chain-move-drop')
    selected_adds = [n for n in calls(cfg_cases, 'add')
                     if n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value in selected]
    assert [n.args[0].value for n in selected_adds] == list(selected)
    assert len(calls(projection, 'compile_stage')) == 4
    assert len(calls(projection, 'execute_program')) == 1
    assert len(calls(projection, 'execute')) == 1
    assert len(calls(projection, 'qualify_cfg')) == 1
    # The second CFG loop is refusals=[] in this exact entry call, so only the
    # accepted-case compile/link/run body is reachable here.
    cfg_call = calls(projection, 'qualify_cfg')[0]
    reference_dict = cfg_call.args[3]
    assert isinstance(reference_dict, ast.Dict)
    ref_values = {ast.literal_eval(k): v for k, v in zip(reference_dict.keys, reference_dict.values)}
    assert isinstance(ref_values['refusals'], ast.List) and not ref_values['refusals'].elts
    counts = {'compile': 4 * (4 + 2), 'invoke': 4 * (4 + 2 + 2),
              'reference': 4 * 2, 'tool': 4 * 2, 'executable': 4, 'mutation': 1}
    assert counts == expected['call_counts'] == plan['expected']['call_counts']
    assert len(expected['check_ids']) == 20 and len(set(expected['check_ids'])) == 20
    assert len(expected['compile_labels']) == 24 and len(expected['invoke_labels']) == 32
    assert len(expected['link_labels']) == 8 and len(expected['executable_labels']) == 4

    # Facade does not inject fuel; the exact reference call supplies no keyword.
    reference_call = calls(projection, 'execute_program')[0]
    assert len(reference_call.args) == 3 and not reference_call.keywords
    vm_defaults = dict(zip([x.arg for x in vm_fn.args.kwonlyargs], vm_fn.args.kw_defaults))
    assert ast.literal_eval(vm_defaults['max_steps']) == 1_000_000
    assert facade.args.kwarg.arg == 'kwargs'
    forward = calls(facade, 'execute')[0]
    assert len(forward.args) == 3 and len(forward.keywords) == 1
    assert forward.keywords[0].arg is None and isinstance(forward.keywords[0].value, ast.Name)
    assert forward.keywords[0].value.id == 'kwargs'
    delegates = calls(journal_call, 'original')
    assert len(delegates) == 1 and len(delegates[0].args) == 1
    assert isinstance(delegates[0].args[0], ast.Starred)
    assert len(delegates[0].keywords) == 1 and delegates[0].keywords[0].arg is None

    # One outer owner encloses the child and every product call. Retained nested
    # owner and subprocess deadlines remain separate, smaller bounds.
    outer = calls(driver, 'run_owned')
    assert len(outer) == 1
    assert literal_keyword(outer[0], 'qualification_seconds') == 180
    assert literal_keyword(outer[0], 'cleanup_seconds') == 3
    nested = calls(cli_execute, 'run_owned')
    assert len(nested) == 1 and literal_keyword(nested[0], 'qualification_seconds') == 15
    assert any(n.arg == 'supervisor_env' for n in outer[0].keywords)
    subprocess_calls = [n for n in calls(q_invoke, 'run') if isinstance(n.func, ast.Attribute)]
    assert len(subprocess_calls) == 1 and literal_keyword(subprocess_calls[0], 'timeout') == 20
    links = [n for n in calls(q_tool, 'run') if isinstance(n.func, ast.Attribute)]
    assert len(links) == 1 and literal_keyword(links[0], 'timeout') == 20
    assert len(calls(q_compile, 'invoke')) == 1

    # Two unconditional actual-array snapshots straddle the only machine call.
    loader_main = function(loader, 'main')
    machine = calls(loader_main, 'entry')
    snapshots = calls(loader_main, '_u32_actual_frames')
    assert len(machine) == 1 and len(snapshots) == 2
    assert snapshots[0].lineno < machine[0].lineno < snapshots[1].lineno
    assert [ast.literal_eval(n.args[1]) for n in snapshots] == ['before', 'after']
    assert all(len(n.args) == 6 for n in snapshots)
    capture_fn = function(loader, '_u32_actual_frames')
    assert 'source' in {n.value for n in ast.walk(capture_fn) if isinstance(n, ast.Constant)}
    assert 'workspace' in {n.value for n in ast.walk(capture_fn) if isinstance(n, ast.Constant)}
    assert 32 in {n.value for n in ast.walk(inventory) if isinstance(n, ast.Constant)}
    assert 'invoke_labels' in {n.value for n in ast.walk(inventory) if isinstance(n, ast.Constant)}
    assert len(calls(child, 'frame_inventory')) == 1
    assert len(calls(driver, 'frame_inventory')) == 1

    checked_sources = []
    for path in (names_path, q_path, cfg_path, program_path, vm_path, cli_path, owner_path):
        row = INPUTS[str(path)]
        expected_row = source_manifest[path.relative_to(SOURCE).as_posix()]
        assert all(row[k] == expected_row[k] for k in row)
        checked_sources.append(str(path))
    assert not (AUTHOR / 'evidence/attempt-r1').exists()
    report = {
        'schema': 'hia.u32.entry-layout.static-flow-review.v1',
        'status': 'PASS_STATIC_REACHABLE_FLOW_WITH_DOCUMENTATION_CLARIFICATIONS',
        'product_executions': 0, 'CI_executions': 0, 'original_leaf_changes': 0,
        'reviewed_author_recipe': '4e0f3b2f19dd017744ab3ad93b7ae8dd3904c309',
        'observations': {
            'whole_function_three_change_inverse_bytes_and_AST': True,
            'gate_called_once_inside_journal_and_outer_child': True,
            'original_CFG_selected_rows_exactly_two': list(selected),
            'counts_from_four_combinations_and_original_reachable_bodies': counts,
            'reference_facade_preserves_empty_kwargs_default_fuel': 1_000_000,
            'outer_owner_qualification_seconds': 180, 'outer_owner_cleanup_seconds': 3,
            'original_compiler_and_linker_timeout_seconds': 20,
            'original_ELF_owner_qualification_seconds': 15,
            'native_snapshot_callpoints_straddle_actual_entry': [n.lineno for n in snapshots],
            'native_actual_entry_line': machine[0].lineno,
            'complete_frame_gate_is_in_child_finalization_before_child_exit': True,
            'original_SOURCE_assignment_in_runner': False,
            'flat_and_linked_calls_reach_same_snapshot_sites': True,
        },
        'anchors': [anchor(runner_path, driver), anchor(runner_path, child), anchor(runner_path, admission),
            anchor(projection_path, projection), anchor(support_path, journal_call), anchor(support_path, inventory),
            anchor(q_path, q_compile), anchor(q_path, q_invoke), anchor(cfg_path, cfg_fn),
            anchor(program_path, facade), anchor(vm_path, vm_fn), anchor(cli_path, cli_execute),
            anchor(owner_path, owner_run), anchor(owner_path, owner_supervise), anchor(loader_path, loader_main)],
        'documentation_clarifications': [
            {'id': 'D1', 'path': str(AUTHOR / 'PLAN.md'),
             'finding': 'Execution-boundary prose names the superseded REVIEWED-COMMAND-INTENT.json; use FINAL-COMMAND-INTENT.json and current exact plan SHA. Old command would be rejected before an owner launch.',
             'runner_change_required': False},
            {'id': 'D2', 'path': str(AUTHOR / 'PLAN.md'),
             'finding': 'CHILD is not the only temporary module binding. GateJournal wraps six retained functions and RuntimeBridge wraps owner.run_owned; normal unwinding restores each. No product file is edited.',
             'runner_change_required': False},
            {'id': 'D3', 'path': str(AUTHOR / 'PLAN.md'),
             'finding': 'All VM, compile, link, ELF operations and child finalization are within the 180-second owner deadline. Parent preflight, post-owner guards and final raw inventory are outside it; original run_owned also retains its transport wait overhead.',
             'runner_change_required': False},
        ],
        'limitations': [
            'No actual product/VM/compiler execution was performed; static review cannot prove the future attempt completes within budget.',
            'Actual 32 six-buffer completion is required on success. Trap/kill can leave only genuine before frames; missing after frames are never synthesized.',
            'ELF internal workspace is unobserved. Four ELF records cover actual stdin/stdout/stderr and cleanup only.',
            'The copied RuntimeBridge retains original returned-error behavior. Incomplete nested cleanup cannot pass final admission, but this is not a newly introduced immediate-stop guarantee.',
            'Extra hash/journal/frame I/O is included in existing child limits; this instrumented gate is not a performance claim.',
        ],
        'input_identities': INPUTS,
        'source_paths_read_not_full_tree_scan': checked_sources,
    }
    raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    destination = ROOT / 'FLOW-REVIEW.json'
    with destination.open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'status': report['status'], 'call_counts': counts,
                      'documentation_clarifications': 3, 'product_executions': 0,
                      'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}))


if __name__ == '__main__':
    main()
