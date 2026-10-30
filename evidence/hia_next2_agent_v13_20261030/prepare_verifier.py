"""Prepare a new independent V13 reader; never modify retained V12 records."""
from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
OLD = ROOT / 'p7-v12-evidence-staging-20261030/verify_evidence.py'
OUT = HERE / 'verify_evidence.py'


def main():
    if OUT.exists():
        raise ValueError('refuse to overwrite a reader attempt')
    source = OLD.read_text()
    for old, new in (
        ('p7-v12-20261030', 'p7-v13-20261030'),
        ('p7-v12-integrated-44e34b7a', 'p7-v13-integrated-953fa62'),
        ('44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304', '953fa62dee5aa563551d57b1374ab95b6d548b45'),
        ('835555fb35dbdcf867724ef7a0bb1a6616270217', 'aa0683509a02ca97e4e0c1dd723e4047f50d81b3'),
        ("plan['task_prompt_model_generation_parameters_changed'] is False", "plan['generation_budget_changed'] is False\n            and plan['public_generic_guidance_and_decoder_changed'] is True\n            and plan['task_examples_answers_or_selected_nodes_added'] is False"),
        ("execution['task_or_generation_parameters_modified']", "execution['wrapper_modified_frozen_study_parameters']"),
        ("len(before['files']) == 6685", "len(before['files']) == 6907"),
        ('V12 reused the pinned model', 'V13 reused the pinned model'),
        ("sum(cell['correct'] for cell in cells) == 0", "sum(cell['correct'] for cell in cells) == summary['calibration']['correct']"),
    ):
        if old not in source:
            raise ValueError('reader anchor missing: ' + old)
        source = source.replace(old, new)
    start = source.index('    statuses = ')
    end = source.index('    attempts = ', start)
    source = source[:start] + '''    for cell in cells:
        require(cell == data(fresh + 'calibration/' + cell['id'] + '/CELL.json'),
                'actual cell/result differs')
    flat_attempts = [(cell, index, attempt) for cell in cells
                     for index, attempt in enumerate(cell['attempts'])]
''' + source[end:]
    source = source.replace("        cell, attempt_index = cells[transport_index // 3], transport_index % 3",
                            "        cell, attempt_index, bound_attempt = flat_attempts[transport_index]")
    start = source.index("        item = {'type': 'object'")
    end = source.index("        require(wrapped['edits']", start)
    source = source[:start] + '''        public_types = ['Vec<u8>', 'bool', 'u16', 'u32', 'u64', 'u8', 'usize']
        groups = {}
        for node in nodes:
            if node['fields']:
                require(node['category'] in ('expression', 'type'), 'unknown public node category')
                groups.setdefault(node['category'], []).append(node['id'])
        def object_schema(properties, required):
            return {'type': 'object', 'properties': properties,
                    'required': required, 'additionalProperties': False}
        variants = []
        for category, group_ids in sorted(groups.items()):
            replacement = {'enum': public_types} if category == 'type' else {'type': 'string'}
            changes = object_schema({'text': replacement}, ['text'])
            variants.append(object_schema({'node': {'enum': sorted(group_ids)},
                                           'changes': changes}, ['node', 'changes']))
        items = variants[0] if len(variants) == 1 else {'oneOf': variants}
        schema = object_schema({'edits': {'type': 'array', 'minItems': 1,
                                         'maxItems': 16, 'items': items}}, ['edits'])
        require(payload['json_schema'] == schema and response['decoder_sha256'] == digest(schema),
                'decoder differs from complete public node categories and disclosed type grammar')
        body_bytes = captured[stem + '.request.body.json']
        body = json.loads(body_bytes)
        require(body == payload and body_bytes == json.dumps(body, sort_keys=False,
                separators=(',', ':'), allow_nan=False).encode(), 'actual wire body differs from retained payload')
        wire_item = body['json_schema']['properties']['edits']['items']
        wire_variants = wire_item.get('oneOf', [wire_item])
        require(len(wire_variants) == len(variants) and all(list(item['properties']) == ['node', 'changes']
                for item in wire_variants), 'actual decoder wire order differs')
        grammar = transport_response['generation_settings']['grammar']
        require(type(grammar) is str, 'actual native grammar missing')
        rules = [line for line in grammar.splitlines() if '::=' in line
                 and '-node-kv' in line.split('::=', 1)[1]
                 and '-changes-kv' in line.split('::=', 1)[1]]
        require(len(rules) == len(variants) and all(line.split('::=', 1)[1].index('-node-kv')
                < line.split('::=', 1)[1].index('-changes-kv') for line in rules),
                'actual native grammar does not select target before replacement')
        wire = evaluated['decoder_wire_check']
        require(wire == response['decoder_wire_check'] and wire['rules'] == rules
                and wire['actual_request_body_sha256'] == hashlib.sha256(body_bytes).hexdigest()
                and wire['selection_before_replacement'] is True and wire['model_answer_rewritten'] is False
                and wire['does_not_prove_candidate_semantics'] is True,
                'recorded decoder check differs from independently inspected wire/grammar')
        binding = wire['schema_binding']
        ordered_schema = json.dumps(body['json_schema'], sort_keys=False,
                                    separators=(',', ':'), allow_nan=False).encode()
        require(binding['schema_sha256'] == digest(schema)
                and binding['ordered_schema_sha256'] == hashlib.sha256(ordered_schema).hexdigest()
                and binding['query_sha256'] == query['query_sha256']
                and binding['all_public_editable_nodes_included'] is True
                and binding['task_or_reference_replacement_values_embedded'] is False,
                'actual wire schema/query binding differs')
        answer = json.loads(response['text'])
        require(set(answer) == {'edits'} and type(answer['edits']) is list and 1 <= len(answer['edits']) <= 16,
                'observed answer violates its retained public envelope')
        categories = {node['id']: node['category'] for node in nodes if node['fields']}
        for edit in answer['edits']:
            require(type(edit) is dict and set(edit) == {'node', 'changes'} and edit['node'] in ids
                    and type(edit['changes']) is dict and set(edit['changes']) == {'text'}
                    and type(edit['changes']['text']) is str, 'observed answer violates public field schema')
            require(categories[edit['node']] != 'type' or edit['changes']['text'] in public_types,
                    'observed type edit violates disclosed finite grammar')
''' + source[end:]
    start = source.index('        if transport_index >= 3:')
    end = source.index('        for key in raw_totals:', start)
    source = source[:start] + source[end:]
    start = source.index('    require(raw_totals == {')
    end = source.index("    peer = data('review/P7_PEER_REVIEW.json')", start)
    source = source[:start] + '''    require(raw_totals == summary['calibration']['usage'], 'summary usage differs from actual SSE')
''' + source[end:]
    source = source.replace("peer['calibration']['correct'] == 0 and peer['calibration']['requests'] == 9",
                            "peer['calibration']['correct'] == sum(cell['correct'] for cell in cells)\n            and peer['calibration']['requests'] == calibration['requests']")
    start = source.index("            'actual_failure_classes':")
    end = source.index("            'main_cells':", start)
    source = source[:start] + "            'actual_attempt_statuses': dict(Counter(a['status'] for a in attempts)),\n" + source[end:]
    ast.parse(source)
    OUT.write_text(source)
    record = {'schema': 'hepta.p7.v13-reader-preparation.v1',
              'parent_reader': {'path': str(OLD), 'sha256': hashlib.sha256(OLD.read_bytes()).hexdigest()},
              'reader': {'path': str(OUT), 'sha256': hashlib.sha256(OUT.read_bytes()).hexdigest()},
              'archived_code_executed': False, 'actual_readback_executed': False,
              'preserved_v12_reader_modified': False}
    (HERE / 'READER_PREPARATION.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
