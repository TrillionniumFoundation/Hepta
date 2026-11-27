"""Reverse only the reviewed candidate-capture splice, retaining the oracle."""
from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256


REFERENCE_CAPTURE = '''if _evaluation_owns_build_inputs(self, args):
    captured = _capture_evaluation_build_inputs(self, args["candidate_artifact"], args["context"])
    candidate_bytes, candidate_meta, candidate_program = captured.observation
    built = captured.admit(self, args["build_receipt"], args["context"], args["candidate_artifact"])
else:
    candidate_bytes, candidate_meta, candidate_program = self._native(args["candidate_artifact"], args["context"])
    built = self._build_receipt(args["build_receipt"], args["context"], args["candidate_artifact"])
'''
REFERENCE_CAPTURE_SHA256 = 'a3cda16dd75c7a73797d753c601aa1c49d02582dfe980406c4bdc6f124c2a859'


def original_reference(retained):
    """Restore precisely two original statements; all other AST stays visible."""
    if sha256(REFERENCE_CAPTURE.encode()).hexdigest() != REFERENCE_CAPTURE_SHA256:
        raise AssertionError('reviewed evaluation capture splice changed')
    if type(retained) is not ast.FunctionDef or retained.name != '_hia_evaluate_reference':
        raise AssertionError('expected the retained evaluation reference body')
    expected = ast.parse(REFERENCE_CAPTURE).body[0]
    positions = [index for index, node in enumerate(retained.body)
                 if ast.dump(node) == ast.dump(expected)]
    if len(positions) != 1:
        raise AssertionError('evaluation capture source is not the exact reviewed successor')
    restored = deepcopy(retained)
    position, = positions
    restored.body[position:position + 1] = deepcopy(expected.orelse)
    return restored
