"""Author-time message inventory; runtime formatting is emitted as HIA."""

NAMES = '''PROGRAM_KEYS PROGRAM_EXPORT_KEYS SCHEMA MODULE_IDENT FUNCTION_INVENTORY
DUPLICATE_FUNCTION DUPLICATE_EXPORT EXPORT_MISSING EXPORT_RESOURCE FUNCTION_KEYS
FUNCTION_LOAN_KEYS FUNCTION_IDENT RUNTIME_NAME RETURNS_LIST TYPE LOAN_VERSION
ORIGIN_ARITY ORIGIN_NONLOAN ORIGIN_PERMISSION EFFECTS ENTRY_IDENT BLOCK_INVENTORY
BLOCK_KEYS BLOCK_IDENT DUPLICATE_BLOCK OPERATIONS_LIST INSTRUCTION_KEYS OPCODE_TEXT
ATTRIBUTES_OBJECT ENTRY_SIGNATURE UNREACHABLE CHAIN_VERSION PARAMETER_LIST
PARAMETER_KEYS WHERE_IDENT DUPLICATE_PARAMETER DUPLICATE_SSA VALUE_LIST EDGE_KEYS
EDGE_TARGET_IDENT MISSING_TERMINATOR RETURN_KEYS JUMP_KEYS BRANCH_KEYS
BRANCH_CONDITION_IDENT TRAP_KEYS TRAP_CODE UNKNOWN_TERMINATOR MISSING_BLOCK
ENTRY_INCOMING EDGE_ARITY UNDEFINED_VALUE CONSUMED_RESOURCE OWNER_REQUIRED
OWNER_BORROWED VIEW_REQUIRED PARENT_SUSPENDED BORROW_PERMISSION BORROW_GRAPH
BORROW_CONFLICT OPCODE_ATTRIBUTES OPERAND_COUNT OPERAND_TYPES OUTPUT_COUNT
OUTPUT_TYPES CONSTANT CAST END_CALLER_LOAN END_CHILD_LOANS DISTINCT_OWNER
CALLEE_IDENT UNKNOWN_CALLEE CALL_ARITY CALL_ARGUMENT_TYPE CALL_DUPLICATE_OWNER
CALL_ALIAS_VIEWS CALL_RETURN_TYPES BRANCH_BOOL MISSING_EFFECTS RETURN_TYPES
DUPLICATE_RETURN_LOAN RETURN_ORIGIN DUPLICATE_RETURN_OWNER RETURN_LIVE
BLOCKS_CHECKED EDGE_TYPES EDGE_DUPLICATE EDGE_DROPS EDGE_PARENT EDGE_PREDECESSOR
OPCODE_VERSION UNKNOWN_OPCODE'''.split()
IDS = {name: i + 1 for i, name in enumerate(NAMES)}

MESSAGES = {
    'PROGRAM_KEYS': 'program: expected exactly functions, module, schema',
    'PROGRAM_EXPORT_KEYS': 'program: expected exactly exports, functions, module, schema',
    'SCHEMA': 'unsupported program schema',
    'MODULE_IDENT': 'module: invalid/reserved ASCII identifier',
    'FUNCTION_INVENTORY': 'invalid function inventory',
    'DUPLICATE_FUNCTION': 'duplicate function',
    'DUPLICATE_EXPORT': 'duplicate explicit scalar export',
    'EXPORT_MISSING': 'explicit export names a missing function',
    'EXPORT_RESOURCE': 'public exports cannot carry resource descriptors',
    'FUNCTION_KEYS': 'function: expected exactly blocks, effects, entry, name, params, returns',
    'FUNCTION_LOAN_KEYS': 'function: expected exactly blocks, effects, entry, name, params, return_loans, returns',
    'FUNCTION_IDENT': 'function: invalid/reserved ASCII identifier',
    'RUNTIME_NAME': 'function collides with native runtime symbol',
    'RETURNS_LIST': 'returns must be a list',
    'TYPE': 'type is outside the closed primitive profile',
    'LOAN_VERSION': 'call loans require the v8 parameter-return contract',
    'ORIGIN_ARITY': 'return_loans must match the return arity',
    'ORIGIN_NONLOAN': 'nonloan result requires a null return_loans entry',
    'ORIGIN_PERMISSION': 'borrowed result must name an input loan with sufficient permission',
    'EFFECTS': 'unknown/duplicate function effect',
    'ENTRY_IDENT': 'entry: invalid/reserved ASCII identifier',
    'BLOCK_INVENTORY': 'invalid block inventory',
    'BLOCK_KEYS': 'block: expected exactly id, ops, params, term',
    'BLOCK_IDENT': 'block id: invalid/reserved ASCII identifier',
    'DUPLICATE_BLOCK': 'duplicate block',
    'OPERATIONS_LIST': 'block operations must be a list',
    'INSTRUCTION_KEYS': 'instruction: expected exactly args, attrs, op, out',
    'OPCODE_TEXT': 'opcode must be text',
    'ATTRIBUTES_OBJECT': 'instruction attributes must be an object',
    'ENTRY_SIGNATURE': 'entry parameters must equal the function signature',
    'UNREACHABLE': 'unreachable blocks are not admitted',
    'CHAIN_VERSION': 'recursive chain types require HIA program v7',
    'EDGE_KEYS': 'CFG edge: expected exactly args, target',
    'EDGE_TARGET_IDENT': 'edge target: invalid/reserved ASCII identifier',
    'MISSING_TERMINATOR': 'missing terminator',
    'RETURN_KEYS': 'ret: expected exactly op, values',
    'JUMP_KEYS': 'jump: expected exactly args, op, target',
    'BRANCH_KEYS': 'branch: expected exactly cond, else, op, then',
    'BRANCH_CONDITION_IDENT': 'branch condition: invalid/reserved ASCII identifier',
    'TRAP_KEYS': 'trap: expected exactly code, op',
    'TRAP_CODE': 'unknown trap code',
    'UNKNOWN_TERMINATOR': 'unknown terminator',
    'MISSING_BLOCK': 'jump to missing block',
    'ENTRY_INCOMING': 'entry cannot have incoming CFG edges; use a loop header',
    'EDGE_ARITY': 'edge arity differs from block parameters',
    'OWNER_REQUIRED': 'operation requires an owner',
    'OWNER_BORROWED': 'owner moved/dropped/returned while borrowed',
    'VIEW_REQUIRED': 'memory access requires appropriate view',
    'PARENT_SUSPENDED': 'parent view is suspended until child loans end',
    'BORROW_PERMISSION': 'invalid borrow permission',
    'BORROW_GRAPH': 'invalid loan parent graph',
    'BORROW_CONFLICT': 'conflicting live borrow',
    'CONSTANT': 'constant must be an exactly typed scalar',
    'CAST': 'unsupported integer cast',
    'END_CALLER_LOAN': "callee cannot end its caller's loan",
    'END_CHILD_LOANS': 'end child loans before their parent',
    'CALLEE_IDENT': 'callee: invalid/reserved ASCII identifier',
    'UNKNOWN_CALLEE': 'unknown callee',
    'CALL_ARITY': 'call arity mismatch',
    'CALL_ARGUMENT_TYPE': 'call argument type mismatch',
    'CALL_DUPLICATE_OWNER': 'owner supplied twice to call',
    'CALL_ALIAS_VIEWS': 'aliased exclusive call arguments',
    'BRANCH_BOOL': 'branch condition is not bool',
    'RETURN_TYPES': 'return type/arity mismatch',
    'DUPLICATE_RETURN_LOAN': 'same loan capability returned twice',
    'RETURN_ORIGIN': 'returned loan must be its declared parameter or a direct child',
    'DUPLICATE_RETURN_OWNER': 'same owner returned twice',
    'RETURN_LIVE': 'return leaves live owner/local loan',
    'BLOCKS_CHECKED': 'not all blocks were checked',
    'EDGE_TYPES': 'edge values do not match block parameter types',
    'EDGE_DUPLICATE': 'linear capability duplicated across an edge',
    'EDGE_DROPS': 'edge drops a live owner or local loan',
    'EDGE_PARENT': 'loan must travel with its owner/parent capability',
    'EDGE_PREDECESSOR': 'predecessors disagree on loan origins/permissions',
}
WHERE = ('function parameters', 'block parameters', 'instruction outputs',
         'explicit scalar exports', 'instruction arguments', 'edge arguments', 'return values')
MAGIC = int.from_bytes(b'HIACDG01', 'little')
TEXT_MAGIC = int.from_bytes(b'HIACDT01', 'little')
CONTEXT_BYTES = 512
