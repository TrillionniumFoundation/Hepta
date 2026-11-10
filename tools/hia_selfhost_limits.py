"""Versioned limits used to author and qualify Selfhost-Core v5.

These values are substituted into the checked-in HIA source at authoring time.
Native successor compilers do not import this module or consult Python state.
"""

MAX_INSTRUCTIONS = 8192
MAX_CORE_NODES = 262144

# An instruction creates at most one relative call; each block creates at most
# two relative edge records. Each public scalar wrapper adds one call; the single
# optional shared chain destructor adds exactly two allocator calls. A nonfirst
# entry adds at most one prologue jump per function. This bound is
# independent of whether a particular maximum-sized module fits its output.
MAX_FUNCTIONS = 128
MAX_BLOCKS = 1536
MAX_RELOCATIONS = 12000
RELOCATION_UPPER_BOUND = MAX_FUNCTIONS + MAX_INSTRUCTIONS + 2 * MAX_BLOCKS + MAX_FUNCTIONS + 2

# Conservative canonical JSON byte bounds for the fixed grammar. Reserve the
# entire 1MiB assembly input for identifier/literal payload bytes, rather than
# assuming historical short numeric names. ASCII names need no JSON escaping;
# each named occurrence and literal is already present in the assembly input.
# Remaining JSON syntax/field names/types fit 1024 bytes per function,1024 per
# block (at most16params/two16argument edges) and512 per operation (at most
#16arguments/three outputs/one attribute). Integer magnitudes are at most64bits.
# Each operation has at most 16 arguments, up to three scalar outputs and one attribute;
# buffer.try_new has two results and one argument; chain.try_push/chain.pop
# have three results, at most two arguments and no attributes. These also fit
# the same conservative 512-byte per-operation allowance.
# each block has at most 16 parameters and two 16-argument terminal edges.
CORE_BYTES_UPPER_BOUND = (1 << 20) + 1024 + MAX_FUNCTIONS * 1024 + MAX_BLOCKS * 1024 + MAX_INSTRUCTIONS * 512
