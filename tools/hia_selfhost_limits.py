"""Versioned limits used to author and qualify Selfhost-Core v5.

These values are substituted into the checked-in HIA source at authoring time.
Native successor compilers do not import this module or consult Python state.
"""

MAX_INSTRUCTIONS = 8192
MAX_CORE_NODES = 262144

# An instruction creates at most one relative call; each block creates at most
# two relative edge records. The public wrapper adds one call; the single
# optional shared chain destructor adds exactly two allocator calls. This bound is
# independent of whether a particular maximum-sized module fits its output.
MAX_FUNCTIONS = 128
MAX_BLOCKS = 1536
MAX_RELOCATIONS = 12000
RELOCATION_UPPER_BOUND = 1 + MAX_INSTRUCTIONS + 2 * MAX_BLOCKS + 2

# Conservative canonical JSON byte bounds for the fixed grammar. Identifiers
# are f0..f127, b0..b255 and v0..v2047; literals are at most unsigned 64-bit.
# Each operation has at most 16 arguments, up to three scalar outputs and one attribute;
# buffer.try_new has two results and one argument; chain.try_push/chain.pop
# have three results, at most two arguments and no attributes. These also fit
# the same conservative 512-byte per-operation allowance.
# each block has at most 16 parameters and two 16-argument terminal edges.
CORE_BYTES_UPPER_BOUND = 1024 + MAX_FUNCTIONS * 1024 + MAX_BLOCKS * 2048 + MAX_INSTRUCTIONS * 512

