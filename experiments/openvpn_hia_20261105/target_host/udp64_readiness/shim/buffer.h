/* Allocation adapters for the exact upstream event backend. */
#define ALLOC_OBJ_CLEAR(p, type) do { (p) = calloc(1, sizeof(type)); assert(p); } while (0)
#define ALLOC_ARRAY_CLEAR(p, type, n) do { (p) = calloc((n), sizeof(type)); assert(p); } while (0)
