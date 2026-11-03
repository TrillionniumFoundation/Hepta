#ifndef EXPERIMENT_C_NATIVE_ARRAY_STORAGE_H
#define EXPERIMENT_C_NATIVE_ARRAY_STORAGE_H
#include <stddef.h>
#include <stdint.h>
/* Isolated representation experiment. Not the Hepta compiler's public ABI. */
typedef int32_t NativeRow[3];
typedef NativeRow NativePlane[2];
typedef struct { NativeRow payload; } RowValue;
typedef struct { NativePlane payload; } PlaneValue;
/* Caller establishes initialized live storage, valid extent/index and alignment.
 * Returned pointers borrow caller storage; these functions never extend lifetime.
 * No restrict: aliases are intentionally permitted in this experiment. */
RowValue row_load(const NativeRow *rows, size_t index);
void row_store(NativeRow *rows, size_t index, RowValue value);
PlaneValue plane_load(const NativePlane *planes, size_t index);
void plane_store(NativePlane *planes, size_t index, PlaneValue value);
NativeRow *row_identity(NativeRow *rows);
NativePlane *plane_identity(NativePlane *planes);
void row_rebind(NativeRow **slot, NativeRow *replacement);
int32_t alias_observe(NativeRow *target, const NativeRow *alias, RowValue value);
/* Deliberate private-to-private value forwarding, not a foreign wrapper ABI. */
RowValue row_value_copy(RowValue value);
#endif
