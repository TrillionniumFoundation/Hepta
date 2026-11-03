#include "storage.h"
#include <string.h>
RowValue row_load(const NativeRow *rows, size_t index) {
    RowValue value;
    memcpy(&value.payload, &rows[index], sizeof value.payload);
    return value;
}
void row_store(NativeRow *rows, size_t index, RowValue value) {
    memcpy(&rows[index], &value.payload, sizeof value.payload);
}
PlaneValue plane_load(const NativePlane *planes, size_t index) {
    PlaneValue value;
    memcpy(&value.payload, &planes[index], sizeof value.payload);
    return value;
}
void plane_store(NativePlane *planes, size_t index, PlaneValue value) {
    memcpy(&planes[index], &value.payload, sizeof value.payload);
}
NativeRow *row_identity(NativeRow *rows) { return rows; }
NativePlane *plane_identity(NativePlane *planes) { return planes; }
void row_rebind(NativeRow **slot, NativeRow *replacement) { *slot = replacement; }
int32_t alias_observe(NativeRow *target, const NativeRow *alias, RowValue value) {
    row_store(target, 0, value);
    return (*alias)[1];
}
RowValue row_value_copy(RowValue value) { return value; }
