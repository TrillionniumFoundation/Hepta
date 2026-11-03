/* Deliberately wrong integration strategies, all exercised with live storage.
 * No dangling pointer is dereferenced, compared, or executed after lifetime. */
#include "../c_native_array_storage/storage.h"
#include <assert.h>

static int32_t mutate_and_observe(NativeRow *target, const NativeRow *alias) {
    (*target)[0] = 77;
    return (*alias)[0];
}
static int32_t wrong_copy_bridge(NativeRow *target, const NativeRow *alias) {
    RowValue scratch = row_load((const NativeRow *)target, 0);
    int32_t observed = mutate_and_observe(&scratch.payload, alias);
    row_store(target, 0, scratch);
    return observed;
}
static void wrong_slot_bridge(NativeRow **slot, NativeRow *replacement) {
    NativeRow *scratch = *slot;
    row_rebind(&scratch, replacement);
    /* Correct implementation must mutate the original slot. */
}
static int identity_observer(const NativeRow *original, const NativeRow *received) {
    return original == received;
}
static int wrong_identity_bridge(NativeRow *original) {
    RowValue scratch = row_load((const NativeRow *)original, 0);
    /* Check while scratch is alive. Returning &scratch.payload instead would
     * introduce a lifetime bug; this experiment deliberately never does that. */
    return identity_observer((const NativeRow *)original,
                             (const NativeRow *)row_identity(&scratch.payload));
}
int main(void) {
    NativePlane rows = {{1,2,3},{4,5,6}};
    int32_t direct = mutate_and_observe(rows, (const NativeRow *)rows);
    assert(direct == 77);
    rows[0][0] = 1;
    int32_t copied = wrong_copy_bridge(rows, (const NativeRow *)rows);
    assert(copied == 1 && rows[0][0] == 77 && direct != copied);
    NativeRow *p = rows;
    wrong_slot_bridge(&p, rows + 1);
    assert(p == rows);
    row_rebind(&p, rows + 1);
    assert(p == rows + 1);
    assert(identity_observer((const NativeRow *)rows,
                            (const NativeRow *)row_identity(rows)) == 1);
    assert(wrong_identity_bridge(rows) == 0);
    return 0;
}
