#include "storage.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    NativePlane rows = {{1,2,3},{4,5,6}};
    NativeRow *p = rows;
    /* C11 needs explicit qualification conversion for pointer-to-array types.
     * This does not authorize removing const, or converting T ** to const T **. */
    const NativeRow *read_rows = (const NativeRow *)rows;
    RowValue saved = row_value_copy(row_load(read_rows, 1));
    RowValue replacement = {{7,8,9}};
    assert(row_identity(p) == p);
    assert(alias_observe(p, read_rows, replacement) == 8);
    assert(rows[0][2] == 9);
    row_store(p, 1, replacement);
    assert(saved.payload[0] == 4 && saved.payload[2] == 6);
    replacement.payload[1] = 44;
    assert(rows[1][1] == 8); /* stores copy values rather than retaining them */
    row_rebind(&p, rows + 1);
    assert(p == rows + 1);
    row_store(p, 0, replacement);
    assert(rows[1][1] == 44 && rows[0][1] == 8);
    const NativePlane frozen = {{10,11,12},{13,14,15}};
    assert(row_load(frozen, 1).payload[2] == 15);

    NativePlane cubes[2] = {{{1,2,3},{4,5,6}},{{7,8,9},{10,11,12}}};
    PlaneValue saved_plane = plane_load((const NativePlane *)cubes, 1);
    PlaneValue changed = {{{21,22,23},{24,25,26}}};
    assert(plane_identity(cubes) == cubes);
    plane_store(cubes, 1, changed);
    assert(cubes[1][1][2] == 26 && cubes[0][1][2] == 6);
    assert(saved_plane.payload[1][2] == 12);
    /* Wrapper payload itself contains true nested arrays. No array of wrappers. */
    row_store(changed.payload, 1, replacement);
    assert(changed.payload[1][1] == 44 && cubes[1][1][1] == 25);
    plane_store(cubes, 0, changed);
    assert(cubes[0][1][1] == 44);

    /* Optional allocated storage: effective type originates from NativePlane
     * payload, not the enclosing PlaneValue wrapper. No pointer is retained. */
    NativePlane *allocated = malloc(sizeof *allocated);
    assert(allocated != NULL);
    memcpy(allocated, &changed.payload, sizeof changed.payload);
    PlaneValue from_allocated = plane_load((const NativePlane *)allocated, 0);
    assert(from_allocated.payload[1][1] == 44);
    plane_store(allocated, 0, saved_plane);
    assert((*allocated)[1][2] == 12);
    free(allocated);
    return 0;
}
