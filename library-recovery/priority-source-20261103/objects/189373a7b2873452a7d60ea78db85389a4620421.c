// True C translation unit linked against C++ implementation through the C ABI.
#include <stdint.h>
#include <limits.h>
extern uint64_t hia_cpp_new(int32_t);
extern int hia_cpp_step(uint64_t, int32_t, int32_t *);
extern int hia_cpp_delete(uint64_t);
extern uint64_t hia_cpp_constructed(void);
extern uint64_t hia_cpp_destroyed(void);
int main(void) {
    uint64_t handle = hia_cpp_new(40);
    if(!handle) return 1;
    int32_t value = 0;
    if(hia_cpp_step(handle,2,&value) != 0 || value != 42) return 2;
    if(hia_cpp_step(handle,INT32_MIN,&value) != 3 || value != 42) return 3;
    if(hia_cpp_delete(handle) != 0) return 4;
    if(hia_cpp_delete(handle) != 1) return 5;
    if(hia_cpp_step(handle,1,&value) != 1) return 6;
    uint64_t another = hia_cpp_new(7);
    if(!another || another == handle) return 7;
    if(hia_cpp_delete(another) != 0) return 8;
    if(hia_cpp_constructed() != 2 || hia_cpp_destroyed() != 2) return 9;
    return 0;
}
