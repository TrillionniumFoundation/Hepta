// Independent reference-only allocator instrumentation; never linked into HIA.
#include <cstddef>
#include <cstdlib>
#include <new>

extern "C" bool cpp_refuse_allocation(std::size_t);
extern "C" void cpp_record_allocation(void*, std::size_t);
extern "C" void cpp_record_release(void*);

void* operator new[](std::size_t size) {
    if (cpp_refuse_allocation(size)) { throw std::bad_alloc(); }
    void* pointer = std::malloc(size);
    if (!pointer) { throw std::bad_alloc(); }
    cpp_record_allocation(pointer, size);
    return pointer;
}

void operator delete[](void* pointer) noexcept {
    cpp_record_release(pointer);
    std::free(pointer);
}

void operator delete[](void* pointer, std::size_t) noexcept { ::operator delete[](pointer); }
