/* Fixed CPython 3.14 exception-note transport, a hosted C mechanism.
 * HIA selects the frame and sequence. This body receives no JSON document,
 * performs no traversal, and changes no recursion or interpreter limits.
 * API pointers belong to one explicitly pinned current interpreter table.
 */
#include <stdint.h>
struct note_api {
    void (*incref)(void *);
    void (*set_raised)(void *);
    void *(*get_raised)(void);
    void (*format_note)(const char *, ...);
};
_Static_assert(sizeof(void *) == 8, "LP64 pointer ABI required");
_Static_assert(sizeof(int64_t) == 8, "64-bit signed index required");

__attribute__((section(".text.entry"), used, visibility("hidden")))
void *hia_cpython_note(const struct note_api *api, void *error,
                     uint64_t kind, void *container, void *key, int64_t index)
{
    if (api == (void *)0 || error == (void *)0 || kind < 1 || kind > 4 ||
        (kind != 2 && index != 0) || (kind == 2 && index < 0) ||
        (kind == 4 && (container != (void *)0 || key != (void *)0)))
        return (void *)0;
    api->incref(error);
    api->set_raised(error);
    /* Delivery keeps the existing exception chain. A Python raise statement
     * would implicitly replace its context with the currently handled error.
     * PYFUNCTYPE propagates this existing raised exception after returning. */
    if (kind == 4)
        return (void *)0;
    if (kind == 1)
        api->format_note("when serializing %T item %R", container, key);
    else if (kind == 2)
        api->format_note("when serializing %T item %zd", container, index);
    else
        api->format_note("when serializing %T object", container);
    return api->get_raised();
}
