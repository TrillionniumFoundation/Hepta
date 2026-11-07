
#include <stdint.h>
#include <stddef.h>
struct hia_packet { uint8_t kind; uint32_t count; uint64_t digest; };
size_t hia_packet_size(void) { return sizeof(struct hia_packet); }
size_t hia_packet_align(void) { return _Alignof(struct hia_packet); }
size_t hia_packet_kind_offset(void) { return offsetof(struct hia_packet,kind); }
size_t hia_packet_count_offset(void) { return offsetof(struct hia_packet,count); }
size_t hia_packet_digest_offset(void) { return offsetof(struct hia_packet,digest); }
