/* SPDX-License-Identifier: GPL-2.0-only
 * Derived from OpenVPN 2.7.8 packet-ID semantics, upstream commit
 * dc1f569087135894ac2703aeabd7a960ee9452d4.
 */
/* Finite experimental ABI, Linux x86-64 LP64, OpenVPN 2.7.8.
 * Borrowed wire/state ranges never escape the synchronous HIA call.
 * Caller must supply live, properly initialized, synchronized C objects.
 * p, b and the nonempty declared data range must be pairwise disjoint.
 * The adapter checks numeric wrap, null/nonempty, capacity <=65536, object
 * alignment, metadata shape and overlap before mutation. Invalid arguments
 * return false/0 without state changes. It cannot authenticate C liveness.
 * The adapter marshals struct fields and validates this boundary. packet_program.py implements all
 * wire encoding, state transitions and OpenVPN partial-failure behavior.
 */
#ifndef OPENVPN_HIA_ADAPTER_H
#define OPENVPN_HIA_ADAPTER_H
#include <stdint.h>
#include <stdbool.h>
#include "packet_id.h"
bool hia_packet_id_read(struct packet_id_net *, struct buffer *, bool);
bool hia_packet_id_write(struct packet_id_send *, struct buffer *, bool, bool);
uint16_t hia_packet_id_read_epoch(struct packet_id_net *, struct buffer *);
bool hia_packet_id_write_epoch(struct packet_id_send *, uint16_t, struct buffer *);
#endif
