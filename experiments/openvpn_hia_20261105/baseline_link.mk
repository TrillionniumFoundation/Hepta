# Include after the generated OFFICIAL build/src/openvpn/Makefile.
# All official object files and official link flags are reused verbatim.
# Example: make -f Makefile -f /path/baseline_link.mk hia-openvpn \
#   HIA_OBJECT=/path/packet.o HIA_ADAPTER=/path/adapter.o \
#   HIA_OUTPUT=/path/openvpn-hia
# Add HIA_TRACE=/path/trace.o only for diagnostic runs; omit for timing.
HIA_NAMES = packet_id_read packet_id_write packet_id_read_epoch packet_id_write_epoch
HIA_WRAP_FLAGS = $(foreach name,$(HIA_NAMES),-Wl$(comma)--wrap=$(name))
comma := ,
ifneq ($(HIA_TRACE),)
HIA_TRACE_FLAGS = $(foreach name,$(HIA_NAMES),-Wl$(comma)--wrap=ovpn_hia_$(name))
endif
.PHONY: hia-openvpn
hia-openvpn:
	@test -n "$(HIA_OUTPUT)" -a -f "$(HIA_OBJECT)" -a -f "$(HIA_ADAPTER)"
	$(LINK) -o $(HIA_OUTPUT) $(openvpn_OBJECTS) $(openvpn_LDADD) $(LIBS) $(HIA_ADAPTER) $(HIA_OBJECT) $(HIA_TRACE) $(HIA_WRAP_FLAGS) $(HIA_TRACE_FLAGS)
