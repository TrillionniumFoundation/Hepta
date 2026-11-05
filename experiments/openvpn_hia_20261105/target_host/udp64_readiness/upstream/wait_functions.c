/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

void
multi_io_process_flags(struct context *c, struct event_set *es, struct link_socket *sock, const unsigned int flags)
{
    unsigned int socket = 0;
    unsigned int tuntap = 0;
    static uintptr_t tun_shift = TUN_SHIFT;
    static uintptr_t err_shift = ERR_SHIFT;

    /*
     * Calculate the flags based on the provided 'flags' argument.
     */
    if ((c->options.mode != MODE_SERVER) && (flags & IOW_WAIT_SIGNAL))
    {
        wait_signal(es, (void *)err_shift);
    }

    if (flags & IOW_TO_LINK)
    {
        if (flags & IOW_SHAPER)
        {
            /*
             * If sending this packet would put us over our traffic shaping
             * quota, don't send -- instead compute the delay we must wait
             * until it will be OK to send the packet.
             */
            int delay = 0;

            /* set traffic shaping delay in microseconds */
            if (c->options.shaper)
            {
                delay = max_int(delay, shaper_delay(&c->c2.shaper));
            }

            if (delay < 1000)
            {
                socket |= EVENT_WRITE;
            }
            else
            {
                shaper_soonest_event(&c->c2.timeval, delay);
            }
        }
        else
        {
            socket |= EVENT_WRITE;
        }
    }
    else if (!((flags & IOW_FRAG) && TO_LINK_FRAG(c)))
    {
        if (flags & IOW_READ_TUN)
        {
            tuntap |= EVENT_READ;
        }
    }

    /*
     * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
     * from device.  Otherwise, wait for incoming data on TCP/UDP port.
     */
    if (flags & IOW_TO_TUN)
    {
        tuntap |= EVENT_WRITE;
    }
    else
    {
        if (flags & IOW_READ_LINK)
        {
            socket |= EVENT_READ;
        }
    }

    /*
     * Force wait on TUN input, even if also waiting on TCP/UDP output
     */
    if (flags & IOW_READ_TUN_FORCE)
    {
        tuntap |= EVENT_READ;
    }

    /*
     * Configure event wait based on socket, tuntap flags.
     * (for TCP server sockets this happens in
     *  socket_set_listen_persistent()).
     */
    socket_set(sock, es, socket, &sock->ev_arg, NULL);
    tun_set(c->c1.tuntap, es, tuntap, (void *)tun_shift, NULL);
}

/*
 * This is the core I/O wait function, used for all I/O waits.
 *
 * Invoked by P2P instances in tunnel_point_to_point() or by P2MP
 * instances within the per-client context in multi_io.c.
 */
void
io_wait(struct context *c, const unsigned int flags)
{
    struct event_set_return esr[4];

    /* These shifts all depend on EVENT_READ and EVENT_WRITE */
    static uintptr_t socket_shift = SOCKET_SHIFT; /* depends on SOCKET_READ and SOCKET_WRITE */
#ifdef ENABLE_MANAGEMENT
    static uintptr_t management_shift =
        MANAGEMENT_SHIFT; /* depends on MANAGEMENT_READ and MANAGEMENT_WRITE */
#endif

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
    static uintptr_t dco_shift = DCO_SHIFT; /* Event from DCO linux kernel module */
#endif

    /*
     * Decide what kind of events we want to wait for.
     */
    event_reset(c->c2.event_set);

    multi_io_process_flags(c, c->c2.event_set, c->c2.link_sockets[0], flags);

#if defined(TARGET_LINUX) || defined(TARGET_FREEBSD)
    if (c->c1.tuntap)
    {
        dco_event_set(&c->c1.tuntap->dco, c->c2.event_set, (void *)dco_shift);
    }
#endif

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, c->c2.event_set, (void *)management_shift, NULL);
    }
#endif

    /*
     * Possible scenarios:
     *  (1) tcp/udp port has data available to read
     *  (2) tcp/udp port is ready to accept more data to write
     *  (3) tun dev has data available to read
     *  (4) tun dev is ready to accept more data to write
     *  (5) we received a signal (handler sets signal_received)
     *  (6) timeout (tv) expired
     */

    c->c2.event_set_status = ES_ERROR;

    if (!c->sig->signal_received)
    {
        if (!(flags & IOW_CHECK_RESIDUAL) || !sockets_read_residual(c))
        {
            int status;

#ifdef ENABLE_DEBUG
            if (check_debug_level(D_EVENT_WAIT))
            {
                show_wait_status(c);
            }
#endif

            /*
             * Wait for something to happen.
             */
            status = event_wait(c->c2.event_set, &c->c2.timeval, esr, SIZE(esr));

            check_status(status, "event_wait", NULL, NULL);

            if (status > 0)
            {
                int i;
                c->c2.event_set_status = 0;
                for (i = 0; i < status; ++i)
                {
                    const struct event_set_return *e = &esr[i];
                    uintptr_t shift;

                    if (e->arg >= MULTI_N)
                    {
                        struct event_arg *ev_arg = (struct event_arg *)e->arg;
                        if (ev_arg->type != EVENT_ARG_LINK_SOCKET)
                        {
                            c->c2.event_set_status = ES_ERROR;
                            msg(D_LINK_ERRORS, "io_work: non socket event delivered");
                            return;
                        }

                        shift = socket_shift;
                    }
                    else
                    {
                        shift = (uintptr_t)e->arg;
                    }

                    c->c2.event_set_status |= ((e->rwflags & 3) << shift);
                }
            }
            else if (status == 0)
            {
                c->c2.event_set_status = ES_TIMEOUT;
            }
        }
        else
        {
            c->c2.event_set_status = SOCKET_READ;
        }
    }

    /* 'now' should always be a reasonably up-to-date timestamp */
    update_time();

    /* set signal_received if a signal was received */
    if (c->c2.event_set_status & ES_ERROR)
    {
        get_signal(&c->sig->signal_received);
    }

    dmsg(D_EVENT_WAIT, "I/O WAIT status=0x%04x", c->c2.event_set_status);
}

