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
process_io(struct context *c, struct link_socket *sock)
{
    const unsigned int status = c->c2.event_set_status;

#ifdef ENABLE_MANAGEMENT
    if (status & (MANAGEMENT_READ | MANAGEMENT_WRITE))
    {
        ASSERT(management);
        management_io(management);
    }
#endif

    /* TCP/UDP port ready to accept write */
    if (status & SOCKET_WRITE)
    {
        process_outgoing_link(c, sock);
    }
    /* TUN device ready to accept write */
    else if (status & TUN_WRITE)
    {
        process_outgoing_tun(c, sock);
    }
    /* Incoming data on TCP/UDP port */
    else if (status & SOCKET_READ)
    {
        read_incoming_link(c, sock);
        if (!IS_SIG(c))
        {
            process_incoming_link(c, sock);
        }
    }
    /* Incoming data on TUN device */
    else if (status & TUN_READ)
    {
        read_incoming_tun(c);
        if (!IS_SIG(c))
        {
            process_incoming_tun(c, sock);
        }
    }
    else if (status & DCO_READ)
    {
        if (!IS_SIG(c))
        {
            dco_read_and_process(&c->c1.tuntap->dco);
        }
    }
}
