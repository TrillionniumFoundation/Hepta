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

unsigned int
socket_set(struct link_socket *s, struct event_set *es, unsigned int rwflags, void *arg,
           unsigned int *persistent)
{
    if (s)
    {
        if ((rwflags & EVENT_READ) && !stream_buf_read_setup(s))
        {
            ASSERT(!persistent);
            rwflags &= ~EVENT_READ;
        }

#ifdef _WIN32
        if (rwflags & EVENT_READ)
        {
            socket_recv_queue(s, 0);
        }
#endif

        /* if persistent is defined, call event_ctl only if rwflags has changed since last call */
        if (!persistent || *persistent != rwflags)
        {
            event_ctl(es, socket_event_handle(s), rwflags, arg);
            if (persistent)
            {
                *persistent = rwflags;
            }
        }

        s->rwflags_debug = rwflags;
    }
    return rwflags;
}
