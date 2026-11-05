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

static inline void
tun_set(struct tuntap *tt, struct event_set *es, unsigned int rwflags, void *arg,
        unsigned int *persistent)
{
    if (!tuntap_defined(tt) || tuntap_is_dco_win(tt))
    {
        return;
    }

    /* if persistent is defined, call event_ctl only if rwflags has changed since last call */
    if (!persistent || *persistent != rwflags)
    {
        event_ctl(es, tun_event_handle(tt), rwflags, arg);
        if (persistent)
        {
            *persistent = rwflags;
        }
    }
#ifdef _WIN32
    if (tt->backend_driver == WINDOWS_DRIVER_TAP_WINDOWS6 && (rwflags & EVENT_READ))
    {
        tun_read_queue(tt, 0);
    }
#endif
    tt->rwflags_debug = rwflags;
}
