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

static void
do_event_set_init(struct context *c, bool need_us_timeout)
{
    unsigned int flags = 0;

    c->c2.event_set_max = BASE_N_EVENTS;

    flags |= EVENT_METHOD_FAST;

    if (need_us_timeout)
    {
        flags |= EVENT_METHOD_US_TIMEOUT;
    }

    c->c2.event_set = event_set_init(&c->c2.event_set_max, flags);
    c->c2.event_set_owned = true;
}
