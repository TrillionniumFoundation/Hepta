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

static inline unsigned int
p2p_iow_flags(const struct context *c)
{
    unsigned int flags = (IOW_SHAPER | IOW_CHECK_RESIDUAL | IOW_FRAG | IOW_READ | IOW_WAIT_SIGNAL);
    if (c->c2.to_link.len > 0)
    {
        flags |= IOW_TO_LINK;
    }
    if (c->c2.to_tun.len > 0)
    {
        flags |= IOW_TO_TUN;
    }
    return flags;
}
