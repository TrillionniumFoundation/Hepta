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

#define IOW_TO_TUN         (1 << 0)
#define IOW_TO_LINK        (1 << 1)
#define IOW_READ_TUN       (1 << 2)
#define IOW_READ_LINK      (1 << 3)
#define IOW_SHAPER         (1 << 4)
#define IOW_CHECK_RESIDUAL (1 << 5)
#define IOW_FRAG           (1 << 6)
#define IOW_READ_TUN_FORCE (1 << 8)
#define IOW_WAIT_SIGNAL    (1 << 9)

#define IOW_READ (IOW_READ_TUN | IOW_READ_LINK)
