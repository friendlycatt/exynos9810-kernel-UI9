/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility shim for the 5.15 BPF backport.
 *
 * Upstream v5.9 moved the ipv6 stub definitions into net/ipv6_stubs.h.
 * This tree still keeps them in net/addrconf.h, so simply forward there.
 */
#ifndef _IPV6_STUBS_H
#define _IPV6_STUBS_H

#include <net/addrconf.h>

#endif /* _IPV6_STUBS_H */
