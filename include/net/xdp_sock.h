/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal AF_XDP (XDP socket) shim for the 5.15 BPF backport.
 *
 * This 4.9 vendor tree has no AF_XDP implementation at all, but the
 * backported net/core/filter.c still references the XSKMAP plumbing.
 * The map type is never registered (CONFIG_XDP_SOCKETS does not exist
 * here), so these paths are unreachable; the stubs exist purely to keep
 * the code building and to keep the verifier's context-access helpers
 * type-correct.
 */
#ifndef _LINUX_XDP_SOCK_H
#define _LINUX_XDP_SOCK_H

#include <linux/types.h>
#include <net/xdp.h>

struct bpf_map;

struct xdp_sock {
	/* queue index the socket is bound to */
	u32 queue_id;
};

static inline int __xsk_map_redirect(void *fwd, struct xdp_buff *xdp)
{
	return -EOPNOTSUPP;
}

static inline void __xsk_map_flush(void)
{
}

static inline void *__xsk_map_lookup_elem(struct bpf_map *map, u32 index)
{
	return NULL;
}

static inline int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	return -EOPNOTSUPP;
}

#endif /* _LINUX_XDP_SOCK_H */
