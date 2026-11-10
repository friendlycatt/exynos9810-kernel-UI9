/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal kernel-TLS shim for the 5.15 BPF backport.
 *
 * This 4.9 vendor tree has no kTLS implementation (CONFIG_TLS does not
 * exist here), but the backported net/core/filter.c references
 * tls_sw_has_ctx_rx() from its sk_skb_adjust_room() helper.  With no kTLS
 * present the answer is always "no".
 */
#ifndef _NET_TLS_H
#define _NET_TLS_H

#include <linux/types.h>

struct sock;

static inline bool tls_sw_has_ctx_rx(const struct sock *sk)
{
	return false;
}

static inline bool tls_sw_has_ctx_tx(const struct sock *sk)
{
	return false;
}

#endif /* _NET_TLS_H */
