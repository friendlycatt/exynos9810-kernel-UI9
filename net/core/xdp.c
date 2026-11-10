/* net/core/xdp.c
 *
 * Copyright (c) 2017 Jesper Dangaard Brouer, Red Hat Inc.
 * Released under terms in GPL version 2.  See COPYING.
 */
#include <linux/types.h>
#include <linux/mm.h>

#include <net/xdp.h>

#define REG_STATE_NEW		0x0
#define REG_STATE_REGISTERED	0x1
#define REG_STATE_UNREGISTERED	0x2
#define REG_STATE_UNUSED	0x3

void xdp_rxq_info_unreg(struct xdp_rxq_info *xdp_rxq)
{
	/* Simplify driver cleanup code paths, allow unreg "unused" */
	if (xdp_rxq->reg_state == REG_STATE_UNUSED)
		return;

	WARN(!(xdp_rxq->reg_state == REG_STATE_REGISTERED), "Driver BUG");

	xdp_rxq->reg_state = REG_STATE_UNREGISTERED;
	xdp_rxq->dev = NULL;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_unreg);

static void xdp_rxq_info_init(struct xdp_rxq_info *xdp_rxq)
{
	memset(xdp_rxq, 0, sizeof(*xdp_rxq));
}

/* Returns 0 on success, negative on failure */
int xdp_rxq_info_reg(struct xdp_rxq_info *xdp_rxq,
		     struct net_device *dev, u32 queue_index)
{
	if (xdp_rxq->reg_state == REG_STATE_UNUSED) {
		WARN(1, "Driver promised not to register this");
		return -EINVAL;
	}

	if (xdp_rxq->reg_state == REG_STATE_REGISTERED) {
		WARN(1, "Missing unregister, handled but fix driver");
		xdp_rxq_info_unreg(xdp_rxq);
	}

	if (!dev) {
		WARN(1, "Missing net_device from driver");
		return -ENODEV;
	}

	/* State either UNREGISTERED or NEW */
	xdp_rxq_info_init(xdp_rxq);
	xdp_rxq->dev = dev;
	xdp_rxq->queue_index = queue_index;

	xdp_rxq->reg_state = REG_STATE_REGISTERED;
	return 0;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_reg);

void xdp_rxq_info_unused(struct xdp_rxq_info *xdp_rxq)
{
	xdp_rxq->reg_state = REG_STATE_UNUSED;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_unused);

bool xdp_rxq_info_is_reg(struct xdp_rxq_info *xdp_rxq)
{
	return (xdp_rxq->reg_state == REG_STATE_REGISTERED);
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_is_reg);

/*
 * Backported from v5.15: frame bookkeeping for devmap/cpumap.
 *
 * v5.15 stores a struct xdp_frame inside the packet headroom and passes it
 * around between CPUs.  This tree has no page_pool and no zero-copy support,
 * so everything here is the MEM_TYPE_PAGE_SHARED (one page per packet) model:
 * the page that backs the frame is the one the driver handed to XDP, and
 * returning the frame simply drops that page reference.
 */
struct xdp_frame *xdp_convert_buff_to_frame(struct xdp_buff *xdp)
{
	struct xdp_frame *xdp_frame;

	/* The frame is built in the headroom, right at data_hard_start. */
	xdp_frame = xdp->data_hard_start;
	xdp_frame->data = xdp->data;
	xdp_frame->len = xdp->data_end - xdp->data;
	xdp_frame->headroom = xdp->data - xdp->data_hard_start -
			      sizeof(struct xdp_frame);
	xdp_frame->metasize = xdp->data - xdp->data_meta;
	xdp_frame->frame_sz = xdp->frame_sz;
	xdp_frame->dev_rx = NULL;
	xdp_frame->mem.type = MEM_TYPE_PAGE_SHARED;
	xdp_frame->mem.id = 0;

	return xdp_frame;
}
EXPORT_SYMBOL_GPL(xdp_convert_buff_to_frame);

void xdp_return_frame(struct xdp_frame *xdpf)
{
	struct page *page = virt_to_head_page(xdpf->data);

	put_page(page);
}
EXPORT_SYMBOL_GPL(xdp_return_frame);

/* The _rx_napi variant exists upstream to pick a different recycle strategy
 * when page_pool is in use.  Without page_pool both paths are identical.
 */
void xdp_return_frame_rx_napi(struct xdp_frame *xdpf)
{
	xdp_return_frame(xdpf);
}
EXPORT_SYMBOL_GPL(xdp_return_frame_rx_napi);

void xdp_return_buff(struct xdp_buff *xdp)
{
	struct page *page = virt_to_head_page(xdp->data);

	put_page(page);
}
EXPORT_SYMBOL_GPL(xdp_return_buff);

void xdp_warn(const char *msg, const char *func, const int line)
{
	WARN(1, "XDP_WARN: %s(line:%d): %s\n", func, line, msg);
}
EXPORT_SYMBOL_GPL(xdp_warn);
