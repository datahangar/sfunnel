#ifndef SFUNNEL_GSO_H
#define SFUNNEL_GSO_H

#include "common.h"

/**
* Funneling and unfunneling GSOed skbs is not possible. Currently, there is no
* way to change `gso_type` from eBPF TC/TCX. Disabling GSO in interfaces
* is not an option either, as TCP traffic is always GSOed in recent kernels
* (and would obviously affect the performance of all traffic). As discussed in
* #11 and #12, several workarounds have been attempted with no or partial
* success.
*
* The work-around implemented here is to force GSOed (GSO/TSO/UFO) skbs that
* need to be funneled/unfunneled (matchng traffic) to be segmented by the kernel
* by forcing them to be TXed on an interface with all segmentation offloads
* disabled. This was suggested by Daniel Borkmann (thx!). This has the obvious
* downside of performance, but makes it work without NIC specifics.
*
* In #11, #12 other options which might be more performant are discussed, but
* it's unclear whether this will always work (e.g. avoid pushing/popping headers
* and abusing TCP reserved bits to encode a flow_id seems an elegant solution
* but some NICs an intermediate FWs might clear those bits).
*
* Egress pkt flow:                          Ingress pkt flow:
*
*                  |                                           |
*                  v                                           v
*             -----------                                 ------------
*            | Egress if |                               | Ingress if |
*             ------------                                ------------
*                  |                                           |
*  *********************************        ***********************************
*  * BPF sfunnel:                  *        * BPF sfunnel:                    *
*  *  - lookup + cache entry (mark)*        *  - lookup + cache entry (fwmark)*
*  *  - set dmac to _seg_pair      *        *  - set dmac to _seg_pair        *
*  *  - bpf_redirect(_seg))        *        *  - bpf_redirect(_seg))          *
*  *********************************        ***********************************
*                  |                                           |
*                  v                                           v
*               ------                                      ------
*              | _seg |                                    | _seg |
*               ------                                      ------
*                  x                                           x
*                  x       //Segmentation happens here//       x
*                  x                                           x
*             -----------                                 -----------
*            | _seg_pair |                               | _seg_pair |
*             -----------                                 -----------
*                  |                                           |
*  *********************************        ***********************************
*  * BPF sfunnel: (No op)          *        * BPF sfunnel:                    *
*  *********************************        *  - recover cached entry (fwmark)*
*                  |                        *  - exec actions                 *
*                  v                        ***********************************
*        ++++++++++++++++++++                                 |
*        + Kernel IP lookup +                                 v
*        ++++++++++++++++++++                       ++++++++++++++++++++
*                  |                                +    Kernel RX     +
*                  v                                ++++++++++++++++++++
*             -----------
*            | Egress if |
*             ------------
*                  |
*  *********************************
*  * BPF sfunnel:                  *
*  *  - recover cached entry (mark)*
*  *  - exec actions               *
*  *********************************
*                  |
*                  v
*                 out
*/

static inline
int redirect_seg_pkt(struct __sk_buff* skb, bool ingress, __u16 rule_id){
	//Redirecting all pkts, incl. non GSOed, to avoid reorderings.
	__u8 _seg_mac[ETH_ALEN] = {SEG_PAIR_DEV_MAC};
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
					  _seg_mac, ETH_ALEN, 0);

	skb->mark = ingress ? PKT_REDIR_INGRESS : PKT_REDIR_EGRESS;
	skb->mark |= rule_id;

	PRINTK("[%d:0x%p] Redirecting %d->%d mark: 0x%x", skb->ifindex, skb,
							skb->ifindex,
							SEG_DEV_IFINDEX,
							skb->mark);
	return bpf_redirect(SEG_DEV_IFINDEX, 0);
}

#endif //SFUNNEL_GSO
