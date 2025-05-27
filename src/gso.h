#ifndef SFUNNEL_GSO_H
#define SFUNNEL_GSO_H

#include "common.h"
#include "fib.h"
#include "pmtud.h"

/**
* Funneling and unfunneling GSOed skbs is not possible. Currently, there is no
* way to change `gso_type` from eBPF TC/TCX. Disabling GSO in interfaces
* is not an option either, as TCP traffic is always GSOed in recent kernels
* (and would obviously affect the performance of all traffic). As discussed in
* #11 and #12, several workarounds have been attempted with no or partial
* success.
*
* The work-around implemented here is to force GSOed (GSO/TSO/UFO) skbs that
* need to be funneled/unfunneled (matching traffic) to be segmented by the
* kernel by forcing them to be TXed on an interface with all segmentation
* offloads disabled. This was suggested by Daniel Borkmann (thx!). This has the
* obvious downside of performance, but makes it work without NIC specifics.
*
* In #11, #12 other options which might be more performant are discussed, but
* it's unclear whether this will always work (e.g. avoid pushing/popping headers
* and abusing TCP reserved bits to encode a flow_id seems an elegant solution
* but some NICs an intermediate FWs might clear those bits).
*
* After unGSOing the packet, MTU is checked on_seg_pair. If the size of the
* packet + the overhead of the funneling header exceed the effective MTU to the
* destination, the packet is transformed into a PMTUD ICMP packet, and let
* the Linux kernel route it accordingly. This requires 6.12+ kernels, due to the
* need for the mtu_result field in fib_lookup().
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
*  ***********************************      ***********************************
*  * BPF sfunnel: (No op)            *      * BPF sfunnel:                    *
*  *  - fib_lookup()                 *      *  - recover cached entry (fwmark)*
*  *  - MTU check; ICMP PMTUD        *      *  - exec actions                 *
*  *    generation, if necessary     *      ***********************************
*  *  - _or_ bpf_redirect(egress_if) *                        |
*  ***********************************                        |
*                  |         |                                |
*                  |         --> to kernel                    |
*                  v             (PMTUD)                      |
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

/**
* Redirect all packets, incl. non GSOed (to avoid reorderings) to
* SEG_PAIR_DEV_MAC, to ungso.
*/
static inline
int gso_redirect_seg_pkt(struct __sk_buff* skb, bool ingress,
			 sfunnel_ip4_rule_t* rule){
	//Redirecting all pkts, incl. non GSOed, to avoid reorderings.
	__u8 _seg_mac[ETH_ALEN] = {SEG_PAIR_DEV_MAC};
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
					  _seg_mac, ETH_ALEN, 0);

	skb->mark |= ingress ? PKT_REDIR_INGRESS : PKT_REDIR_EGRESS;
	skb->mark |= rule->id;
	if(rule->actions.funnel.execute){
		bool tcp = rule->actions.funnel.p.funnel.funn_proto == IPPROTO_TCP;
		skb->mark |= tcp? PKT_PUSH_TCP : PKT_PUSH_UDP;
	}

	PRINTK("[%d:0x%p][gso] Redirecting %d->%d mark: 0x%08x", skb->ifindex, skb,
							skb->ifindex,
							SEG_DEV_IFINDEX,
							skb->mark);
	return bpf_redirect(SEG_DEV_IFINDEX, 0);
}

/**
* Reinjects packet to the original egress iface after ungsoed
*/
static inline
int gso_reinject_egress_pkt(struct __sk_buff* skb, struct iphdr* ip){
	int rc;
	struct bpf_fib_lookup fib_params = {0};

	if(skb->mark&PKT_REDIR_EGR_BACK){
		//The packet has been redirected back before, but is looped
		//so drop (bug)
		PRINTK("[%d:0x%p][gso] Egress redirected back packet can't be redirected back again!",
						skb->ifindex, skb);
		return TC_ACT_SHOT;
	}

	//Packet on the egress direction was ungsoed.
	//Now, do a fib lookup to discover the effective MTU towards dst,
	//so that we can craft a PMTUD pkt back if necessary, else reinject
	//back to the egress iface
	rc = fib_ip4_lookup(skb, &fib_params, ip);
	if(rc != TC_ACT_OK)
		return rc;

	//Check MTU and, if necessary, generated PMTUD pkt back
	rc = pmtud_ip4_check(skb, ip, &fib_params);
	if(rc != TC_ACT_OK){
		//We used ACT_UNSPEC to signal ICMP PMTUD frame instead of OK
		//Remap to TC_ACT_OK
		return rc == TC_ACT_UNSPEC? TC_ACT_OK : rc;
	}

	//Now redirect
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    fib_params.dmac, ETH_ALEN, 0);

	skb->mark &= ~PKT_REDIR_EGRESS;
	skb->mark |= PKT_REDIR_EGR_BACK;

	PRINTK("[%d:0x%p][gso] Reinjecting EGRESS redirected packet back to %d, mark: 0x%08x",
							skb->ifindex, skb,
							fib_params.ifindex,
							skb->mark);
	return bpf_redirect(fib_params.ifindex, 0);
}

#endif //SFUNNEL_GSO
