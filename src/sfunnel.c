#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"
#include "lookup.h"

static __always_inline
int ip4_funnel(struct __sk_buff* skb, __u8* eth, struct iphdr* ip, void* l4,
							const __u8 funn_proto,
							__u16 src_port,
							__u16 dst_port){
	struct tcphdr *old_tcp, *tcp = NULL;
	struct udphdr *old_udp, *udp = NULL;

	__u8 old_l4_proto = ip->protocol;
	__u32 old_tot_len = bpf_ntohs(ip->tot_len);
	__u32 l3_off  = (__u8*)ip - eth;
	__u32 fhdr_size;
	__u32 l4_csum_off;
	__be32 old_csum, new_csum;

	//L4 header to funnel
	if(old_l4_proto == IPPROTO_UDP){
		old_udp = (struct udphdr*)l4;
		CHECK_SKB_PTR(skb, old_udp+1);
		l4_csum_off  = (__u8*)l4 - eth + offsetof(struct udphdr, check);
		old_csum = old_udp->check;
	}else if(old_l4_proto == IPPROTO_TCP){
		old_tcp = (struct tcphdr*)l4;
		CHECK_SKB_PTR(skb, old_tcp+1);
		l4_csum_off  = (__u8*)l4 - eth + offsetof(struct tcphdr, check);
		old_csum = old_tcp->check;
	}else{
		PRINTK("[%d:0x%p] ERROR: IP funneled proto %d not supported!",
							skb->ifindex, skb,
							old_l4_proto);
		return TC_ACT_SHOT;
	}

	//Funneling header
	if(funn_proto == IPPROTO_UDP){
		fhdr_size = sizeof(struct udphdr);
	}else if(funn_proto == IPPROTO_TCP){
		fhdr_size = sizeof(struct tcphdr);
	}else{
		PRINTK("[%d:0x%p] ERROR: IP funneling proto %d not supported!",
							skb->ifindex, skb,
							funn_proto);
		return TC_ACT_SHOT;
	}

	PRINTK("[%d:0x%p] Size: %d", skb->ifindex, skb, skb->len);
	PRINTK("[%d:0x%p] Funneling proto:%d packet thru proto: %d",
							skb->ifindex, skb,
							old_l4_proto,
							funn_proto);
	//Packet will likely traverse NATs. Set sip/dip for L4 csum
	//(pseudoheader) calculation to a known value 0x0
	__s64 diff = bpf_csum_diff((__be32*)&ip->saddr, 4, NULL, 0, 0);
	diff = bpf_csum_diff((__be32*)&ip->daddr, 4, NULL, 0, diff);

	int rc = bpf_l4_csum_replace(skb, l4_csum_off, 0, diff, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p] ERROR l4_csum_replace: %d", skb->ifindex, skb,
							rc);
		return TC_ACT_SHOT;
	}

	//Reeval ptrs common
	eth = (__u8*)SKB_GET_ETH(skb);
	ip = (struct iphdr*)(eth+sizeof(struct ethhdr));
	CHECK_SKB_PTR(skb, ip+1);

	//Recover new_csum
	if(old_l4_proto == IPPROTO_UDP){
		old_udp = (struct udphdr *)((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, old_udp+1);
		new_csum = old_udp->check;
	}else if(old_l4_proto == IPPROTO_TCP){
		old_tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, old_tcp+1);
		new_csum = old_tcp->check;
	}

	//Change IP PROTO
	union ttl_proto old_ttl = *(union ttl_proto*)&ip->ttl;
	ip->protocol = funn_proto;
	diff = bpf_csum_diff((__be32*)&old_ttl, 4, (__be32*)&ip->ttl, 4, 0);

	//Increase tot_len with new L4 hdr
	struct ver_ihl_tos_totlen old_totlen = *(struct ver_ihl_tos_totlen*)ip;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len)+fhdr_size);
	diff = bpf_csum_diff((__be32*)&old_totlen, 4, (__be32*)ip, 4, diff);

	//Adjust IP checksum and make room for the new L4 hdr
	rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p] ERROR l3_csum_replace: %d", skb->ifindex, skb,
								 rc);
		return TC_ACT_SHOT;
	}
	rc = bpf_skb_adjust_room(skb, fhdr_size, BPF_ADJ_ROOM_NET, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p] ERROR adjust room: %d", skb->ifindex, skb,
								rc);
		return TC_ACT_SHOT;
	}

	//Reeval ptrs common ptrs
	eth = (__u8*)SKB_GET_ETH(skb);
	ip = (struct iphdr*)(eth+sizeof(struct ethhdr));
	CHECK_SKB_PTR(skb, ip+1);

	//Compute L4 funneling cksum as a diff over the old L4
	diff = 0;

	//Diff due to previous L4 HDR checksum 0ed for calc., now payload
	if(old_l4_proto == IPPROTO_UDP){
		old_udp = (struct udphdr *)((__u8*)ip + (ip->ihl * 4)
								+ fhdr_size);
		CHECK_SKB_PTR(skb, old_udp+1);

		diff = csum_fold(old_udp->check);
		__be16 udp_csum[2] = {0, old_udp->check};
		diff = bpf_csum_diff(0, 0, (__be32*)&udp_csum, 4, diff);
	}else if(old_l4_proto == IPPROTO_TCP){
		old_tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4)
								+ fhdr_size);
		CHECK_SKB_PTR(skb, old_tcp+1);

		diff = csum_fold(old_tcp->check);
		__be16 tcp_csum[2] = {old_tcp->check, 0};
		diff = bpf_csum_diff(0, 0, (__be32*)&tcp_csum, 4, diff);
	}

	//Apply diff due to 0ing sip/dip for csum in payload L4
	//TODO: Look into merging this csum_diff with the previous; in principle
	//it should be sufficient to diff 0 (original L4 checksum bytes) =>
	//new_csum, but doesn't seem to work...
	diff = bpf_csum_diff(&old_csum, 4, &new_csum, 4, diff);

	//Pseudoheader diff
	struct pseudo_header old, new;
	old.src = ip->saddr;
	old.dst = ip->daddr;
	old.res = 0x0;
	old.proto = old_l4_proto;
	old.len = bpf_htons(old_tot_len - (ip->ihl * 4));

	new = old;
	new.proto = funn_proto;
	new.len = bpf_htons(old_tot_len + fhdr_size - (ip->ihl * 4));
	diff = bpf_csum_diff((__be32*)&old, sizeof(old), (__be32*)&new,
							sizeof(new), diff);
	//Fill in the funneling hdr and adjust cksum diff
	if(funn_proto == IPPROTO_UDP){
		udp = (struct udphdr *) ((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, udp+1);

		udp->dest = bpf_htons(dst_port);
		udp->source =  bpf_htons(src_port);
		udp->len = bpf_htons(old_tot_len - (ip->ihl * 4) + fhdr_size);
		diff = bpf_csum_diff(0, 0, (__be32*)udp, sizeof(*udp), diff);

		//Set checksum
		udp->check = csum_fold(diff);
	}else if(funn_proto == IPPROTO_TCP){
		tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, tcp+1);

		tcp->dest = bpf_htons(dst_port);
		tcp->source = bpf_htons(src_port);
		tcp->seq = bpf_htonl(0xCAFEBABE);
		tcp->ack_seq = bpf_htonl(0xBABECAFE);
		*((&tcp->ack_seq)+1) = tcp->urg_ptr = tcp->check = 0x0;
		tcp->syn = 0x1;
		tcp->window = bpf_htons(1024);
		tcp->doff = sizeof(*tcp)/4;
		tcp->check = 0x0;

		diff = bpf_csum_diff(0, 0, (__be32*)tcp, sizeof(*tcp), diff);

		//Set checksum
		tcp->check = csum_fold(diff);
	}

	//Packet has been mangled, mark it as such
	bpf_set_hash_invalid(skb);

	PRINTK("[%d:0x%p] Funneled size: %d!", skb->ifindex, skb, skb->len);
	return TC_ACT_OK;
}

static __always_inline
int ip4_unfunnel(struct __sk_buff* skb, struct iphdr* ip, const __u8 proto){

	__u32 fhdr_size;
	__u32 l4_csum_off;

	//L4 funneling header
	if(ip->protocol == IPPROTO_UDP){
		fhdr_size = sizeof(struct udphdr);
	}else if(ip->protocol == IPPROTO_TCP){
		fhdr_size = sizeof(struct tcphdr);
	}else{
		PRINTK("[%d:0x%p] ERROR: IP funneling proto %d not supported!",
							skb->ifindex, skb,
							ip->protocol);
		return TC_ACT_SHOT;
	}

	PRINTK("[%d:0x%p] Size: %d", skb->ifindex, skb, skb->len);
	PRINTK("[%d:0x%p] Unfunneling funneling proto:%d packet, original L4 proto: %d",
							skb->ifindex, skb,
							ip->protocol, proto);

	//Substract funneling HDR and recalc check
	union ttl_proto old_ttl = *(union ttl_proto*)&ip->ttl;
	ip->protocol = proto;
	__s64 diff = bpf_csum_diff((__be32*)&old_ttl, 4, (__be32*)&ip->ttl, 4,
								0);
	if(diff < 0){
		PRINTK("[%d:0x%p] ERROR csum_diff: %d", skb->ifindex, skb,
							diff);
		return TC_ACT_SHOT;
	}

	//Decrease tot_len with funneling hdr size
	struct ver_ihl_tos_totlen old_totlen = *(struct ver_ihl_tos_totlen*)ip;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - fhdr_size);
	diff = bpf_csum_diff((__be32*)&old_totlen, 4, (__be32*)ip, 4, diff);
	if(diff < 0){
		PRINTK("[%d:0x%p] ERROR csum_diff: %d", skb->ifindex, skb,
							diff);
		return TC_ACT_SHOT;
	}

	//Modify checksum and remove funneling hdr
	__u32 l3_off = (__u8*)ip - (__u8*)SKB_GET_ETH(skb);
	int rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p] ERROR l3_csum_replace: %d", skb->ifindex, skb,
							rc);
		return TC_ACT_SHOT;
	}
	rc = bpf_skb_adjust_room(skb, -(__s32)fhdr_size, BPF_ADJ_ROOM_NET, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p] ERROR adjust room: %d", skb->ifindex, skb,
							rc);
		return TC_ACT_SHOT;
	}

	//Reeval ptrs
	__u8* eth = (__u8*)SKB_GET_ETH(skb);
	ip = (struct iphdr*) (eth + sizeof(struct ethhdr));
	CHECK_SKB_PTR(skb, ip+1);
	__u8* l4 = ((__u8*)ip + (ip->ihl * 4));

	//Adjust L4 checksum (NAT)
	if(proto == IPPROTO_UDP){
		CHECK_SKB_PTR(skb, l4+sizeof(struct udphdr));
		l4_csum_off  = (__u8*)l4 - eth + offsetof(struct udphdr, check);
	}else if(proto == IPPROTO_TCP){
		CHECK_SKB_PTR(skb, l4+sizeof(struct tcphdr));
		l4_csum_off  = (__u8*)l4 - eth + offsetof(struct tcphdr, check);
	}else{
		PRINTK("[%d:0x%p]ERROR: IP funneled proto %d not supported!",
							skb->ifindex, skb,
							proto);
		return TC_ACT_SHOT;
	}

	diff = bpf_csum_diff(NULL, 0, (__be32*)&ip->saddr, 4, 0);
	diff = bpf_csum_diff(NULL, 0, (__be32*)&ip->daddr, 4, diff);

	rc = bpf_l4_csum_replace(skb, l4_csum_off, 0, diff, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p] ERROR l4_csum_replace: %d", skb->ifindex, skb,
								rc);
		return TC_ACT_SHOT;
	}

	//Packet has been mangled, mark it as such
	bpf_set_hash_invalid(skb);

	PRINTK("[%d:0x%p] Unfunneled size: %d!", skb->ifindex, skb, skb->len);

	return TC_ACT_OK;
}

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

static inline
int proc_ip4(struct __sk_buff* skb, bool ingress, __u8* eth, struct iphdr* ip){
	sfunnel_ip4_rule_t* rule;
	struct tcphdr* tcp = NULL;
	struct udphdr* udp = NULL;
	void* l4;
	sfunnel_action_funnel_params_t* funn_p;

	CHECK_SKB_PTR(skb, ip+1);
	if(ip->protocol == IPPROTO_UDP){
		l4 = udp = (struct udphdr *) ((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, udp+1);
	}else if(ip->protocol == IPPROTO_TCP){
		l4 = tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, tcp+1);
	}else{
		return TC_ACT_UNSPEC;
	}

	if(skb->mark&PKT_REDIR){
		//INGRESS traffic needs to be processed in seg_pair
		//EGRESS traffic is hairpinned and will be processed by the
		//egress iface
		if(skb->mark&PKT_REDIR_EGRESS &&
		   skb->ifindex == SEG_PAIR_DEV_IFINDEX){
			PRINTK("[%d:0x%p] Skipping redirected pkt coming from EGRESS program",
							skb->ifindex, skb);
			return TC_ACT_UNSPEC;
		}

		if(skb->gso_size > 0){
			//The packet has been redirected before, but is looped
			//back GSOed => drop (bug)
			PRINTK("[%d:0x%p] Redirected pkt is still GSOed",
							skb->ifindex, skb);
			return TC_ACT_SHOT;
		}

		PRINTK("[%d:0x%p] Processing redirected pkt from %s, mark: 0x%x",
			skb->ifindex,
			skb,
			skb->mark&PKT_REDIR_EGRESS? "EGRESS" : "INGRESS",
			skb->mark);

		//Packet has been ungsoed. Recover cached lookup
		__u16 index = skb->mark&0xFFFF;
		if(index >= IP4_RULES_SIZE){
			PRINTK("[%d:0x%p] Invalid rule num %d", skb->ifindex,
								skb, index);
			return TC_ACT_SHOT;
		}
		rule = &ip4_rules[index];
		skb->mark &= ~(0xFFFF | PKT_REDIR);

		PRINTK("[%d:0x%p] Cached matched rule#%u %s", skb->ifindex, skb,
								rule->id);
	}else{
		PRINTK("[%d:0x%p] Looking up IP4/%s, size %d", skb->ifindex, skb,
						(ip->protocol == IPPROTO_UDP)?
							"UDP" : "TCP",
						skb->len);
		rule = ip4_rule_lookup(skb, ip, tcp, udp);
		if(!rule || rule >= ip4_rules+sizeof(ip4_rules)){
			PRINTK("[%d:0x%p] No match", skb->ifindex, skb);
			return TC_ACT_UNSPEC;
		}

		PRINTK("[%d:0x%p] Matched rule#%u", skb->ifindex, skb, rule->id);
		if(SEG_DEV_IFINDEX > 0)
			return redirect_seg_pkt(skb, ingress, rule->id);
	}

	//Direct actions
	if(rule->actions.drop.execute){
		return TC_ACT_SHOT;
	}else if(rule->actions.accept.execute){
		return TC_ACT_OK;
	}

	//Funnel or unfunnel
	if(rule->actions.funnel.execute){
		funn_p = &rule->actions.funnel.p.funnel;
		return ip4_funnel(skb, eth, ip, l4, funn_p->funn_proto,
						funn_p->sport,
						funn_p->dport);
	}else if(rule->actions.unfunnel.execute){
		__be16 proto = rule->actions.unfunnel.p.unfunnel.proto;
		return ip4_unfunnel(skb, ip, proto);
	}

	return TC_ACT_UNSPEC;
}

SEC("classifier")
int tc_sfunnel(struct __sk_buff *skb){
	struct ethhdr *eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if(eth->h_proto == bpf_htons(ETH_P_IP)){
		struct iphdr* ip = (struct iphdr*)((__u8*)eth+sizeof(struct ethhdr));
		return proc_ip4(skb, INGRESS, (__u8*)eth, ip);
	}else if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
		//XXX
		//PRINTK("IPv6 packet with length: %d NOT SUPPORTED!\n", skb->len);
	}

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("Dual BSD/GPL");
