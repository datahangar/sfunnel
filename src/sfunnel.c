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
	__u32 old_tot_len = bpf_ntohs(ip->tot_len) ;
	__u32 l3_off  = (__u8*)ip - eth;
	__u32 fhdr_size;

	//L4 header to funnel
	if(old_l4_proto == IPPROTO_UDP){
		old_udp = (struct udphdr*)l4;
		CHECK_SKB_PTR(skb, old_udp+1);
	}else if(old_l4_proto == IPPROTO_TCP){
		old_tcp = (struct tcphdr*)l4;
		CHECK_SKB_PTR(skb, old_tcp+1);
	}else{
		PRINTK("ERROR: IP funneled proto %d not supported!",
							old_l4_proto);
		return TC_ACT_SHOT;
	}

	//Funneling header
	if(funn_proto == IPPROTO_UDP){
		fhdr_size = sizeof(struct udphdr);
	}else if(funn_proto == IPPROTO_TCP){
		fhdr_size = sizeof(struct tcphdr);
	}else{
		PRINTK("ERROR: IP funneling proto %d not supported!",
							funn_proto);
		return TC_ACT_SHOT;
	}

	PRINTK("[%p] Funneling proto:%d packet thru proto: %d of size: %d", skb,
							old_l4_proto,
							funn_proto,
							skb->len);
	//Change IP PROTO
	union ttl_proto old_ttl = *(union ttl_proto*)&ip->ttl;
	ip->protocol = funn_proto;
	__s64 diff = bpf_csum_diff((__be32*)&old_ttl, 4, (__be32*)&ip->ttl, 4,
							0);

	//Increase tot_len with new L4 hdr
	struct ver_ihl_tos_totlen old_totlen = *(struct ver_ihl_tos_totlen*)ip;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len)+fhdr_size);
	diff = bpf_csum_diff((__be32*)&old_totlen, 4, (__be32*)ip, 4, diff);

	//Adjust IP checksum and make room for the new L4 hdr
	int rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);
	if(rc < 0){
		PRINTK("ERROR l3_csum_replace: %d", rc);
		return TC_ACT_SHOT;
	}
	rc = bpf_skb_adjust_room(skb, fhdr_size, BPF_ADJ_ROOM_NET, 0);
	if(rc < 0){
		PRINTK("ERROR adjust room: %d", rc);
		return TC_ACT_SHOT;
	}

	//Reeval ptrs common ptrs
	eth = (__u8*)SKB_GET_ETH(skb);
	ip = (struct iphdr*)(eth+sizeof(struct ethhdr));
	CHECK_SKB_PTR(skb, ip+1);

	//Compute L4 funneling cksum as a diff over the old L4
	diff = 0;
	if(old_l4_proto == IPPROTO_UDP){
		old_udp = (struct udphdr *)((__u8*)ip + (ip->ihl * 4)
								+ fhdr_size);
		CHECK_SKB_PTR(skb, old_udp+1);

		//Recover previous cksum
		diff = csum_fold(old_udp->check);

		//UDP checksum (0ed in UDP checksum calc, now payload)
		__be16 udp_csum[2] = {0, old_udp->check};
		diff = bpf_csum_diff(0, 0, (__be32*)&udp_csum, 4, diff);
	}else if(old_l4_proto == IPPROTO_TCP){
		old_tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4)
								+ fhdr_size);
		CHECK_SKB_PTR(skb, old_tcp+1);

		//Recover previous cksum
		diff = csum_fold(old_tcp->check);

		//UDP checksum (0ed in UDP checksum calc, now payload)
		__be16 tcp_csum[2] = {old_tcp->check, 0};
		diff = bpf_csum_diff(0, 0, (__be32*)&tcp_csum, 4, diff);
	}

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

	PRINTK("[%p] Funneled size: %d!", skb, skb->len);
	return TC_ACT_OK;
}

static __always_inline
int ip4_unfunnel(struct __sk_buff* skb, struct iphdr* ip, void* l4,
							const __u8 proto){

	__u32 fhdr_size;

	//L4 funneling header
	if(ip->protocol == IPPROTO_UDP){
		fhdr_size = sizeof(struct udphdr);
	}else if(ip->protocol == IPPROTO_TCP){
		fhdr_size = sizeof(struct tcphdr);
	}else{
		PRINTK("ERROR: IP funneling proto %d not supported!",
							ip->protocol);
		return TC_ACT_SHOT;
	}

	PRINTK("[%p] Unfunneling funneling proto:%d packet, original L4 proto: %d of size: %d", skb,
							ip->protocol, proto,
							skb->len);

	//Substract tcp HDR and recalc check
	union ttl_proto old_ttl = *(union ttl_proto*)&ip->ttl;
	ip->protocol = proto;
	__s64 diff = bpf_csum_diff((__be32*)&old_ttl, 4, (__be32*)&ip->ttl, 4,
								0);
	if(diff < 0){
		PRINTK("ERROR csum_diff: %d", diff);
		return TC_ACT_SHOT;
	}

	//Decrease tot_len with TCP hdr
	struct ver_ihl_tos_totlen old_totlen = *(struct ver_ihl_tos_totlen*)ip;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - fhdr_size);
	diff = bpf_csum_diff((__be32*)&old_totlen, 4, (__be32*)ip, 4, diff);
	if(diff < 0){
		PRINTK("ERROR csum_diff: %d", diff);
		return TC_ACT_SHOT;
	}

	//Modify checksum and remove TCP hdr
	__u32 l3_off = (__u8*)ip - (__u8*)SKB_GET_ETH(skb);
	int rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);
	if(rc < 0){
		PRINTK("ERROR l3_csum_replace: %d", rc);
		return TC_ACT_SHOT;
	}
	rc = bpf_skb_adjust_room(skb, -(__s32)fhdr_size, BPF_ADJ_ROOM_NET, 0);
	if(rc < 0){
		PRINTK("ERROR adjust room: %d", rc);
		return TC_ACT_SHOT;
	}

	//Packet has been mangled, mark it as such
	bpf_set_hash_invalid(skb);

	PRINTK("[%p] Unfunneled size: %d!", skb, skb->len);

	return TC_ACT_OK;
}

static inline int proc_ip4(struct __sk_buff* skb, __u8* eth, struct iphdr* ip){
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

	PRINTK("[%p] Looking up IP4/%s, size %d", skb,
						(ip->protocol == IPPROTO_UDP)?
							"UDP" : "TCP",
						skb->len);
	rule = ip4_rule_lookup(skb, ip, tcp, udp);
	if(!rule || rule >= ip4_rules+sizeof(ip4_rules)){
		PRINTK("[%p] No match", skb);
		return TC_ACT_UNSPEC;
	}
	PRINTK("[%p] Matched rule#%u", skb, rule->id);

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
		return ip4_unfunnel(skb, ip, l4, proto);
	}

	//DNAT
	//TODO

	return TC_ACT_UNSPEC;
}

SEC("funnel")
int tc_ingress(struct __sk_buff *skb){
	struct ethhdr *eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if(eth->h_proto == bpf_htons(ETH_P_IP)){
		struct iphdr* ip = (struct iphdr*)((__u8*)eth+sizeof(struct ethhdr));
		return proc_ip4(skb, (__u8*)eth, ip);
	}else if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
		//XXX
		PRINTK("IPv6 packet with length: %d NOT SUPPORTED!\n", skb->len);
	}

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("Dual BSD/GPL");
