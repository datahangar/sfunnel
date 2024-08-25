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

static __always_inline int ip4_unfunnel(struct __sk_buff* skb,
							struct iphdr* ip,
							const __u8 fun_l4_proto,
							void* l4,
							const __u8 proto){

	__u32 fhdr_size;

	//L4 funneling header
	if(fun_l4_proto == IPPROTO_UDP){
		fhdr_size = sizeof(struct udphdr);
	}else if(fun_l4_proto == IPPROTO_TCP){
		fhdr_size = sizeof(struct tcphdr);
	}else{
		PRINTK("ERROR: IP funneling proto %d not supported!",
							fun_l4_proto);
		return TC_ACT_SHOT;
	}

	PRINTK("[%p] Unfunneling funneling proto:%d packet, original L4 proto: %d of size: %d", skb,
							fun_l4_proto, proto,
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

static inline int proc_ip4(struct __sk_buff* skb, struct iphdr* ip){
	struct tcphdr* tcp;

	CHECK_SKB_PTR(skb, ip+1);

	//XXX: to be removed by dynamic config

	if(ip->protocol == IPPROTO_TCP){
		tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
		CHECK_SKB_PTR(skb, tcp+1);

		if(tcp->dest != bpf_htons(TCP_FUNNEL_DST_PORT))
			return TC_ACT_UNSPEC;

		//Unfunnel {IPFIX, Netflow and sFlow} via TCP (BGP)
		if(tcp->source == bpf_htons(TCP_FUNNEL_SRC_PORT))
			return ip4_unfunnel(skb, ip, IPPROTO_TCP, tcp,
								IPPROTO_UDP);
#ifdef TEST_TCP_FUNNELING
		if(tcp->source == bpf_htons(TEST_TCPINTCP_TCP_FUNNEL_SRC_PORT))
			return ip4_unfunnel(skb, ip, IPPROTO_TCP, tcp,
								IPPROTO_TCP);
#endif //TEST_TCP_FUNNELING
	}

	//XXX: end to be removed

	return TC_ACT_UNSPEC;
}


SEC("funnel")
int tc_ingress(struct __sk_buff *skb){
	struct ethhdr *eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if(eth->h_proto == bpf_htons(ETH_P_IP)){
		struct iphdr* ip = (struct iphdr*)((__u8*)eth+sizeof(struct ethhdr));
		return proc_ip4(skb, ip);
	}else if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
		//XXX
		PRINTK("IPv6 packet with length: %d NOT SUPPORTED!\n", skb->len);
	}

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("Dual BSD/GPL");
