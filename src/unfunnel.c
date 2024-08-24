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

static __always_inline int ip4_unfunnel_udp_thru_tcp(struct __sk_buff* skb,
							struct iphdr* ip){
	//Substract tcp HDR and recalc check
	union ttl_proto old_ttl =  *(union ttl_proto*)&ip->ttl;
	ip->protocol = IPPROTO_UDP;
	__s64 diff = bpf_csum_diff((__be32*)&old_ttl, 4, (__be32*)&ip->ttl, 4,
								0);
	if(diff < 0){
		PRINTK("ERROR csum_diff: %d", diff);
		return TC_ACT_SHOT;
	}

	//Decrease tot_len with TCP hdr
	struct ver_ihl_tos_totlen old_totlen = *(struct ver_ihl_tos_totlen*)ip;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len)-sizeof(struct tcphdr));
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
	rc = bpf_skb_adjust_room(skb, -(__s32)sizeof(struct tcphdr), BPF_ADJ_ROOM_NET, 0);
	if(rc < 0){
		PRINTK("ERROR adjust room: %d", rc);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static inline int proc_ip4(struct __sk_buff* skb, struct iphdr* ip){
	struct tcphdr* tcp;

	CHECK_SKB_PTR(skb, ip+1);

	if(ip->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	//XXX: check if DST IP is the one we care
	tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, tcp+1);

	if(tcp->source != bpf_htons(TCP_FUNNEL_SRC_PORT) ||
		tcp->dest != bpf_htons(TCP_FUNNEL_DST_PORT))
		return TC_ACT_UNSPEC;

	return ip4_unfunnel_udp_thru_tcp(skb, ip);
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

char _license[] SEC("license") = "GPL";
