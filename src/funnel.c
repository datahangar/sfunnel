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

static __always_inline int ip4_funnel_udp_thru_tcp(struct __sk_buff* skb,
							struct iphdr* ip,
							struct udphdr* udp,
							__u16 src_port,
							__u16 dst_port){
	CHECK_SKB_PTR(skb, udp+1);

	//Store current UDP offset & content of udp header
	__u32 l3_off = (__u8*)ip - (__u8*)SKB_GET_ETH(skb);
	__u32  l4_off __attribute__((unused)) =
					(__u8*)udp - (__u8*)SKB_GET_ETH(skb);

	PRINTK("UDP packet of length: %u, offset: %u!\n", skb->len, l4_off);

	//Change IP PROTO
	union ttl_proto old_ttl = *(union ttl_proto*)&ip->ttl;
	ip->protocol = IPPROTO_TCP;
	__s64 diff = bpf_csum_diff((__be32*)&old_ttl, 4, (__be32*)&ip->ttl, 4,
							0);

	//Increase tot_len with TCP hdr
	struct ver_ihl_tos_totlen old_totlen = *(struct ver_ihl_tos_totlen*)ip;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len)+sizeof(struct tcphdr));
	diff = bpf_csum_diff((__be32*)&old_totlen, 4, (__be32*)ip, 4, diff);

	//Adjust IP checksum and make room for the TCP hdr
	int rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);
	if(rc < 0){
		PRINTK("ERROR l3_csum_replace: %d", rc);
		return TC_ACT_SHOT;
	}
	rc = bpf_skb_adjust_room(skb, sizeof(struct tcphdr), BPF_ADJ_ROOM_NET,
							0);
	if(rc < 0){
		PRINTK("ERROR adjust room: %d", rc);
		return TC_ACT_SHOT;
	}

	//Reeval ptrs
	ip = (struct iphdr*)((__u8*)SKB_GET_ETH(skb)+sizeof(struct ethhdr));
	CHECK_SKB_PTR(skb, ip+1);
	struct tcphdr* tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, tcp+1);
	l3_off = (__u8*)ip - (__u8*)SKB_GET_ETH(skb); //Must be recomputed (?)
	l4_off = (__u8*)tcp - (__u8*)SKB_GET_ETH(skb); //idem
	udp = (struct udphdr*)(tcp+1);
	CHECK_SKB_PTR(skb, udp+1);

	tcp->dest = bpf_htons(dst_port);
	tcp->source = bpf_htons(src_port);
	tcp->seq = bpf_htonl(0xCAFEBABE);
	tcp->ack_seq = bpf_htonl(0xBABECAFE);
	*((&tcp->ack_seq)+1) = tcp->urg_ptr = tcp->check = 0x0;
	tcp->syn = 0x1;
	tcp->window = bpf_htons(1024);
	tcp->doff = sizeof(*tcp)/4;
	tcp->check = 0x0;

	//UDP checksum as a basis
	diff = csum_fold(udp->check);

	//Add diff from the new TCP hdr
	diff = bpf_csum_diff(0, 0, (__be32*)tcp, sizeof(*tcp), diff);

	//Diff pseudoheader
	struct pseudo_header old, new;
	old.src = ip->saddr;
	old.dst = ip->daddr;
	old.res = 0x0;
	old.proto = IPPROTO_UDP;
	old.len = udp->len;

	new = old;
	new.proto = IPPROTO_TCP;
	new.len = bpf_htons(bpf_ntohs(udp->len)+sizeof(*tcp));
	diff = bpf_csum_diff((__be32*)&old, sizeof(old), (__be32*)&new,
							sizeof(new), diff);

	//Finally add the UDP checksum (0ed in UDP checksum calc, now payload)
	__be16 udp_csum[2] = {0, udp->check};
	diff = bpf_csum_diff(0, 0, (__be32*)&udp_csum, 4, diff);

	//Set checksum
	tcp->check = csum_fold(diff);

	//Packet has been mangled, mark it as such
	bpf_set_hash_invalid(skb);

	return TC_ACT_OK;
}

static inline int proc_ip4(struct __sk_buff* skb, struct iphdr* ip){
	struct udphdr* udp;

	CHECK_SKB_PTR(skb, ip+1);

	if(ip->protocol != IPPROTO_UDP){
		return TC_ACT_UNSPEC;
	}

	//XXX: check if DST IP and DST port is the one we care

	udp = (struct udphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, udp+1);
	if(udp->dest != bpf_ntohs(UDP_TOFUNNEL_DST_PORT))
		return TC_ACT_UNSPEC;

	return ip4_funnel_udp_thru_tcp(skb, ip, udp, TCP_FUNNEL_SRC_PORT,
							TCP_FUNNEL_DST_PORT);
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
