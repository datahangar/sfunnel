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
#include "ip4.h"

SEC("classifier")
int tc_sfunnel(struct __sk_buff *skb){
	struct ethhdr *eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if(eth->h_proto == bpf_htons(ETH_P_IP)){
		struct iphdr* ip = (struct iphdr*)(eth+1);
		return proc_ip4(skb, INGRESS, (__u8*)eth, ip);
	}else if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
		//XXX
		//PRINTK("IPv6 packet with length: %d NOT SUPPORTED!\n", skb->len);
	}

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("Dual BSD/GPL");
