#ifndef SFUNNEL_FIB_H
#define SFUNNEL_FIB_H

#include "common.h"

static __always_inline
int fib_ip4_lookup(struct __sk_buff* skb, struct bpf_fib_lookup* fib_params,
		   struct iphdr* ip){
	int rc;

	fib_params->family = AF_INET;
	fib_params->tos = ip->tos;
	fib_params->l4_protocol = ip->protocol;
	fib_params->tot_len = bpf_ntohs(ip->tot_len);
	fib_params->ifindex = skb->ifindex;
	fib_params->ipv4_dst = ip->daddr;
	fib_params->ipv4_src = ip->saddr;

	rc = bpf_fib_lookup(skb, fib_params, sizeof(*fib_params), 0);
	if(rc != BPF_FIB_LKUP_RET_SUCCESS){
		PRINTK("[%d:0x%p][fib] Failed to bpf_fib_lookup() on egress: rc=%d",
						skb->ifindex,
						skb, rc);
		return TC_ACT_SHOT;
	}

	PRINTK("[%d:0x%p][fib] bpf_fib_lookup() egress if: %d, effective mtu: %d",
						skb->ifindex, skb,
						fib_params->ifindex,
						fib_params->mtu_result);
	return TC_ACT_OK;
}

#endif //SFUNNEL_FIB
