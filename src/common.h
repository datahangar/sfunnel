#ifndef FUNNEL_COMMON_H
#define FUNNEL_COMMON_H

#include <stdbool.h>

#if 0
	#define PRINTK(...) bpf_printk( __VA_ARGS__ )
#else
	#define PRINTK(...)
#endif

#define SKB_GET_ETH( SKB ) (struct ethhdr*)(unsigned long long)skb->data


#define CHECK_SKB_PTR_VAL( SKB, PTR, VAL ) \
	if (  (void*)(PTR) > ((void*)(unsigned long long) SKB -> data_end )) {	\
		PRINTK("PTR: %p on pkt with length: %d out of bounds!\n",   \
								PTR, SKB ->len);\
		return VAL;							\
	} do{}while(0)
#define CHECK_SKB_PTR( SKB, PTR ) CHECK_SKB_PTR_VAL( SKB, PTR, TC_ACT_OK)

struct __attribute__((packed)) pseudo_header {
	__be32 src;
	__be32 dst;
	__u8 res;
	__u8 proto;
	__be16 len;
};
union __attribute__((packed)) ttl_proto {
	__be32 be32;
	__u8 aux[4];
};
struct __attribute__((packed)) ver_ihl_tos_totlen {
	__be16 ver_ihl_tos;
	__be16 tot_len;
};

//Taken from Cilium
static __always_inline  __be16 csum_fold(__s64 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__be16)~csum;
}

#ifndef BPF_LICENSE
#define BPF_LICENSE(NAME) \
  char ____license[] __attribute__((section("license"), used)) = NAME
#endif


//Rules
typedef struct sfunnel_ip4_addr_match {
	__be32 addr;
	__be32 mask;
	bool negate;
} sfunnel_ip4_addr_match_t;

typedef struct sfunnel_l4_port_match {
	__be16 port;
	bool negate;
} sfunnel_l4_port_match_t;

typedef struct sfunnel_action_funnel_params {
	__u8 funn_proto; //Funneling proto (TCP or UDP)
	__be16 sport;
	__be16 dport;
	__u8 tcp_flags; //Not supported yet (SYN for the time being)
}sfunnel_action_funnel_params_t;

typedef struct sfunnel_action_unfunnel_params {
	__u8 proto; //Inner pkt proto (TCP or UDP)
	//TODO add more (e.g. dec ttl?)
}sfunnel_action_unfunnel_params_t;

typedef struct sfunnel_action_dnat_params {
	__be32 daddr;
	//TODO: add more for LB.
}sfunnel_action_dnat_params_t;

typedef struct sfunnel_action_params {
	bool execute;
	union {
		sfunnel_action_funnel_params_t funnel;
		sfunnel_action_unfunnel_params_t unfunnel;
		sfunnel_action_dnat_params_t dnat;
	}p;
}sfunnel_action_params_t;

typedef struct sfunnel_ip4_rule {
	__u16 id;
	struct sfunnel_ip4_matches{
		sfunnel_ip4_addr_match_t saddr;
		sfunnel_ip4_addr_match_t daddr;
		__u8 proto; //0 don't match
		sfunnel_l4_port_match_t sport;
		sfunnel_l4_port_match_t dport;
	} matches;
	struct {
		sfunnel_action_params_t funnel;
		sfunnel_action_params_t unfunnel;
		sfunnel_action_params_t dnat;
		sfunnel_action_params_t accept;
		sfunnel_action_params_t drop;
	} actions;
}sfunnel_ip4_rule_t;

#include "ruleset.h"

#endif //FUNNEL_COMMON_H
