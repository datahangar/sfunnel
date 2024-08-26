#ifndef SFUNNEL_LOOKUP_H
#define SFUNNEL_LOOKUP_H

#include "common.h"

static __always_inline
__u8 match_addr(sfunnel_ip4_addr_match_t* m, __be32 ip){
	return ((ip&m->mask) == (m->addr&m->mask)) != m->negate;
}

static __always_inline
bool match_port(sfunnel_l4_port_match_t* m, __be16 port){
	return !m->port || ((port == m->port) != m->negate);
}

static __always_inline
bool rule_check_tcp(struct __sk_buff* skb, struct sfunnel_ip4_matches* m,
							struct iphdr* ip,
							struct tcphdr* tcp){
	return match_port(&m->sport, tcp->source) &&
					match_port(&m->dport, tcp->dest);
}

static __always_inline
bool rule_check_udp(struct __sk_buff* skb, struct sfunnel_ip4_matches* m,
							struct iphdr* ip,
							struct udphdr* udp){
	return match_port(&m->sport, udp->source) &&
					match_port(&m->dport, udp->dest);
}

static __always_inline
sfunnel_ip4_rule_t* ip4_rule_lookup(struct __sk_buff* skb, struct iphdr* ip,
							struct tcphdr* tcp,
							struct udphdr* udp){

	sfunnel_ip4_rule_t* r;
	struct sfunnel_ip4_matches* m;

	//Linear lookup
	__u32 n_rules = sizeof(ip4_rules)/sizeof(*r);
	for(__u32 i=0; i < n_rules; ++i){
		r = &ip4_rules[i];
		m = &r->matches;

		if(!match_addr(&m->saddr, ip->saddr))
			continue;
		if(!match_addr(&m->daddr, ip->daddr))
			continue;

		if(m->proto && ip->protocol != m->proto)
			continue;

		//We seem to have to reeval ip, tcp, udp...
		//Verifier bug (?)
		ip = (struct iphdr*)((__u8*)SKB_GET_ETH(skb) +
							sizeof(struct ethhdr));
		CHECK_SKB_PTR_VAL(skb, ip+1, NULL);
		__u16 l3_size = ip->ihl * 4;

		if(ip->protocol == IPPROTO_TCP){
			tcp = (struct tcphdr*)((__u8*)ip+l3_size);
			CHECK_SKB_PTR_VAL(skb, tcp+1, NULL);

			if(!rule_check_tcp(skb, m, ip, tcp))
				continue;
		}else if(ip->protocol == IPPROTO_UDP){
			udp = (struct udphdr*)((__u8*)ip+l3_size);
			CHECK_SKB_PTR_VAL(skb, udp+1, NULL);

			if(!rule_check_udp(skb, m, ip, udp))
				continue;
		}else{
			continue;
		}

		return r;
	}

	return NULL;
}

#endif //SFUNNEL_LOOKUP
