#ifndef SFUNNEL_LOOKUP_H
#define SFUNNEL_LOOKUP_H

#include "common.h"

typedef struct pkt_hdrs {
	__be32 saddr;
	__be32 daddr;
	__u8 proto;
	__be16 sport;
	__be16 dport;
	__u8 pad;
	__u16 pad2;
}pkt_hdrs_t;

static __always_inline
__u8 match_addr(const sfunnel_ip4_addr_match_t* m, const __be32 ip){
	return ((ip&m->mask) == (m->addr&m->mask)) != m->negate;
}

static __always_inline
bool match_port(const sfunnel_l4_port_match_t* m, const __be16 port){
	return !m->port || ((port == m->port) != m->negate);
}

static __always_inline
bool rule_check_l4_ports(const struct sfunnel_ip4_matches* m,
				const __be16 sport, const __be16 dport){
	return match_port(&m->sport, sport) && match_port(&m->dport, dport);
}

static __always_inline
const sfunnel_ip4_rule_t* ip4_rule_lookup(const pkt_hdrs_t* hdrs){
	const sfunnel_ip4_rule_t* r = NULL;

	//Linear lookup
#pragma unroll
	for(__u32 i=0; i<IP4_RULES_SIZE; ++i){
		r = &ip4_rules[i];
		const struct sfunnel_ip4_matches* m = &r->matches;

		if(!match_addr(&m->saddr, hdrs->saddr))
			continue;
		if(!match_addr(&m->daddr, hdrs->daddr))
			continue;

		if(m->proto && hdrs->proto != m->proto)
			continue;
		if(!rule_check_l4_ports(m, hdrs->sport, hdrs->dport))
			continue;
		return r;
	}

	return NULL;
}

#endif //SFUNNEL_LOOKUP
