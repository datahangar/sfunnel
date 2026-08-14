#ifndef SFUNNEL_PMTUD_H
#define SFUNNEL_PMTUD_H

/* XXX Ugly hack to avoid including if.h */
#define _LINUX_IF_H
#ifndef IFNAMSIZ
	#define IFNAMSIZ 16
#endif //IFNAMSIZ
#include <linux/icmp.h>
#undef _LINUX_IF_H

#include "common.h"
#include "lookup.h"

#define IP_DF 0x4000

typedef struct pmtud_pkt {
	struct iphdr ip;
	struct icmphdr icmp;
}pmtud_pkt_t;

typedef pkt_hdrs_t pmtud_flow_hash_t;

COMPILATION_ASSERT(sizeof(pmtud_flow_hash_t) == 16,
		   "Size of pmtud_flow_hash_t must be 16!");

typedef struct __attribute__((packed)) pmtud_flow_state{
	__u16 last_seen_net_mtu;
	__u16 adjusted_mtu;
}pmtud_flow_state_t;
COMPILATION_ASSERT(sizeof(pmtud_flow_state_t) == 4,
		   "Size of pmtud_flow_state_t must be 4!");

/**
* PMTUD map
*/
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PMTUD_MAP_N_ENTRIES);
    __type(key, pmtud_flow_hash_t);
    __type(value, pmtud_flow_state_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} PMTUD_MAP_NAME SEC(".maps");

#define pmtud_map PMTUD_MAP_NAME

static __always_inline
int pmtud_ip4_gen_frag_needed(struct __sk_buff* skb, struct iphdr* ip,
			      const __u32 usable_mtu, const __be32 icmp_saddr){
	int rc;
	struct iphdr old_ip;
	struct ethhdr *eth;
	pmtud_pkt_t hdrs, *ip_icmp;
	__s64 ip_csum, icmp_csum;
	struct pseudo_header pseudo;
	__u16 tot_len = bpf_ntohs(ip->tot_len);

	//Prepare the IP hdr (outer)
	hdrs.ip.version = 4;
	hdrs.ip.ihl = 5;
	hdrs.ip.tos = 0x0;
	hdrs.ip.tot_len = bpf_htons(sizeof(pmtud_pkt_t) + 64);
	hdrs.ip.id = ip->id;
	hdrs.ip.frag_off = 0x0;
	hdrs.ip.ttl = 64;
	hdrs.ip.protocol = IPPROTO_ICMP;
	hdrs.ip.daddr = ip->saddr;
	hdrs.ip.saddr = icmp_saddr;
	hdrs.ip.check = 0x0;

	hdrs.icmp.type = ICMP_DEST_UNREACH;
	hdrs.icmp.code = ICMP_FRAG_NEEDED;
	hdrs.icmp.checksum = 0x0;
	hdrs.icmp.un.frag.__unused = 0x0;
	hdrs.icmp.un.frag.mtu = bpf_htons(usable_mtu);

	//Inner, as push will happen between l3 and l4
	old_ip = *ip;

	if(tot_len < 64){
		PRINTK("[%d:0x%p][pmtud] Buggy packet of len: %d, less than 64 byte supposed to trigger frag. needed!",
						skb->ifindex, skb,
						skb->len);
		return TC_ACT_SHOT;

	}

    	//Limit payload to 64 bytes
	rc = bpf_skb_change_tail(skb, sizeof(*eth) + sizeof(hdrs) + 64, 0x0);
	if(rc < 0){
		PRINTK("[%d:0x%p][pmtud] Unable to trim skb (len: %d). rc=%d",
						skb->ifindex, skb,
						skb->len, rc);
		return TC_ACT_SHOT;
	}

	//Make room for outer IP + ICMP + MTU
	rc = bpf_skb_adjust_room(skb, sizeof(pmtud_pkt_t), BPF_ADJ_ROOM_NET, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p][pmtud] Unable to adjust_room for pmtud hdr +%d (IP+ICMPv4+opt). rc=%d",
							skb->ifindex, skb,
							sizeof(pmtud_pkt_t),
							rc);
        	return TC_ACT_SHOT;
	}

	eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);
	ip_icmp = (pmtud_pkt_t*)(eth+1);
	CHECK_SKB_PTR(skb, ip_icmp+1);
	*ip_icmp = hdrs;
	ip = (struct iphdr*)(ip_icmp+1);
	CHECK_SKB_PTR(skb, ip+1);
	*ip = old_ip;

	ip_csum = bpf_csum_diff(NULL, 0, (__be32*)&hdrs.ip, sizeof(hdrs.ip), 0);
	pseudo.dst = hdrs.ip.daddr;
	pseudo.src = hdrs.ip.saddr;
	pseudo.res = 0x0;
	pseudo.proto = IPPROTO_ICMP;
	pseudo.len = bpf_htons(sizeof(hdrs.icmp) + 64);
	icmp_csum = bpf_csum_diff(NULL, 0, (__be32*)&pseudo, sizeof(pseudo), 0);

	CHECK_SKB_PTR(skb, ((__u8*)(ip_icmp+1)) + 64);
	icmp_csum = bpf_csum_diff(NULL, 0, (__be32*)&ip_icmp->icmp,
				  sizeof(hdrs) - sizeof(hdrs.ip) + 64,
				  icmp_csum);

	__u32 l3_off = (__u8*)&ip_icmp->ip - (__u8*)SKB_GET_ETH(skb);
	__u32 l4_off = l3_off + sizeof(hdrs.ip);

	rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0,
				 ip_csum, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p][pmtud] Unable to set L3 csum. rc=%d",
							skb->ifindex, skb,
							rc);
        	return TC_ACT_SHOT;
	}

	rc = bpf_l4_csum_replace(skb, l4_off + offsetof(struct icmphdr, checksum),
				 0, icmp_csum, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p][pmtud] Unable to set L4 csum. rc=%d",
							skb->ifindex, skb,
							rc);
        	return TC_ACT_SHOT;
	}

	//Packet has been mangled, mark it as such
	bpf_set_hash_invalid(skb);

	//Use TC_ACT_UNSPEC as rc to indicate ingress via SEG_PAIR
	//Will be later translated to TC_ACT_OK
	return TC_ACT_UNSPEC;
}

static __always_inline
bool pmtud_ip4_check(struct __sk_buff* skb, struct iphdr* ip,
		     const struct bpf_fib_lookup* fib_params){
	__u16 len = bpf_ntohs(ip->tot_len);
	__u16 usable_mtu = fib_params->mtu_result;

	if(!(ip->frag_off & bpf_htons(IP_DF)))
		return TC_ACT_OK;

	//Calculate the usable MTU against effective MTU to dest post funneling
	//(assuming it hasn't been adjusted before)
	if(skb->mark&PKT_PUSH_TCP){
		usable_mtu -= sizeof(struct tcphdr);
	}else if(skb->mark&PKT_PUSH_UDP){
		usable_mtu -= sizeof(struct udphdr);
	}

	if(len < usable_mtu)
		return TC_ACT_OK;

	pmtud_flow_hash_t hash = {0};
	pmtud_flow_state_t* state = NULL;
	hash.daddr = ip->daddr;
	hash.saddr = ip->saddr;
	hash.proto = ip->protocol;
	if(hash.proto == IPPROTO_TCP){
		struct tcphdr *tcp = (struct tcphdr*)(ip+1);
		CHECK_SKB_PTR(skb, tcp+1);
		hash.dport = tcp->dest;
		hash.sport = tcp->source;
	}else if(hash.proto == IPPROTO_UDP){
		struct udphdr *udp = (struct udphdr*)(ip+1);
		CHECK_SKB_PTR(skb, udp+1);
		hash.dport = udp->dest;
		hash.sport = udp->source;
	}else{
		PRINTK("[%d:0x%p][pmtud] Buggy protocol %d", skb->ifindex, skb,
								hash.proto);
		return false;
	}

	PRINTK("[%d:0x%p][pmtud] Looking for flow: ", skb->ifindex, skb);
	PRINTK("{ saddr: 0x%x, daddr: 0x%x, protocol: %d" ,
						bpf_htonl(hash.saddr),
						bpf_htonl(hash.daddr),
						hash.proto);
	PRINTK("  sport: %d, dport: %d }" , bpf_htons(hash.sport),
						bpf_htons(hash.dport));

	state = bpf_map_lookup_elem(&pmtud_map, &hash);
	if(state){
		//Already adjusted and pkt within bounds we are done!
		if(len <= state->adjusted_mtu)
			return TC_ACT_OK;

		//TODO: intercept network ICMP PMTUD pkts and adjust state
		if(fib_params->mtu_result != state->adjusted_mtu &&
			fib_params->mtu_result != state->last_seen_net_mtu){
			PRINTK("[%d:0x%p][pmtud] Invalid PMTUD state effective mtu: %d, last adjusted: %d",
					skb->ifindex, skb,
					fib_params->mtu_result,
					state->adjusted_mtu);
			return TC_ACT_SHOT;
		}

		//We sent PMTUD but apparently was not received / processed
		//Do it again
		goto SEND_ICMP;
	}

	PRINTK("[%d:0x%p][pmtud] Adjusting MTU. Discovered mtu to destination: %d, usuable mtu (after push): %d. Generating icmp frag. needed.",
					skb->ifindex, skb,
					fib_params->mtu_result,
					usable_mtu);

	pmtud_flow_state_t new_state = {
			.last_seen_net_mtu = fib_params->mtu_result,
			.adjusted_mtu = usable_mtu
	};
	int rc = bpf_map_update_elem(&pmtud_map, &hash, &new_state, BPF_ANY);
	if(rc < 0){
		PRINTK("[%d:0x%p][pmtud] Unable to create flow state rc=%d",
						skb->ifindex, skb, rc);
	}

SEND_ICMP:
	return pmtud_ip4_gen_frag_needed(skb, ip, usable_mtu,
					 fib_params->ipv4_src);
}

static __always_inline
int pmtud_proc_icmp(struct __sk_buff* skb, struct iphdr* ip){
	int rc;
	const sfunnel_ip4_rule_t* rule = NULL;
	pmtud_flow_state_t* state = NULL;
	struct udphdr* udp;
	struct icmphdr* icmp;
	struct iphdr* inner_ip;
	pkt_hdrs_t hdrs = {0};
	__u8 fhdr_size;

	icmp = (struct icmphdr*) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, icmp+1);

	if(icmp->type != ICMP_DEST_UNREACH || icmp->code != ICMP_FRAG_NEEDED)
		return TC_ACT_UNSPEC;

	inner_ip = (struct iphdr*)(icmp+1);
	CHECK_SKB_PTR(skb, inner_ip+1);
	if(inner_ip->protocol != IPPROTO_UDP &&
	   inner_ip->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	//Note: the ICMP quotes a pkt _we_ funneled and sent out, whereas
	//unfunnel rules live in the ingress path, hence they describe the
	//mirror flow (our funneled traffic coming back). Lookup the rule with
	//the quoted flow reversed.
	hdrs.saddr = inner_ip->daddr;
	hdrs.daddr = inner_ip->saddr;
	hdrs.proto = inner_ip->protocol;

	//Note: RFC 792 only ensures the first 8 bytes of the original L4 hdr
	//This got updated with RFC 4884 and 1812 in practice most systems
	//will send at least 64 bytes, which includes the inner L4 hdr. This
	//allows us to look in the inner L4 hdr instead of having to do
	//flow tracking
	//
	//Note2: we are only interested in the s/dport of the L4 hdr. Using
	//UDP as they are in the same position of the hdr.
	udp = (struct udphdr *)((__u8*)inner_ip + (inner_ip->ihl * 4));
	CHECK_SKB_PTR(skb, ((__u8*)udp) + 8);

	hdrs.sport = udp->dest;
	hdrs.dport = udp->source;

	rule = ip4_rule_lookup(&hdrs);

	if(!rule || !rule->actions.unfunnel.execute)
		return TC_ACT_UNSPEC;


	//Note: the funneling hdr in the quoted pkt is the one the rule matched
	//(inner_ip->protocol), not the proto the unfunnel action restores
	if(inner_ip->protocol == IPPROTO_UDP)
		fhdr_size = sizeof(struct udphdr);
	else
		fhdr_size = sizeof(struct tcphdr);

	//Recover the max network MTU
	__u16 net_mtu = bpf_ntohs(icmp->un.frag.mtu);
	__s64 icmp_diff = 0;

	CHECK_SKB_PTR(skb, ((__u8*)udp) + fhdr_size + 8);

	//The quoted pkt is the funneled one, but the PMTUD state is keyed with
	//the original (pre funneling) flow, as done in pmtud_ip4_check().
	//Addrs are not modified by funneling; the proto is the one restored by
	//the unfunnel action and the ports are in the inner L4 hdr, right
	//after the funneling hdr (+fhdr_size)
	pmtud_flow_hash_t hash = {0};
	hash.saddr = inner_ip->saddr;
	hash.daddr = inner_ip->daddr;
	hash.proto = rule->actions.unfunnel.p.unfunnel.proto;
	hash.sport = *(__be16*)(((__u8*)udp) + fhdr_size);
	hash.dport = *(__be16*)(((__u8*)udp) + fhdr_size + 2);

	//Check whether we have to adjust the PMTUD map and adapt net_mtu
	//Note: if not present in the map, the end host effective MTU will be
	//lowered. We will further lower it once the first packet exceeding
	//net_mtu + fhdr_size is intercepted, so no need to do anything here.
	state = bpf_map_lookup_elem(&pmtud_map, &hash);
	if(state){
		if(net_mtu < state->last_seen_net_mtu){
			//Note: the ptr returned by a HASH map lookup points to
			//the value itself, so writes through it are persistent
			state->last_seen_net_mtu = net_mtu;
			state->adjusted_mtu = net_mtu - fhdr_size;
		}

		__be32 old_mtu = *(__be32*)&icmp->un.frag;

		//Adjust ICMP network MTU (-fhdr_size)
		icmp->un.frag.mtu = bpf_htons(state->adjusted_mtu);

		//Adjust ICMP checksum
		icmp_diff = bpf_csum_diff(&old_mtu, 4, (__be32*)&icmp->un.frag,
					  4, 0);
	}

	//Now unfunnel
	if(rule->actions.unfunnel.p.unfunnel.proto != inner_ip->protocol){
		//Adjust protocol
		union ttl_proto old_ttl = *(union ttl_proto*)&inner_ip->ttl;
		__s64 diff = bpf_csum_diff((__be32*)&old_ttl, 4,
					   (__be32*)&inner_ip->ttl, 4, 0);
		icmp_diff = bpf_csum_diff((__be32*)&old_ttl, 4,
					  (__be32*)&inner_ip->ttl, 4,
					  icmp_diff);

		__u32 l3_off = (__u8*)inner_ip - (__u8*)SKB_GET_ETH(skb);
		l3_off += offsetof(struct iphdr, check);
		rc = bpf_l3_csum_replace(skb, l3_off, 0, diff, 0);
		if(rc < 0){
			PRINTK("[%d:0x%p][pmtud][proc_icmp] ERROR l3_csum_replace : %d",
			       skb->ifindex, skb, rc);
			return TC_ACT_SHOT;
		}
	}

	//Now set ports from inner L4, which we recovered from the funneled
	//L4 hdr (+fhdr_size)
	__be32 old_ports = *(__be32*)udp;
	*(__be32*)udp = *(__be32*)(((__u8*)udp) + fhdr_size);
	icmp_diff = bpf_csum_diff((__be32*)&old_ports, 4,
					  (__be32*)udp, 4,
					  icmp_diff);

	__u32 l4_off = (__u8*)udp - (__u8*)SKB_GET_ETH(skb);
	l4_off += offsetof(struct icmphdr, checksum);
	rc = bpf_l4_csum_replace(skb, l4_off, 0, icmp_diff, 0);
	if(rc < 0){
		PRINTK("[%d:0x%p][pmtud][net] Unable to set L4 csum. rc=%d",
							skb->ifindex, skb,
							rc);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

#endif //SFUNNEL_PMTUD
