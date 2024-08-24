#ifndef FUNNEL_COMMON_H
#define FUNNEL_COMMON_H

#if 0
	#define PRINTK(...) bpf_printk( __VA_ARGS__ )
#else
	#define PRINTK(...) 
#endif

#define SKB_GET_ETH( SKB ) (struct ethhdr*)(unsigned long long)skb->data

#define CHECK_SKB_PTR( SKB, PTR ) \
	if (  (void*)(PTR) > ((void*)(unsigned long long) SKB -> data_end )) {	\
		PRINTK("PTR: %p on pkt with length: %d out of bounds!\n",   \
								PTR, SKB ->len);\
		return TC_ACT_OK;						\
	} do{}while(0)

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

//Taken from cilium
static __always_inline  __be16 csum_fold(__s64 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__be16)~csum;
}


#define TCP_FUNNEL_DST_PORT 179
#define TCP_FUNNEL_SRC_PORT 540 //E.g. UUCP
#define UDP_TOFUNNEL_DST_PORT 2055

#endif //FUNNEL_COMMON_H
