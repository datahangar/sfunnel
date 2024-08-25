import pytest
from scapy.all import sniff, sendp, Ether, IP, UDP, TCP, Raw
import threading

#43 bytes < 64
pkts_43 = [
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=4739)/Raw("ABC"),
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=2055)/Raw("ABC"),
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=6343)/Raw("ABC")
]

#Multiple of 4
pkts_44 = [
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=4739)/Raw("ABCD"),
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=2055)/Raw("ABCD"),
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=6343)/Raw("ABCD")
]

#Multiple of 1040
pkts_1041 = [
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=4739)/Raw("X"*1001),
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=2055)/Raw("X"*1001),
    Ether()/IP(src="11.1.1.1", dst="10.0.0.2")/UDP(sport=65000, dport=6343)/Raw("X"*1001)
]

all_pkts = pkts_43 + pkts_44 + pkts_1041
SNIFF_TIMEOUT=3

@pytest.fixture
def sniff_packets():
    sniffed_packets_veth1 = []
    sniffed_packets_br_net = []
    sniffed_packets_veth2 = []

    sniff_complete_veth1_ev = threading.Event()
    sniff_complete_br_net_ev = threading.Event()
    sniff_complete_veth2_ev = threading.Event()

    pcap_filter = "host 11.1.1.1"

    def sniffing(interface, sniffed_packets, pkts, event):
        sniff(iface=interface, filter=pcap_filter, count=len(pkts), prn=lambda x: sniffed_packets.append(x), timeout=SNIFF_TIMEOUT)
        event.set()

    # Start sniffing in a separate thread
    sniff_thread1 = threading.Thread(target=sniffing, args=("veth1", sniffed_packets_veth1, all_pkts, sniff_complete_veth1_ev))
    sniff_thread2 = threading.Thread(target=sniffing, args=("br_net", sniffed_packets_br_net, all_pkts, sniff_complete_br_net_ev))
    sniff_thread3 = threading.Thread(target=sniffing, args=("veth2", sniffed_packets_veth2, all_pkts, sniff_complete_veth2_ev))

    sniff_thread1.start()
    sniff_thread2.start()
    sniff_thread3.start()

    yield sniffed_packets_veth1, sniffed_packets_br_net, sniffed_packets_veth2, sniff_complete_veth1_ev, sniff_complete_br_net_ev, sniff_complete_veth2_ev

    # Wait for sniffing to complete
    sniff_thread1.join()
    sniff_thread2.join()
    sniff_thread3.join()

def print_pkts(iface, pkts):
    print(f"[{iface}] Got")
    for p in pkts:
        print(p)

def test_unit_funnel_unfunnel(sniff_packets):
    sniffed_packets_veth1, sniffed_packets_br_net, sniffed_packets_veth2, sniff_complete_veth1_ev, sniff_complete_br_net_ev, sniff_complete_veth2_ev = sniff_packets

    #43 byte pkts
    sendp(pkts_43, iface="veth0")
    sendp(pkts_44, iface="veth0")
    sendp(pkts_1041, iface="veth0")

    #Wait for sniff
    sniff_complete_veth1_ev.wait(SNIFF_TIMEOUT+1)
    sniff_complete_br_net_ev.wait(SNIFF_TIMEOUT+1)
    sniff_complete_veth2_ev.wait(SNIFF_TIMEOUT+1)

    print_pkts("veth1", sniffed_packets_veth1)
    print_pkts("br_net", sniffed_packets_br_net)
    print_pkts("veth2", sniffed_packets_veth2)

    assert(len(sniffed_packets_veth1) == len(all_pkts))
    assert(len(sniffed_packets_br_net) == len(all_pkts))
    assert(len(sniffed_packets_veth2) == len(all_pkts))

    for i in range(0, len(all_pkts)):
        p = all_pkts[i]
        p = p.__class__(bytes(p)) #Calculate checksums

        p_ttl_dec = p.copy()
        p_ttl_dec["IP"].ttl = p_ttl_dec["IP"].ttl -1
        p_ttl_dec = p_ttl_dec.__class__(bytes(p)) #Calculate checksums

        p_veth1 = sniffed_packets_veth1[i]
        p_br_net = sniffed_packets_br_net[i]
        p_veth2 = sniffed_packets_veth2[i]

        #Before and after funneling need to preserve IP hdr, -TTL
        assert p["IP"] == p_veth1["IP"]
        assert p_ttl_dec["IP"] == p_veth2["IP"]

        l4_proto = None
        if "UDP" in p:
            l4_proto = "UDP"
        elif "TCP" in p:
            l4_proto = "TCP"
        else:
            assert 0
        #L4 hdr must be identic before&after funneling
        assert p[l4_proto] == p_veth1[l4_proto]
        assert p_ttl_dec[l4_proto] == p_veth2[l4_proto]

        #Synthetically create the funneled pkt
        aux = p.copy()
        ip = IP(src=p["IP"].src, dst=p["IP"].dst, ttl=p["IP"].ttl)
        tcp = TCP(dport=179, sport=540, flags="S", urgptr=0, window=1024, seq=0xCAFEBABE, ack=0xBABECAFE)
        funneled_p = Ether()/ip/tcp/aux[l4_proto]
        funneled_p = funneled_p.__class__(bytes(funneled_p)) #Calculate checksums

        assert p_br_net["IP"] == funneled_p["IP"]
        assert p_br_net["TCP"] == funneled_p["TCP"]
