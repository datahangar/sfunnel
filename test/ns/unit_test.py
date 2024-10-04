import pytest
import time
import threading
import subprocess
from scapy.all import *
import logging
import copy

WAIT_TIME=2
SNIFF_TIMEOUT=5+WAIT_TIME
logging.basicConfig(level=logging.DEBUG)

TCP_PROTO=6
UDP_PROTO=17

tx_pkts = []
fun_pkts = []
rx_pkts = []

@pytest.fixture
def sniff_packets():
    from scapy.all import sniff, sendp, Ether, IP, UDP, TCP, Raw
    sniffed_packets_veth1 = []
    sniffed_packets_veth2 = []

    sniff_complete_veth1_ev = threading.Event()
    sniff_complete_veth2_ev = threading.Event()

    pcap_filter = "tcp port 179 or udp port 179 or udp port 2055 or udp port 2056 or tcp port 2055 or tcp port 2056"

    def sniffing(interface, sniffed_packets, pkts, event):
        sniff(iface=interface, filter=pcap_filter, count=len(pkts), prn=lambda x: sniffed_packets.append(x), timeout=SNIFF_TIMEOUT)
        event.set()

    # Start sniffing in a separate thread
    sniff_thread1 = threading.Thread(target=sniffing, args=("veth1", sniffed_packets_veth1, tx_pkts, sniff_complete_veth1_ev))
    sniff_thread2 = threading.Thread(target=sniffing, args=("veth2", sniffed_packets_veth2, tx_pkts, sniff_complete_veth2_ev))

    sniff_thread1.start()
    sniff_thread2.start()

    yield sniffed_packets_veth1, sniffed_packets_veth2, sniff_complete_veth1_ev, sniff_complete_veth2_ev

    # Wait for sniffing to complete
    sniff_thread1.join()
    sniff_thread2.join()

def print_pkts(iface, pkts):
    print(f"[{iface}] Got")
    for p in pkts:
        print(p)

def add_pkt(proto, fun_proto, payload_size, nat):
    dip = "192.168.254.1" if not nat else "192.168.254.2"
    rx_dip = "192.168.254.1" if not nat else "192.168.254.3"
    rx_sip = "10.0.0.1" if not nat else "172.16.0.1"

    #dport determines how the packet will be funneled
    dport = 2055 if fun_proto == "tcp" else 2056
    if proto == "udp":
        l4 = UDP(sport=25000, dport=dport)
        fun_sport = 540 #demux criteria on unfunneling
    else:
        l4 = TCP(sport=25000, dport=dport)
        fun_sport = 541 #demux criteria on unfunneling
    payload = Raw("X"*payload_size)

    if fun_proto == "tcp":
        seqnum = 0xCAFEBABE
        ack = 0xBABECAFE
        fun_hdr = TCP(seq=seqnum, ack=ack, flags='S', urgptr=0, sport=fun_sport, dport=179, window=1024)
    else:
        fun_hdr = UDP(sport=fun_sport, dport=179)

    ## Injected
    tx_pkt = IP(src="10.0.0.1", dst=dip, ttl=64)/l4/payload
    tx_pkts.append(tx_pkt)

    ## Funneled pkt
    #We have to adjust L4 csum (payload after funneling) for csum calculation
    #with saddr=daddr=0x0
    aux = tx_pkt.copy()
    aux["IP"].src = aux["IP"].dst = "0.0.0.0"
    aux = aux.__class__(bytes(aux)) #calc l4 csum to pass it as payload

    #Note: we are capturing on veth1 using PF_PACKET, so pre PREROUTING and
    fun_pkts.append(IP(src="10.0.0.1", dst=dip, ttl=64)/fun_hdr/Raw(aux[proto.upper()]))

    ## Unfunneled
    rx_pkts.append(IP(src=rx_sip, dst=rx_dip, ttl=63)/l4/payload)

def tx_pkts_ns(ns, pcap_file):
    command = f"sudo ip netns exec {ns} sudo python3 -c \"from scapy.all import *; send(rdpcap('{pcap_file}'), iface='veth0')\""
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("Error sending packets:", e.stderr.decode())
        exit(1)

def test_unit_funnel_unfunnel(sniff_packets):
    for nat in [False, True]:
        for size in [3, 4, 1001]:
            #UDP funneled through TCP
            add_pkt("udp", "tcp", size, nat)
            #UDP funneled through UDP
            add_pkt("udp", "udp", size, nat)
            #TCP funneled through TCP
            add_pkt("tcp", "tcp", size, nat)
            #TCP funneled through UDP
            add_pkt("tcp", "udp", size, nat)

    wrpcap(".tx_pkts.pcap", tx_pkts)

    sniffed_packets_veth1, sniffed_packets_veth2, sniff_complete_veth1_ev, sniff_complete_veth2_ev = sniff_packets

    print(f'Quick&dirty way to avoid race between this thread and sniffers...')
    time.sleep(WAIT_TIME)

    #Send packets from ns1
    tx_pkts_ns("ns1", ".tx_pkts.pcap")

    #Wait for sniffers to complete their job
    sniff_complete_veth1_ev.wait(SNIFF_TIMEOUT+1)
    sniff_complete_veth2_ev.wait(SNIFF_TIMEOUT+1)
    print("veth1", sniffed_packets_veth1)
    print("veth2", sniffed_packets_veth2)

    assert(len(sniffed_packets_veth1) == len(tx_pkts))
    assert(len(sniffed_packets_veth2) == len(tx_pkts))

    for i in range(0, len(tx_pkts)):
        tx = tx_pkts[i]
        tx = tx.__class__(bytes(tx)) #Calculate checksums
        fun = fun_pkts[i]
        fun = fun.__class__(bytes(fun))
        rx = rx_pkts[i]
        rx = rx.__class__(bytes(rx))

        sniffed_fun = sniffed_packets_veth1[i][IP]
        sniffed_rx = sniffed_packets_veth2[i][IP]

        print(f"Injected pkt:\n")
        tx.show()

        print(f"Expected Funneled pkt:\n")
        fun.show()
        print(f"Funneled pkt:\n")
        sniffed_fun.show()
        assert(fun == sniffed_fun)

        print(f"Expected RX pkt:\n")
        rx.show()
        print(f"RX pkt:\n")
        sniffed_rx.show()
        assert(rx == sniffed_rx)
