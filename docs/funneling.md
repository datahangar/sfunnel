# _Funneling? Isn't it just tunneling_

`sfunnel` pushes a new Layer 4 header (TCP or UDP) between the IP and the existing L4
header. It is a form of pseudo-tunneling, and faces the same [MTU issues](#mtu)
as with any tunnel.

Tunnels usually have a dedicated L4 port, meaning only tunneled traffic is
received on that specific protocol+port. This is not the case when _funneling_,
as funneled traffic coexists with the regular traffic on the port, which is why
the term "funneling" is used to avoid confusion.

For instance, when funneling some UDP traffic over TCP port 80, regular web
traffic will continue to flow as usual and remain unaffected, while the funneled
UDP traffic will be unfunneled (decapsulated or demultiplexed) and delivered
to the application transparently as UDP traffic.

## The life of a packet

### Funneling

Using [`scapy`]() syntax, with a funneling rule like this:

```
udp dport 4739 actions funnel tcp dport 179 sport 540
```

A(n IPFIX) packet:

```python
Ether()/IP()/UDP(dport=4739)/IPFIX()/...
```

would be convereted into:

```python
Ether()/IP()/TCP(dport=179, sport=540)/UDP(dport=4739)/IPFIX()/...
```

> :pencil: Note
>
> For the record, other TCP fields are currently hardcoded to:
>  * `flags`: SYN
>  * `seq`: `0xCAFEBABE`
>  * `ack_seq`: `0xBABECAFE`
>  * `window`: `1024`
>  * `urg_ptr`: `0x0`
>
> `funnel` action could be extended to set some of these values (flags in particular)

### Unfunneling; reversing it!

On the other end, typically a K8s pod, a rule like this would exist:

```
tcp dport 179 sport 540 actions unfunnel udp
```

Therefore, the traffic received by the worker node:

```python
Ether()/IP()/TCP(dport=179, sport=540)/UDP(dport=4739)/IPFIX()/...
```

Would be converted back to:

```python
Ether()/IP()/UDP(dport=4739)/IPFIX()/...
```

## MTU

Funneling faces the same challenges as any encapsulation (tunneling) method. The
MTU must be large enough to accomodate the additional overhead: 20 bytes for TCP
funneling or 8 bytes for UDP funneling.

Ensure that your MTU settings are adjusted accordingly. An [upcoming feature](next_steps.md)
will allow checking for funneled packets that exceeed the MTU and raising alerts
via `printk()`.
