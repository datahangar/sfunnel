# _Funneling? Isn't it just tunneling_

`sfunnel` pushes a new L4 header (TCP or UDP) between the IP and the existing L4
header. It is a form of pseudo-tunneling, and suffers from the same
[MTU issues](#mtu) as a any tunnel.

Tunnels usually have a dedicated L4 proto+port, and _only_ tunneled traffic is
received on that port. This is not the case when _funneling_, as funneled
traffic will flow alongside with the real traffic, hence the reason to use a
different term to avoid confusion.

For example, when funneling some UDP traffic on top TCP port 80, _some_ traffic
flowing will still be WEB traffic, and will be left untouched, while UDP
traffic on top will be unfunneled (decapped or demultiplexed) and delivered as
UDP traffic transparently.

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

Funneling suffers from the same problems as any encapsulation (tunneling). The
MTU should be sufficiently big to accomodate the extra 20 bytes for TCP funneling
or 8 bytes for UDP funneling.

Make sure you adjust this. An [upcoming feature](next_steps.md) will be to check
for MTU exceeding funneled packets and raise alarms (`printk()`).
