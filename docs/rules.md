# Funneling rules

Rules follow this format:

```
<list of match conditions> actions <list of actions>
```

Rules are processed sequentially from top to bottom, in the exact order they are
defined. This ensures a strict total ordering of rule execution. Mind the
[limits](#scalability) regarding the number of rules.

## Syntax
### Match conditions

Match conditions use [nftables syntax](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Matches) [1].

#### `ip`

Matches IPv4 packets. Required to match `saddr` and `daddr`.

#### `saddr [!=] <cidr|addr>`/`daddr [!=] <cidr|addr>`

Matches IPv4 source/destination address of the packet against CIDR. It can
optionally be negated `!=`.

Examples:

```
ip saddr 127.0.0.1
```

```
ip daddr 10.0.0.0/24
```

```
ip saddr != 127.0.0.1 daddr 10.0.0.0/8
```

#### `tcp`/`udp`

Matches TCP or UDP packets. Required to match `sport` and `dport`.

#### `sport [!=] <port>`/`dport [!=] <port>`

Matches _a single_ L4 source or destination port (exact match). It can
optionally be negated with `!=`.

```
tcp dport 80
```

```
udp dport 1000 sport != 1000
```

### Actions

Actions resemble [nftables ones](), but they aren't exact. For `accept` and
`drop` no other action can be defined.

For the rest, actions are accumulative.

#### `funnel <l4_funneling_proto> sport <port> dport <port>`

[Funnels](funneling.md) traffic through `<l4_funneling_proto>`, and set
funneling L4 header and sets `sport`/`dport` accordingly.

Examples:

```
funnel tcp dport 179 sport 540
```

> :sparkles: **Tip**
>
> You can reuse the same `sport` for all UDP or TCP traffic. Original
             `sport` and `dport` are preserved.

> :warning: **Warning**
>
> Make sure there isn't real traffic using `l4_funneling_proto`+`sport`+`dport`.<br>
> Make sure `l4_funneling_proto`+`sport`+`dport` is allowed in your firewall rules.

#### `unfunnel <l4_proto>`

Undo the `funnel`ing. The mandatory paramter `<l4_proto>` is eThe mandatory It must have the L4 protocol it

Example:

```
unfunnel tcp
```

#### `accept`

Don't touch the packet.

#### `drop`

Drop the packet.

## Scalability

### Number of rules

The current implementation is designed to handle fewer than 5 rules.

The use of statically allocated rules is an intentional design choice, as it
eliminates the need to orchestrate BPF maps ([see details here](container.md#life-cycle-and-garbage-collection)).
However, there are limits to the total amount of global data that a BPF program
can handle, which are enforced by the verifier. Experimentally, this translates
(today) in ~500 IPv4 rules.

The lookup algorithm is a simple linear search, which scales _very_ poorly once
the number of rules exceeds few tenths of rules.

There hasn't been (yet) a use-case for it, but if you are interested in
optimizing the lookup, or even conditionally (compile-time) use external BPF
maps, you can look into [lookup.h](../src/lookup.h) and send a PR.

---

_[1] To the best of my ability. AFAIK, there is no existing Python3 library to parse nftable filters._
