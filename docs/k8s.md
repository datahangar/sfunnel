# Deploying `sfunnel` in K8s

Deploying `sfunnel` as an `initContainer` is straight forward (see [1]),
provided that you have the [right privileges](#capabilities).

For `sfunnel` to work, Services must - obviously - be defined with
`sessionAffinity: ClientIP` in first place. `sfunnel` will attach the eBPF
program to the Pod's `$IFACES`.

> :pencil: **Note**
>
> Make sure to adjust the [MTU](funneling.md#mtu)

## Services

### `LoadBalancer`

Traffic must hit the LB funneled. Therefore, traffic must have been either
generated or routed through a node running `sfunnel` with funneling rules.

`LoadBalancer` services honouring `sessionAffinity: ClientIP` will send traffic
from the tuple {`srcIP`, `protocol`, `srcPort`, `DstPort`} to the same Worker
Node.

In turn, CNIs supporting `sessionAffinity: ClientIP` will send traffic for the
tuple {`srcIP`, `protocol`, `srcPort`, `DstPort`} to the same Pod (until rescheduled).
Traffic entering the Pod Network Namespace will be unfunnel/demultiplexed before
being terminated by the Kernel, and delivered to sockets.

### `NodePort`

Similarly, traffic needs to hit the Worker Node funneled. You could theoretically
run funneling rules _before_ the CNI does its magic, but this is tricky and it's
NOT recommended.

It goes without saying that traffic needs to hit the _right_ `NodePort` for the same
{`srcIP`, `protocol`, `srcPort`, `DstPort`}, otherwise `sessionAffinity: ClientIP`
wouldn't work (even for a single port) in first place.

The process is then the exact same as with the `LoadBalancer` service.

### `ClusterIP`

> :warning: **Warning**
>
> This hasn't been tested, so take it as a plausible conjecture.

This is an interesting one, and not anticipated, as the
[original use-case](docs/use-cases/network-telemetry-nfacctd.md) only used
`LoadBalancer` services.

You can funnel multiple `ClusterIP` services - with multiple ports - into a
single protocol+port, provided that are backed by the same Pod. This effectively
makes all flows from a consumer Pod A talk to the same backend Pod B
until there is a rescheduling.

An example:

Pod A (consumer) ruleset:
```
ip daddr <ClusterIP_1> tcp dport 443  funnel tcp dport 80 sport 540  # HTTPs
ip daddr <ClusterIP_2> tcp dport 8080 funnel tcp dport 80 sport 540  # Proxy HTTP
ip daddr <ClusterIP_3> udp dport 443  funnel udp dport 80 sport 541  # QUIC
```

Pod B (backend) ruleset:
```
tcp dport 80 sport 540 unfunnel tcp
tcp dport 80 sport 541 unfunnel udp
```

## Supported CNIs

In principle, any CNI and LB honouring `sessionAffinity: ClientIP` should work
out of the box.

`sfunnel` has been tested with Cilium v1.15 and v1.16.

## Container life-cycle

`sfunnel` is designed to run as an ephemeral initContainer. Upon startup, the
container will attach sfunnel BPF program and exit.

In the event of a Pod being restarted or teared down, the BPF subsystem will
automatically unload the BPF program during virtual interface destruction.

## Security considerations

### Capabilities: `CAP_BPF`, `CAP_NET_ADMIN`

`sfunnel` requires elevated privileges to run and load BPF TC programs.

### Digest

> :heavy_exclamation_mark: **Important**
>
> ALWAYS check `sfunnel`'s image `sha256` when running in production.

E.g.:
```
  image: ghcr.io/datahangar/sfunnel:0.0.3@sha256:f4f72e64a93f7543e33000d01807fb66257cc88165b580763726aa4a01302655
```

---

##### [1] Example

See [example](../example/k8s/) for a small example.
