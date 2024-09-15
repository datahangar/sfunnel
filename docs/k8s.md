# Deploying `sfunnel` in K8s

Deploying `sfunnel` as an [init container](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
is straight forward (see [1]), as long as you have the
[necessary privileges](#security-considerations).

For `sfunnel` to work, Services must be defined with `sessionAffinity: ClientIP`.
`sfunnel` will then attach the eBPF program to the Pod's specified network
interfaces (`$IFACES`).

> :pencil: **Note**
>
> Ensure that the [MTU](funneling.md#mtu) is adjusted accordingly.

## Services

### `LoadBalancer`

Traffic must hit the Network Load Balancer already funneled. Traffic, therefore,
 must either be generated or routed through a node running `sfunnel` with the
appropriate funneling rules in place.

`LoadBalancer` services honouring `sessionAffinity: ClientIP` will consistently
send traffic from the tuple {`srcIP`, `protocol`, `srcPort`, `DstPort`} to the
same Worker Node.

In turn, CNIs supporting `sessionAffinity: ClientIP` will send traffic for the
same tuple to the same Pod (until a rescheduled event happens). Once traffic enters
the Pod's network namespace, it will be "unfunneled" (demultiplexed) before
being terminated by the Kernel and delivered to sockets.

### `NodePort`

Similarly, traffic needs to hit the Worker Node already funneled. While it is
theoretically possible to apply funneling rules _before_ the CNI does its magic,
this is complex and **not recommended**.

> Note: it goes without saying that traffic needs to hit the _right_ `NodePort` for the same
{`srcIP`, `protocol`, `srcPort`, `DstPort`}, otherwise `sessionAffinity: ClientIP`
wouldn't work (even for a single port) in first place.

From this point on, the flow is the same as in the `LoadBalancer` service case.

### `ClusterIP`

> :warning: **Warning**
>
> This hasn't been tested, so take it as a plausible conjecture.

This is an interesting one, and not anticipated, as the
[original use-case](docs/use-cases/network-telemetry-nfacctd.md) only used
`LoadBalancer` services.

You can funnel traffic from multiple `ClusterIP`(non headless) services -
with multiple ports - into a single protocol+port, as long as they are backed
by the same pods. This effectively routes all flows (of that service) from a
consumer Pod A talk to the same backend Pod B until there is a rescheduling.

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

Any CNI and LB honouring `sessionAffinity: ClientIP` should work
out of the box.

`sfunnel` has been tested with Cilium v1.15 and v1.16.

## Container life-cycle

`sfunnel` is designed to run as an ephemeral init container. Upon startup, the
container will attach sfunnel BPF program and exit.

In the event of a Pod being restarted or teared down, the BPF subsystem will
automatically unload the BPF program during virtual interface destruction.

## Security considerations

`sfunnel` requires to run with elevated privileges, specifically:

* Capabilities: `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`.
* Mount `/sys/fs/bpf` in the init container.

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
