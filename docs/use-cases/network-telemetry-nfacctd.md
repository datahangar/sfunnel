# Multi-flow affinity in Kubernetes: making `nfacctd` K8s-ready with eBPF

This is the use-case that started this small project [[1](https://cilium.slack.com/archives/C1MATJ5U5/p1723579808788789)].

## Context
### pmacct and datahangar projects

[pmacct](https://github.com/pmacct/pmacct) is probably _the_ most widely
used Open Source project for passive monitoring of networks. `nfacctd` or
Network Flow ACCounting Daemon, collects flowlogs ([IPFIX](https://en.wikipedia.org/wiki/IP_Flow_Information_Export)/
[Netflow](https://en.wikipedia.org/wiki/NetFlow)/[Sflow](https://en.wikipedia.org/wiki/SFlow))
and enriches them, normalizes values etc. to later export it (e.g. to a DB or
a message bus).

One of the main features of `nfacctd` is to enrich flowlogs with [BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)
information, e.g. `AS_PATH`, `DST_AS`.

For doing so, `nfacctd` acts as a flowlog collector _and_, simultaneously, as a
BGP passive peer for one or more network routers:

![A network router connecting to nfacctd](images/single_router_nfacctd.svg)

[datahangar](https://github.com/datahangar/) was initially created as an
end-to-end(E2E) testing framework for pmacct, focusing on its containerization
and deployment in Kubernetes.

While it still fulfills [this role](https://github.com/pmacct/pmacct/blob/master/.github/workflows/e2e_dh.yaml),
datahangar is evolving towards establishing a reference architecture for a
complete network data pipeline using readily available open-source components in
Kubernetes.

### Connectivity requirements

BGP and flowlogs traffic must:

* Preserve source IP address. Source IP is used to deduce the router's identity.
* End up in the same Pod (replica).

![Proper multi-flow affinity working](images/lb_traffic_affinity_ok.svg)

### Typical deployment scenarios

Given the connectivity requirements, most `nfacctd` instances are deployed outside
Kubernetes today. The goal is to ensure that `nfacctd` can bedeployed and
scaled within a Kubernetes environment.

#### Public cloud

BGP and flowlogs traffic are typically tunneled through a VPN, Direct connect etc.
to the VPC. `nfacctd`'s are either deployed on-prem or in the VPC. In both cases,
they are  manually managed outside of K8s.

![Typical deployment on public clouds](images/deployment_vpc.svg)

### On-prem

Similarly:

![Typical deployment setup on-prem](images/deployment_onprem.svg)

## First attempt: `sessionAffinity: ClientIP` and `externalTrafficPolicy: Local`

The initial attempt to solve the connectivity requirements was to define a
`LoadBalancer` service as follows:

```
kind: Service
apiVersion: v1
metadata:
  name: nfacctd
spec:
  selector:
    app: nfacctd
  ports:
  - name: netflow
    protocol: UDP
    port: 2055
    targetPort: 2055
  - name: bgp
    protocol: TCP
    port: 179
    targetPort: 179
  type: LoadBalancer
  sessionAffinity: ClientIP
  externalTrafficPolicy: Local #Do not SNAT to the service!
```

The mockup test quickly shown that IP preservation worked in all cases,
but affinity didn't work with multiple replicas or multiple worker nodes... :disappointed:.
Flows coming from a router were hitting different Pods, including Pods in other
worker nodes.

![BPG and Flowlogs traffic end up in different pods](images/lb_traffic_no_affinity.svg)

So, what now? Implementing a new feature in Kubernetes, modify all NLBs, and
(potentially) all CNIs on the planet... Yeah, that’s not exactly a weekend
project :sweat_smile:.

## :bulb: What if...

What if could modify the traffic _before_ hitting the Network Load Balancer (NLB),
and disguise it as BGP (`TCP/179`), so that `sessionAffinity: ClientIP` would
do its job, and then "undo" this modification in the Pod, just before the traffic
is delivered to `nfacctd`? Humm, that _might_ work.

Time to go back to the drawing board...

## :honeybee: eBPF to the rescue!

### Funneling traffic through a single protocol and port

[eBPF](https://ebpf.io) is an extremely powerful technology for this sort of
purposes. The idea was to create an eBPF program `tc_funnel` that pushes a new
TCP header, and sets:

* `tcp.sport` to `179` (BGP)
* `tcp.sport` to `X` where X is a well-known port but unused port (to avoid
  colliding with tcp ephemeral ports, as some routers don't allow tweaking this).
  One example is `540` (`UUCP`).
* `tcp.flags`, `ack`, `seq` and `urg` to fixed values.

_Note: I used the term [funneling](../funneling.md) to not confuse it with a real tunnel_.

On the Pod side (inner), we would load another eBPF program that reverses the operation;
it matches `tcp dport 179 sport 540`, and pops the funneling header. The
diagram below shows the interception points for the VPC deployment type:

![VPC deployment with sfunnel](images/deployment_ebpf_sfunnel_vpc.svg)

_Note: funneling could also happen in the VPC GW, depending on the nature of it_

### XDP vs TC

XDP is generally more performant than TC programs, but only a single XDP program
can be attached to an interface at a time. To simplify deployment, and to allow
reusing `fwmark`, TC approach was chosen.

It shouldn't be complicated, thoughi, to improve the code to support both. This
might be interesting particularly for the funneling role.

### Show me the code! :honeybee:

The original prototype is [here](https://github.com/datahangar/sfunnel/tree/984813f57ea3248c8c64192663b3ab4aed84bb46/src);
[funnel.c](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/funnel.c) and
[unfunnel.c](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/unfunnel.c).

The code is fairly simple, and doesn't require much explanation. Perhaps the
only interesting bit is that L3 and L4 checksum calculations use [`bpf_csum_diff()`](https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_csum_diff/)
to reuse the original [IP](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/funnel.c#L38)
and [UDP checksum](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/funnel.c#L75)
calculation as a basis, saving some cycles. Unfunneling doesn't require L4
checksum recalculation.

#### Using an initContainer()

`sfunnel` container was originally packaged with the two sub-commands,
unfunneling by default. It is designed to run, attach the BPF program at startup,
and then end its execution.

The K8s deployment (or statefulset etc.), needed to be extended:

```diff
     spec:
       containers:
+        - name: sfunnel-init
+          image: sfunnel
+          securityContext:
+            privileged: true
+            capabilities:
+              add: [BPF, NET_ADMIN]
+          volumeMounts:
+            - name: bpffs
+              mountPath: /sys/fs/bpf

+     volumes:
+       - name: bpffs
+         hostPath:
+           path: /sys/fs/bpf``
```

The funneled ports could be then removed from the service definition
(e.g. UDP 4739).

#### Loading funneler (`tc_funnel`)

Loading the funneling code in the host namespace of a Linux GW was easy:

```shell
docker run --network=host --privileged sfunnel funnel
```

#### MTU considerations

`funneling` suffers from the same [MTU](../funneling.md#mtu) considerations as
with any other encapsulation.

For flowlogs, it is possible to adjust Netflow/IPFIX/sFlow configuration by
reducing the TX MTU by 20 bytes (TCP header). E.g. in JUNOS:

```
set services ipfix template template-name mtu 1480
```

## Conclusion and limitations

In short, it seems to works :tada:!

Considerations:

* You need sufficient permissions to run `sfunnel` initContainer as a privileged
  container. This is not possible in some managed K8s services, so this is not
  for everybody.
* Need for "funnelers"; flowlogs traffic needs to be modified before reaching
  the NLB. This can be done in the VPC GW or before it reaches the public cloud.
  It can also be done by pointing routers to an intermediate "flowlogs proxy" by
  then DNATing the traffic.
* [MTU considerations](../funneling.md#mtu) apply, but are easily solved
  by adjusting the router configuration for IPFIX/NetFlow/sFlow as discussed
  before.
* It should be possible to implement the unfunneling part as a feature in a CNI
  like Cilium.

## Acknowledgments

Thank you to Martynas Pumputis, Chance Zibolski and Daniel Borkmann for their
support in the Cilium community.
