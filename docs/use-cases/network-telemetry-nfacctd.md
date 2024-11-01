# Multi-port session affinity in K8s: making `nfacctd` K8s-ready with eBPF

This use case initiated this small project [[1](https://cilium.slack.com/archives/C1MATJ5U5/p1723579808788789)].

## Context
### Pmacct and Datahangar projects

[pmacct](https://github.com/pmacct/pmacct) is probably the most widely
used open-source project for passive network monitoring. The Network Flow
ACCounting Daemon (`nfacctd`) collects flowlogs ([IPFIX](https://en.wikipedia.org/wiki/IP_Flow_Information_Export)/
[Netflow](https://en.wikipedia.org/wiki/NetFlow)/[Sflow](https://en.wikipedia.org/wiki/SFlow)),
enriches and normalizes them, and then exports data to a database or a message
bus.

A key feature of `nfacctd` is its ability to enrich flowlogs with [BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)
information, such `AS_PATH` or `DST_AS`.

To achieve this, `nfacctd` acts both as a flowlog collector _and_, simultaneously,
as a BGP passive peer for one or more network routers:

![A network router connecting to nfacctd](images/single_router_nfacctd.svg)

On the other hand, [datahangar](https://github.com/datahangar/) was initially
created as an end-to-end(E2E) testing framework for pmacct, focusing on its
containerization and deployment in Kubernetes.

While it still fulfills [this role](https://github.com/pmacct/pmacct/blob/master/.github/workflows/e2e_dh.yaml),
datahangar is evolving into establishing a reference architecture for a
complete network data pipeline running in Kubernetes using readily available
open-source components.

### Connectivity requirements

For `nfacctd` to function, BGP and flowlog traffic must:

* Preserve source IP address. Source IP is used to deduce the router's identity.
* End up in the same Pod (replica).

![Proper multi-flow affinity working](images/lb_traffic_affinity_ok.svg)

### Typical deployment scenarios

For an overview of common `nfacctd` deployment scenarios today, refer to [this](current-nfacctd-deployments.md).

## First attempt: `sessionAffinity: ClientIP` and `externalTrafficPolicy: Local`

The initial attempt to meet the connectivity requirements involved defining a
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
  externalTrafficPolicy: Local #Do not SNAT traffic
```

Testing revealed that IP preservation worked (as long as you have at least one
pod on each worker-node), but session affinity didn't function with multiple
replicas or multiple worker nodes... :disappointed:. Traffic coming from a router
was hitting different Pods, including Pods in other worker nodes:

![BPG and Flowlogs traffic end up in different pods](images/lb_traffic_no_affinity.svg)

So, what now? Implementing a new feature in Kubernetes, modify all NLBs, and
(potentially) all CNIs on the planet... Yeah, that’s not exactly a weekend
project :sweat_smile:.

## :bulb: What if...

What if traffic could be modified  _before_ hitting the Network Load Balancer (NLB),
disguising it as BGP (`TCP/179`) so that `sessionAffinity: ClientIP` could
do its job, and then "undo" this modification in the Pod just before delivering
the traffic to `nfacctd`? Humm... this _might_ work.

Time to go back to the drawing board...

## :honeybee: eBPF to the rescue!

### Funneling traffic through a single protocol and port

[eBPF](https://ebpf.io) is an extremely powerful technology for this sort of
problems. The plan was to create an eBPF program, `tc_funnel`, that pushes a new
TCP header, and sets:

* `tcp.sport` to `179` (BGP)
* `tcp.sport` to `X` where X is a well-known port but unused port (to avoid
  colliding with tcp ephemeral ports, as some routers don't allow tweaking this).
  One example is `540` (`UUCP`).
* `tcp.flags`, `ack`, `seq` and `urg` to fixed values.

_Note: the term [funneling](../funneling.md) is used to distinguish it from real tunneling._

On the Pod side (Pod's network namespace), the eBPF program reverses this operation
by matching `tcp dport 179 sport 540` and popps the funneling header. The following
diagram illustrates the interception points for the VPC deployment type:

![VPC deployment with sfunnel](images/deployment_ebpf_sfunnel_vpc.svg)

_Note: funneling could also occur in the VPC GW, depending on the nature of the
gateway itself._

### XDP vs TC

XDP generally offers better performance than TC programs, but only allows a single
program per interface. For simplicity and to enable the use of `fwmark`,
the TC approach was chosen.

It shouldn't be complicated, though, to improve the code to support both. This
might be particularly interesting for the funneling role.

### Show me the code! :honeybee:

The original prototype can be found [here](https://github.com/datahangar/sfunnel/tree/984813f57ea3248c8c64192663b3ab4aed84bb46/src);
[funnel.c](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/funnel.c) and
[unfunnel.c](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/unfunnel.c).

The code is fairly simple, and doesn't require much explanation. The only
interesting bits have to do with the L3 and L4 checksum calculations, which use [`bpf_csum_diff()`](https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_csum_diff/)
to reuse the original [IP](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/funnel.c#L38)
and [UDP checksum](https://github.com/datahangar/sfunnel/blob/984813f57ea3248c8c64192663b3ab4aed84bb46/src/funnel.c#L75)
saving some processing cycles.

_Note: this was added later on, and was not part of the original prototype_

At the same time, and in order to properly traverse NATs, during funneling the
original L4 checksum is adjusted with `src_ip` and `dst_ip` set to a known value
(`0x0`). This allows the unfunneling code to readjust the checksum based on the
diff between the known value `0x0` and the actual IP addresses of the packet at
this point, without the need to pass extra state within the packet.

#### Using an init container

`sfunnel` container was originally packaged with the two sub-commands,
defaulting to unfunneling. It is designed to run, attach the BPF program at
startup, and then terminate.

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
+           path: /sys/fs/bpf
```

The funneled ports could then be removed from the service definition
(e.g. UDP 4739).

#### Loading funneler (`tc_funnel`)

Loading the funneling code in the host namespace of a Linux gateway:

```shell
docker run --network=host --privileged sfunnel funnel
```

#### MTU considerations

`funneling` faces the same [MTU](../funneling.md#mtu) issues as other encapsulation
methods.

For flowlogs, you can adjust Netflow/IPFIX/sFlow configuration by reducing the
TX MTU by 20 bytes (TCP header). E.g. in JUNOS:

```
set services ipfix template template-name mtu 1480
```

## Conclusion and limitations

In short, it appears to work :tada:!

Considerations:

* **Permissions**: You need sufficient permissions to run `sfunnel` init container
  as a privileged container. This is not possible in some managed K8s services,
  so this is not for everybody.
* **Funnelers**: Flowlogs traffic needs to be modified before reaching
  the NLB, which can be done in the VPC gateway or before it reaches the public
  cloud. It can also be done by pointing routers to an intermediate "flowlogs proxy"
  and then DNATing the traffic to the K8s Service.
* **[MTU considerations](../funneling.md#mtu)** apply, but are easily solved
  by adjusting the router configuration for IPFIX/NetFlow/sFlow as discussed
  before.
* **Future work:** It is possible to implement the unfunneling part as a feature
  (CRD) in a CNI like Cilium, so that no especial permissions are required.

## Acknowledgments

Thanks to Martynas Pumputis, Chance Zibolski and Daniel Borkmann for their
support in the Cilium community.
