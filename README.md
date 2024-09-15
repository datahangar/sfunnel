# sfunnel: multi-port/multi-flow session affinity in Kubernetes

`sfunnel` is an [eBPF](https://ebpf.io/) tool designed to [_funnel_](docs/funneling)
multiple traffic flows through a single [Kubernetes service](https://kubernetes.io/docs/concepts/services-networking/service/)
_port_, ensuring - under [certain conditions](#requirements) - consistent
`sessionAffinity: ClientIP` affinity across all _ports_ within the service.

See the original use-case [here](docs/use-cases/network-telemetry-nfacctd.md).

## At a glance

Example where `TCP/8080` and `TCP/443` traffic is funneled through `TCP/80`.

Remove _ports_ from the K8s service and e.g. deployment. Add the `sfunnel`
container along with the [rules](docs/rules.md) in `SFUNNEL_RULESET`:

```diff
--- a/service.yaml
+++ b/service.yaml
@@ -1,18 +1,12 @@
 apiVersion: v1
 kind: Service
 metadata:
   name: my-loadbalancer-service
 spec:
   type: LoadBalancer
   selector:
     app: my-nginx-app
   ports:
     - protocol: TCP
       port: 80
       targetPort: 80
-    - protocol: TCP
-      port: 8080
-      targetPort: 8080
-    - protocol: TCP
-      port: 443
-      targetPort: 443
   sessionAffinity: ClientIP
```

```diff
--- a/nginx.yaml
+++ b/nginx.yaml
@@ -1,21 +1,31 @@
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: my-nginx-deployment
 spec:
   replicas: 4
   selector:
     matchLabels:
       app: my-nginx-app
   template:
     metadata:
       labels:
         app: my-nginx-app
     spec:
       containers:
+        - name: sfunnel-init
+          env:
+            - name: SFUNNEL_RULESET
+              value: ip tcp dport 80 sport 540 actions unfunnel tcp
+          image: ghcr.io/datahangar/sfunnel:0.0.4@sha256:78c7c8cdd7a299781a7139f28cd5cffef9e17866d2dcb62d049bad0f0a059f2f
+          securityContext:
+            privileged: false
+            capabilities:
+              add: [BPF, NET_ADMIN, SYS_ADMIN]
+          volumeMounts:
+            - name: bpffs
+              mountPath: /sys/fs/bpf
         - name: nginx
           image: nginx:latest
           ports:
             - containerPort: 80
-            - containerPort: 8080
-            - containerPort: 443
+     volumes:
+       - name: bpffs
+         hostPath:
+           path: /sys/fs/bpf
```

On the other end (e.g. a Linux host, server etc..), deploy it with the
matching [rules](docs/rules.md):

```shell
SFUNNEL_RULESET="ip daddr <your LB IP1> tcp port 443 actions funnel tcp dport 80 sport 540;\
  ip daddr <your LB IP1> tcp port 8080 actions funnel tcp dport 80 sport 540"
docker run --network="host" --privileged -e SFUNNEL_RULESET="$SFUNNEL_RULESET" sfunnel
```

The `sfunnel` container will run, load the eBPF code and finish its execution.

##### More use-cases

This is a simple example yet not very useful example. See [use-cases](docs/use-cases/)
for real world examples.

## Requirements

* In Kubernetes:
  * Privileged init container (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
  * [eBPF](https://ebpf.io/)-enabled kernel, with support for `clsact` and `direct-action`.
  * Proper [MTU configuration](docs/funneling.md#mtu) (20 bytes for TCP, 8 for UDP).
* On the funneling side:
  * Permissions to spawn `sfunnel` (same caps as before).
  * Route or proxy traffic to be funneled. More on this [here](docs/funneling.md)
  * Proper [MTU configuration](docs/funneling.md#mtu) (20 bytes for TCP, 8 for UDP).

Make sure stateful firewalls and IDS/IDPS are properly configured to allow this
type of traffic.

## More...

* [Use-cases](docs/use-cases/)
* [Funneling?](docs/funneling.md)
* [Rule syntax](docs/rules.md)
* [sfunnel container](docs/container.md)
* [Deploying it in K8s](docs/k8s.md)
* [Next steps](docs/next_steps.md)

Contact
-------

Marc Sune < marcdevel (at) gmail (dot) com>
