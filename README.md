# sfunnel: multi-port/multi-flow session affinity in Kubernetes

`sfunnel` is an [eBPF](https://ebpf.io/) program designed to [funnel](docs/funneling.md)
multiple traffic flows through a single Kubernetes service _port_, ensuring
[under certain conditions](#requirements) consistent `sessionAffinity: ClientIP`
affinity across all _ports_ within the service.

See the original use-case [here](docs/use-cases/network-telemetry-nfacctd.md).

:warning: While `sfunnel` should be fully functional, and has been [validated](#tested-environments),
it is still in an early development stage.

## At a glance

Example where `TCP/8080` traffic is funneled through `TCP/80`.

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
+          image: ghcr.io/datahangar/sfunnel:0.0.11@sha256:5f130c2bfc95fb0d264ad54c52b1fef26c58e5635f11b8b862efe611b98b1f9a
+          securityContext:
+            privileged: false #Set to true for some public clouds (e.g. GKE standard)
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
+     volumes:
+       - name: bpffs
+         hostPath:
+           path: /sys/fs/bpf
```
(_Note: funneling HTTPs `TCP/443` through `TCP/80` would work the same way. Manifest
is just too long for this example_)

On the other end (e.g. a Linux host, server etc..), deploy it with the
matching [rules](docs/rules.md):

```shell
SFUNNEL_RULESET="ip daddr <your LB IP1> tcp port 443 actions funnel tcp dport 80 sport 540;\
  ip daddr <your LB IP1> tcp port 8080 actions funnel tcp dport 80 sport 540"
docker run --network="host" --privileged -e SFUNNEL_RULESET="$SFUNNEL_RULESET" sfunnel
```

The `sfunnel` container will run, load the eBPF code and finish its execution.

## Tested environments

* **Google Kubernetes Engine(GKE)**: Standard cluster.
   - Autopilot clusters are _not supported_ due to lack of eBPF support.
* **MetalLB** with the following CNI plugins:
  * Cilium
  * Flannel
  * Calico
* **Dockerd**

`sfunnel` should work on any environments supporting `sessionAffinity: ClientIP`.
If you encounter any issues or have successfully deployed it in other
environments, please reach out so that we can update this list.

## Requirements

* [eBPF](https://ebpf.io/)-enabled kernel, with support for `clsact` and `direct-action`.
* Proper [MTU configuration](docs/funneling.md#mtu) (20 bytes for TCP, 8 for UDP).
* In Kubernetes:
  * Privileged init container (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
    * In some cloud providers (E.g. Google Cloud) `privileged=true` is required.
* On the funneling side:
  * Permissions to spawn `sfunnel` (same caps as before).
  * Route or proxy traffic to be funneled. More on this [here](docs/funneling.md)

## More...

* [Use-cases](docs/use-cases/)
* [Funneling?](docs/funneling.md)
* [Rule syntax](docs/rules.md)
* [sfunnel container](docs/container.md)
* [Deploying it in K8s](docs/k8s.md)
* [Next steps](../../issues?q=is%3Aissue+is%3Aopen+label%3Afeature)

Contact
-------

Marc Sune < marcdevel (at) gmail (dot) com>
