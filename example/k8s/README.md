# K8s example

This example showcases how to provide multi-port/flow affinity between
two HTTP services, one in HTTP port 80 and another in 8080.

Apply the web server and service manifests:

```
kubectl apply -k .
```
The web server returns its hostname (pod name) as part of the
HTTP GET response.

## Testing the LoadBalancer service

For affinity to work, traffic needs to be intercepted before it hits the LoadBalancer.

Load the following sfunnel programs to your egress interface (e.g. `eth0`)

##### Ingress:

```
IFACES=eth0 LB_IP=1.1.1.1 \
SFUNNEL_RULESET="ip daddr ${LB_IP} tcp dport 8080 actions funnel tcp dport 80 sport 540" \
docker run --privileged --network=host -it -e IFACES -e DIRECTION="egress" -e SFUNNEL_RULESET ghcr.io/datahangar/sfunnel:0.0.11
```
##### Egress


```
IFACES=eth0 LB_IP=1.1.1.1 \
SFUNNEL_RULESET="ip saddr ${LB_IP} tcp sport 80 dport 540 actions unfunnel tcp" \
docker run --privileged --network=host -it -e IFACES -e DIRECTION="ingress" -e SFUNNEL_RULESET ghcr.io/datahangar/sfunnel:0.0.11
```

##### Cleanup

You detach both programs by running:

```
IFACES=eth0 \
docker run --privileged --network=host -it -e IFACES -e DIRECTION="both" -e CLEAN=1 ghcr.io/datahangar/sfunnel:0.0.11
```

## Testing the ClusterIP service

Apply the `client.yaml` (not part of kustomize):

```
kubectl apply -f client.yaml
```

`client.yaml` contains a simple script that `curl`s both HTTP/80 and
HTTP/8080 and verifies that both hostnames match.

:warning: Please note the [known issues](#) with Cilium in non-KPR mode
