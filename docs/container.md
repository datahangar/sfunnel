# `sfunnel` container

The `sfunnel` container is designed to load the `tc_funnel` eBPF program onto
specified network interface and then immediately exit. It can be deployed as
an [init container in K8s](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
or as a short-lived (ephemeral) container in Docker (e.g. to load funneling rules
in the host namespace `docker --network="host"`).

When the container starts, it performs the following actions:

1. Recompiles the BPF program with the ruleset provided. The ruleset is static
   at compile-time, so no [BPF maps](https://docs.kernel.org/bpf/maps.html)
   are needed. Mind the [ruleset limitations](rules.md#scalability).
1. For each interface specified in `$IFACES`, the container will:
  * create a `clasct` qdisc
  * Attach the BPF program to ithe qdisc

## Environment variables

Several environment variables can be used to control the behaviour of the `sfunnel`
container:

* `$SFUNNEL_RULESET`: the list of rules. This variable takes precedence over `/etc/sfunnel/ruleset`.
* `$IFACES`: interfaces to load the BPF program to. Default: "" (all).
* `DIRECTION`: specifies the direction {`ingress`, `egress`, `both`} for attaching the BPF program.
   For most use-cases, ingress is sufficient. Default: "ingress".

### Advanced

* `NETNS`: if set, attach the BPF program to `$IFACES` in the `$NETNS` network namespace
   instead of the default container's network namespace. Default: "" (container namespace).
   Note: `/var/run/netns` must be mounted as a volume.
* `CLEAN`: when set to `1`, instead of loading sfunnel, remove **all** TC eBPF
   programs attached to `$DIRECTION` on `$IFACES`. Default: 0.
* `$DEBUG`: enable BPF `printk` traces. :warning: severly affects performance!
* `$N_ATTEMPTS`: number of attempts to load the BPF program on an interface. Default is 6.
* `$RETRY_DELAY`: delay between retry attemps. Default is 3.

## Loading Ruleset via file `/etc/sfunnel/ruleset`

The ruleset can be loaded via configmap (K8s) or a docker volume by creating
the file `/etc/sfunnel/ruleset`.
