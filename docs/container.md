# `sfunnel` container

The `sfunnel` container is meant to run as an initContainer() or as an ephemeral
container (in `docker --network="host"`).

Upon starting, it will:

1. Recompile the BPF program if a custom ruleset is provided. Ruleset is static
   at compile-time, so no maps are needed. Mind the [ruleset limits](rules.md#scalability).
1. For each interface in `$IFACES`:
  * it creates a `clasct` qdisc
  * it attached the BPF program to it

## Environment variables

Some ENV variables control the behaviour of the container:

* `$DEBUG`: dump BPF `printk` traces. :warning: severly affects performance!
* `$SFUNNEL_RULESET`: list of rules. This variable has precedence over `/opt/sfunnel/src/ruleset`.
* `$IFACES`: interfaces to load the BPF program. Default: "" (all).
* `$N_ATTEMPTS`: number of attempts on loading the BPF program on an interface. Default 6.
* `$RETRY_DELAY`: delay between attemps. Default: 3.

## Loading Ruleset via file

The ruleset can be loaded via configmap/docker volume by creating the file `ruleset`
in `/opt/sfunnel/src`. This file has precedence over `/opt/sfunnel/src/ruleset.defaults`.
