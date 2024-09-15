# Current `nfacctd` deployment scenarios

Given the [connectivity requirements](network-telemetry-nfacctd.md#connectivity-requirements),
most `nfacctd` instances are currently deployed outside Kubernetes. The goal is
to ensure that `nfacctd` can be deployed and scaled within a Kubernetes
environment.

## Public cloud

In public cloud environments, BGP and flowlogs traffic are typically tunneled
to the VPC through a VPN, Direct connect etc. `nfacctd` instances are deployed
either on-premises or within the VPC, and are manually managed outside of
Kubernetes.

![Typical deployment on public clouds](images/deployment_vpc.svg)

## On-prem

Similarly:

![Typical deployment setup on-prem](images/deployment_onprem.svg)
