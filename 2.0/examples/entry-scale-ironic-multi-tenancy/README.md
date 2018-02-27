<!--
(c) Copyright 2017 Hewlett Packard Enterprise Development LP
(c) Copyright 2017-2018 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
-->

## Entry Scale Cloud with Ironic Multi-tenancy

This example input model deploys an entry scale cloud that uses the Ironic
service to provision physical machines through the Compute services API and
supports multi-tenancy.

### Control Plane

- Cluster1: 3 nodes of type CONTROLLER-ROLE run the core OpenStack
  services such as Keystone, Nova, Glance, Neutron, Horizon, Heat,
  Ceilometer, block storage, and object storage.

### Lifecycle Manager

  The lifecycle-manager runs on one of the control-plane nodes of type
  CONTROLLER-ROLE. The ip address of the node that will run the
  lifecycle-manager needs to be included in the `data/servers.yml` file.

### Resource Nodes

- Ironic Compute: One node of type IRONIC-COMPUTE-ROLE runs nova-compute,
  nova-compute-ironic and other supporting services.

- Object Storage: Minimal Swift Resources are provided by the control plane.

### Networking

This example requires the following networks:

- IPMI/iLO network, connected to the deployer and the IPMI/iLO ports of all
  nodes.

- External API - This is the network that users will use to make requests
  to the cloud.

- Cloud Management - This is the network that will be used for all internal
  traffic between cloud services. This network is also used to install and
  configure the controller nodes. This network needs to be on an untagged
  VLAN.

- Provisioning - This is the network used to PXE boot the Ironic nodes and
  install the operating system selected by tenants. This network needs to be
  tagged on the switch for control plane/Ironic compute nodes. For
  Ironic bare metal nodes, VLAN configuration on the switch will be set by
  neutron driver.

- Tenant VLANs - The range of VLAN IDs should be reserved for use by Ironic and
  set in the cloud configuration. It is configured as untagged on control plane
  nodes, therefore it cannot be combined with Management network on the same
  network interface.

The following access should be allowed by routing/firewall:

- Access from Management network to IPMI/iLO. Used during cloud installation
  and during Ironic bare metal node provisioning.

- Access from Management network to switch management network. Used by neutron
  driver.

- EXTERNAL\_API network must be reachable from the tenant networks for bare
  metal nodes to be able to make API calls to the cloud.

This example's set of networks is defined in `data/networks.yml`. You will
need to modify this file to reflect your environment.

The example uses `hed3` for Management and External API traffic, and `hed4` for
provisioning and tenant network traffic. If these assignments need to be
modified for your environment, they are defined in `data/net_interfaces.yml`.

The name given to a network interface by the system is configured in the file
`data/net_interfaces.yml`. That file needs to be modified to match your
system.

### Local Storage

All nodes should present a single OS disk, protected by a RAID controller.
This disk needs to be at least 512GB. In addition, the example
configures additional disks depending on the node's role:

- CONTROLLER-ROLE:  `/dev/sdb` and `/dev/sdc` are configured to be used by Swift

Additional disks can be configured for any of the roles by editing the
corresponding `data/disks_*.yml` file.
