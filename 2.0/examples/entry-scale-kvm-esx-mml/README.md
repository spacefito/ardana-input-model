<!--
(c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

## Entry Scale Cloud with Metering & Monitoring Services and a Mix of KVM & ESX Hypervisors

This example input model deploys an entry scale cloud that mixes KVM and ESX
hypervisors, provides Metering & Monitoring services, and runs the database and
messaging services in their own cluster.

### Control Plane

- Cluster1: 2 nodes of type CONTROLLER-ROLE run the core OpenStack
  services such as Keystone, Nova, Glance, Neutron, Horizon, Heat, Ceilometer,
  block storage, and object storage.

- Cluster2: 3 nodes of type MTRMON-ROLE run the OpenStack services for
  metering & monitoring (ceilometer, monasca & logging).

- Cluster3: 3 nodes of type DBMQ-ROLE run clustered database and RabbitMQ
  services to support the cloud infrastructure. Three nodes are required for
  high availability.

### Lifecycle Manager

  The lifecycle-manager runs on one of the control-plane nodes of type
  CONTROLLER-ROLE. The ip address of the node that will run the
  lifecycle-manager needs to be included in the `data/servers.yml` file.

### Resource Nodes

- Compute:
    - KVM: Runs nova-compute and associated services. Runs on nodes of role
           type COMPUTE-ROLE.
    - ESX: Provides ESX compute services. OS and software on this node is
           to be installed by user.

### ESX resource requirements

1. *User needs to supply vSphere server*

2. *User needs to deploy the ovsvapp network resources using the
 neutron-create-ovsvapp-resources.yml playbook*

   The following DVS and DVPGs need to be created and configured for each
   cluster in each ESX hypervisor that will host an OvsVapp appliance. The
   settings for each DVS and DVPG are particular to your system and network
   policies. A json file example is provided in the documentation, but it will
   have to be edited to match your requirements.

   - ESX-CONF (DVS and DVPG) connected to ovsvapp eth0 and compute-proxy eth0

   - MANAGEMENT (DVS and DVPG) connected to ovsvapp eth1 and compute-proxy eth1

   - GUEST (DVS and DVPG) connected to ovsvapp eth2

   - TRUNK (DVS and DVPG) connected to ovsvapp eth3

3. *User needs to deploy ovsvapp appliance (OVSVAPP-ROLE) and
 nova-proxy appliance (ESX-COMPUTE-ROLE)*

4. *User needs to add required information related to compute proxy and
 OVSvApp Nodes*

### Networking

This example requires the following networks:

- IPMI/iLO: network connected to the lifecycle-manager and the IPMI/iLO ports
  of all nodes except the ESX hypervisors.

- External API - This is the network that users will use to make requests to
  the cloud.

- External VM - This is the network that will be used to provide access to VMs
  (via floating IP addresses).

- Guest - This is the network that will carry traffic between VMs on private
  networks within the cloud.

- Cloud Management - This is the network that will be used for all internal
  traffic between cloud services. This network is also used to install and
  configure nodes. This network needs to be on an untagged VLAN.

- TRUNK is the network that will be used to apply security group rules
  on tenant traffic. It is managed by the cloud admin and is restricted
  to the vCenter environment.

- ESX-CONF-NET network is used only to configure the ESX compute nodes in the
  cloud. This network should be different from the network used with PXE to
  stand up the cloud control-plane.

This example's set of networks is defined in `data/networks.yml`. This file
needs to be modified to reflect your environment.

This example uses `hed3` & `hed4` as a bonded network interface for all nodes.
The name given to a network interface by the system is configured in the file
`data/net_interfaces.yml`. That file needs to be modified to match your
system.

### Local Storage

All nodes should present a single OS disk, protected by a RAID controller.
The disk needs to be at least 512GB. In addition, the example configures
additional disks depending on the node's role:

- CONTROLLER-ROLE: `/dev/sdb` is configured to be used by Swift.

- COMPUTE-ROLE: `/dev/sdb` is configured as an additional Volume Group to be
  used for VM storage.

Additional disks can be configured for any of the roles by editing the
corresponding `data/disks_*.yml` file.
