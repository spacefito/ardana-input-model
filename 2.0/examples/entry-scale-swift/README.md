<!--
(c) Copyright 2015 Hewlett Packard Enterprise Development LP
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

## Entry Scale Swift Cloud

This example input model deploys an entry scale Swift environment.

### Control Planes

- Core cluster: 3 nodes of type CONTROLLER-ROLE run Swift and other supporting
  services.

### Lifecycle Manager

  The lifecycle-manager runs on one of the control-plane nodes. The ip address
  of the node that will run the lifecycle-manager needs to be included in the
  `data/servers.yml` file.

### Resource Nodes

- Object storage: 3 nodes of type SWOBJ-ROLE provide the Swift object storage.

*Additional resource nodes can be added to the configuration.*

### Networking

This example requires the following networks:

- IPMI/iLO: network connected to the lifecycle-manager and the IPMI/iLO ports
  of all servers.

- External API - This is the network that users will use to make requests to
  the cloud.

- Cloud Management - This is the network that will be used for all internal
  traffic between the cloud services. This network is also used to install and
  configure the controller nodes only. This network needs to be on an untagged
  VLAN.

- SWIFT - This network is used for internal Swift communications between the
  Swift servers.

An example set of networks is defined in `data/networks.yml`, which needs to be
modified to reflect your environment.

The example uses the devices `hed3` & `hed4` as a bonded network interface
for all services. The name given to a network interface by the system is
configured in the file `data/net_interfaces.yml`. That file needs to be
edited to match your system.

### Local Storage

All servers should present a single OS disk, protected by a RAID controller.
This disk needs to be at least 512GB. In addition the example configures
additional disks depending on the role of the server:

- Controllers:  `/dev/sdb` and `/dev/sdc` are configured to be used by
  Swift account and container services

- Object Servers:  `/dev/sdb`, `/dev/sdc`, `/dev/sdd` and `/dev/sde` are
  configured to be used by the Swift object service.

Additional disks can be configured for any of these roles by editing the
corresponding `data/disks_*.yml` file.
