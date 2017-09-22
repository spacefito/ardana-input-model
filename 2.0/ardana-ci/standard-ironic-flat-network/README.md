(c) Copyright 2016 Hewlett Packard Enterprise Development LP
(c) Copyright 2017 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.


##Ardana Standard Cloud with Ironic Example##

The input files in this folder are ment to deploy a simulated bare metal cloud
with ironic that has the following characteristics:

### Control Planes ###

- A single control plane consisting of three servers that redundantly host all of the
  required services.

###Resource Pools###

*Minimal Swift Resources are provided by the control plane*

*Additional ironic bare metal nodes resource nodes can be added later by using Ironic API.*

###Lifecycle Manager###

This configuration runs the lifecycle-manager on a control plane node. You need to include
this node address in your servers.yml definition.
This function does not need a dedicated network.

*The minimum server count for this example is therefore 4 servers
(Control Plane (x3) + 1 nova-compute proxy.*
*(Additional bare metal nodes will be added after deployment via the Ironic API)*


An example set of servers are defined in ***data/servers.yml***. You may wish to modify
this file to reflect your specific environment.


###Networking###

The example requires the following networks:

- Management - This is the network that will be used for all internal traffic
  between the cloud services. This network is also used to install and configure the
  controller nodes only.
  This network needs to be on an untagged VLAN

- Guest - This is the flat network that will carry traffic between bare metal instances within
  the cloud. This is also the network used to PXE boot the ironic nodes and install the
  operating system selected by tenants.

- EXT-NET - This network is used to provide external access to the bare metal nodes.


###Local Storage###

Disk needs to be at least 200GB in capacity.
To achieve this please ensure that the environment variables ARDANA_CCN_DISK
and ARDANA_CPN_DISK are both set to "200GB" before starting testing.

- Controllers:  /dev/sdb and /dev/sdc is configured to be used by Swift

Additional discs can be configured for any of these roles by editing the corresponding
***data/disks_*.yml*** file
