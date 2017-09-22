
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


##Ardana Entry Scale Swift##

The input files in this model deploy a cloud that has the following characteristics:


### Control Planes ###

- A single control plane consisting of three servers that co-host all the required services
  needed to support a swift only configuration. For example keystone, monasca, horizon,
  opsconsole. These 3 servers also include the swift proxy, account, container and
  swift ring building services.

###Resource Pools###

- Three swift object servers


*Additional resource nodes can be added to the configuration.*


###Deployer Node###


This configuration runs the lifecycle-manager (formerly referred to as the deployer) on a
control plane node. You need to include this node address in your servers.yml definition.
This function does not need a dedicated network.

*The minimum server count for this example is therefore 6 servers (Control Plane (x3) + Swift Object (x3)*

An example set of servers are defined in ***data/servers.yml***. You will need to modify
this file to reflect your specific environment.


###Networking###

The example requires the following networks:

IPMI/iLO network, connected to the deployer and the IPMI/iLO ports of all servers

eth1 is used for the Management network.

An example set of networks are defined in ***data/networks.yml***. You will need to
modify this file to reflect your environment.

###Local Storage###

All servers should present a single OS disk, protected by a RAID controller. This
disk needs to be at least 512GB in capacity. In addition the example configures
additional disk depending on the role of the server:

- Controllers:  /dev/sdb and /dev/sdc are configured to be used by Swift account
  and container services
- Object Servers:  /dev/sdb, /dev/sdc, /dev/sdd, /dev/sde and /dev/sdf are
  configured to be used by the Swift object service

Additional discs can be configured for any of these roles by editing the corresponding
***data/disks_*.yml*** file

