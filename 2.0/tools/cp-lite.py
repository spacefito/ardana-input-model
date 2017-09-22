#!/usr/bin/python
#
# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from copy import deepcopy
import fnmatch
import getopt
import ipaddress
import json
import os
from pprint import pprint
import sys
import yaml


#---------------------------------------
# Find all .json and .yml files in a tree
#---------------------------------------
def find_files(directory):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, '*.json'):
                filename = os.path.join(root, basename)
                yield filename
            if fnmatch.fnmatch(basename, '*.yml'):
                filename = os.path.join(root, basename)
                yield filename


#---------------------------------------
# convert CIRD to netmask
#---------------------------------------
def cidr_to_mask(cidr):

    mask = int(str.split(cidr,'/')[1])
    bits = 0
    for i in xrange(32-mask,32):
        bits |= (1 << i)
    return "%d.%d.%d.%d" % ((bits & 0xff000000) >> 24, (bits & 0xff0000) >> 16, (bits & 0xff00) >> 8 , (bits & 0xff))


#---------------------------------------
# Print details of a Server
#---------------------------------------
def print_server(s):

    address = s['addr']
    print "      --------------------------------------------"
    print "      %s in rack %s with address %s" % (s['name'], s['rack'], address)

    print "        components:"
    for component in s['components']:
        print "          %s" % (component)

    for iface_name, iface in s['interfaces'].iteritems():
        if iface['networks']:
            print "         %s" % (iface['name'])
            print "           device name: %s" % (iface['device']['name'])
            if 'nic-mapping' in iface['device']:
                port_type = "UNKNOWN"
                port_addr= "UNKNOWN"
                for pport in s['nic_map'].get('physical-ports',[]):
                    if pport['logical-name'] == iface['device']['nic-mapping']:
                       port_name = pport['logical-name']
                       port_type = pport['type']
                       port_addr = pport['bus-address']
                       break
                print "           nic-mapping: %s -> %s (%s)" % (port_name, port_addr, port_type)

            if 'bond-data' in iface:
                bond_data = iface['bond-data']
                if 'provider' not in bond_data:
                  bond_data['provider'] = 'linux'
                print "           bond-data:"
                print "             provider: %s" % (bond_data['provider'])
                print "             devices:"
                for device in bond_data['devices']:
                    print "               device name: %s" % (device['name'])
                    if 'nic-mapping' in device:
                        port_type = "UNKNOWN"
                        port_addr= "UNKNOWN"
                        for pport in s['nic_map'].get('physical-ports',[]):
                            if pport['logical-name'] == device['nic-mapping']:
                               port_name = pport['logical-name']
                               port_type = pport['type']
                               port_addr = pport['bus-address']
                               break
                        print "                 nic-mapping : %s ->  %s (%s)" % (port_name, port_addr, port_type)
                print "               bond-options:"
                for k, v in bond_data['options'].iteritems():
                    print "                 %s: %s:" % (k,v)


        for net_name, net in iface['networks'].iteritems():
            name = net['name']
            vlan = net['vlanid']
            cidr = net.get('cidr',"")
            addr = net.get('addr',"")
            net_group = network_groups[net['network-group']]
            if cidr:
                print "           %s (vlan:%s %s)" % (name, vlan, cidr)
                print "             address %s" % (net['addr'])
            else:
                print "           %s (vlan:%s)" % (name, vlan)
            for endpoint in net['endpoints']:
                print "             endpoint: %s" %(endpoint)
            for route in net['routes']:
                print "             routes to %s" % (route)
            for tag_data in net['service-tags']:
                print "             tag %s:" % (tag_data['name'])
                print "                 values: %s " % (tag_data['values'])
                print "                 definition: %s " % (tag_data['definition'])
                print "                 service: %s " % (tag_data['service'])
                print "                 component: %s " % (tag_data['component'])

    for device_group in s['disk-model']['device-groups']:
        consumer = device_group.get('consumer', {})
        consumer_name = consumer.get ('name', "None")
        consumer_data = consumer
        #del consumer_data['name']
        print "         Device Group %s is consumed by %s (%s)" % (device_group['name'], consumer_name, consumer_data)
        for device in device_group['devices']:
            print "           %s" % (device['name'])
            if 'mkfs' in device:
                print "             mkfs: %s" % (device['mkfs'])
            if 'mount' in device:
                print "             mount as %s" % (device['mount'])

    for vg in s['disk-model'].get('volume-groups', []):
        print "         Volume Group: %s" % (vg['name'])
        for pv in vg['physical-volumes']:
            print "           Physical Volume %s" % (pv['device'])
        for lv in vg['logical-volumes']:
            print "           Logical Volume %s (%s)" % (lv['name'], lv['size'])
            if 'mount' in lv:
                print "             mount on %s" % (lv['mount'])
            consumer = lv.get ('consumer', {})
            consumer_name = consumer.get ('name', "None")
            consumer_data = consumer.get ('attrs', {})
            if consumer:
                print "             consumed by %s (%s)" % (consumer_name, consumer_data)


#---------------------------------------
# Print details of a Control Plane
#---------------------------------------
def print_cp(cp):
        print
        print ("Control Plane: " + cp['name'])
        print

        #
        # Print details of load balancers
        #
        for vip_net_name, vip_net in cp['vip_networks'].iteritems():
            print "  Load Balancers on Network %s" % (vip_net_name)
            for vip_data in vip_net:
                vip_component_name =  vip_data['component-name']
                if vip_data.get('valid', True):
                    print "    %s on %s:%s -> %s" % (vip_component_name, vip_data['address'],
                                                         vip_data['port'], vip_data['target'])
                    print "      roles: %s" % vip_data['roles']
                    print "      vip-tls: %s" % vip_data['vip-tls']
                    if 'cert-file' in vip_data:
                        print "      %s" % (vip_data['cert-file'])
                    else:
                        print "      Cert from ECA"

                    if 'vip-options' in vip_data:
                        print "      options: %s" % (vip_data['vip-options'])

                    if 'vip-check' in vip_data:
                        print "      check: %s" % (vip_data['vip-check'])


                    print "      Provider: %s" % (vip_data['provider'])
                    print "      Advertise: %s" % vip_data['advertise']

                    for host in vip_data['hosts']:
                        print "        %s" % (host)
            print

        #
        # Print details of endpoints
        #
        print "  Endpoints"
        for name, ep in cp['endpoints'].iteritems():
            print "    %s:" % (name)
            if ep['access']['use-tls']:
                tls = ' (TLS)'
            else:
                tls = ''
            if 'address' in ep['access']:
                print "      access %s:%s%s" % (ep['access']['address'], ep['access']['port'], tls)
            else:
                for member in ep['access']['members']:
                    print "      access %s:%s%s" % (member, ep['access']['port'], tls)

            if 'tls-init' in ep:
                print "      tls-init %s:%s" % (ep['tls-init']['address'], ep['tls-init']['port'])

            if 'address' in ep['bind']:
                print "      bind %s:%s" % (ep['bind']['address'], ep['bind']['port'])
            else:
                print "      bind %s:%s" % (ep['bind']['network_group'], ep['bind']['port'])

            if 'tls-term' in ep:
                print "      tls-term %s:%s" % (ep['tls-term']['network_group'], ep['tls-term']['port'])
        print

        #
        # Print the details for each group of servers
        #
        for cluster in cp['member-groups']:

            # Find the set of networks on these servers
            required_nets = set()
            for s_name, s in cluster['servers'].iteritems():
                for iface_name, iface in s['interfaces'].iteritems():
                    for net_group in iface['network-groups']:
                        required_nets.add(net_group)

            print
            print "  Member-group %s: " % (cluster['name'])
            print "    components: %s" % (cluster['service-components'])
            print "    required Networks %s" % (required_nets)

            print "    %s servers of type %s" %(cluster['member-count'],cluster['server-role'])
            for s_name, s in cluster['servers'].iteritems():
                print_server(s)

        for r_name, resources in cp.get('resource-nodes', {}).iteritems():

            # Find the set of networks on these servers
            required_nets = set()
            for s_name, s in resources['servers'].iteritems():
                for iface_name, iface in s['interfaces'].iteritems():
                    for net_group in iface['network-groups']:
                        required_nets.add(net_group)

            print
            print "  Resource nodes: %s" % (resources['name'])

            print "    components: %s" % (resources['service-components'])
            print "    required Networks %s" % (required_nets)
            print "    %s servers of type %s" %(len(resources['servers']),resources['server-role'])
            for s_name, s in resources['servers'].iteritems():
                print_server(s)
        print
        print "==================================================================="
        print



#---------------------------------------
# Build the group vars all file
#---------------------------------------
def build_ansible_group_vars_all(ansible_dir, cloud, components, service_view):

    cloud_name = cloud['cloud_info']['name']

    filename = "%s/group_vars/all" % (ansible_dir)
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))

    global_vars = {'global': {'ansible_vars': [],
                              'all_servers': []}}

    vips = []
    for region_name, region in cloud['regions'].iteritems():
        for ep_name, ep_data in region['endpoints'].iteritems():
            if 'hostname' in ep_data['access']:
                vips.append(ep_data['access']['hostname'])
            if 'hostname' in ep_data.get('admin', {}):
                vips.append(ep_data['admin']['hostname'])

    global_vars['global']['vips'] = vips

    global_vars['topology'] = {'name': cloud_name,
                               'control_planes': []}
    for cp_name, cp in service_view.iteritems():
        cp_data = {'name': cp_name,
                   'services': [] }
        for service_name, components in cp.iteritems():
            service_data = {'name': service_name,
                            'components': [] }

            for component_name, hosts in components.iteritems():
                component_data = {'name': component_name,
                                  'hosts': hosts}
                service_data['components'].append(component_data)

            cp_data['services'].append(service_data)

        global_vars['topology']['control_planes'].append(cp_data)

    #
    # Include disc details of all servers for Swift
    #
    for role, nodes in servers.iteritems():
        for server in nodes:
            if not server['available']:
                server_info = {'name': server['name'],
                               'rack': server.get('rack', None),
                               'region': server.get('region', None),
                               'disc_model': server['disk-model']}

                global_vars['global']['all_servers'].append(server_info)


    with open(filename, 'w') as fp:
        yaml.dump(global_vars, fp, default_flow_style=False, indent=4)


#---------------------------------------
# Build the group vars files
#---------------------------------------


def build_ansible_group_vars(ansible_dir, cloud_name, cp, components):

    cp_group_vars = {}

    cp_prefix = "%s-%s" % (cloud_data['name'], cp['name'])
    for cluster in cp['member-groups']:

        host_prefix = "%s-%s-%s" % (cloud_data['name'], cp['name'], cluster['name'])

        group_vars = {}
        _build_ansible_group_vars(cp, group_vars, cp_prefix, host_prefix, cluster['service-components'], cluster['servers'], components)

        filename = "%s/group_vars/%s-%s-%s" %(ansible_dir, cloud_name, cp['name'], cluster['name'])
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        with open(filename, 'w') as fp:
            yaml.dump(group_vars, fp, default_flow_style=False, indent=4)

        for key, val in group_vars.iteritems():
            cp_group_vars[key] = val

    for res_name, resources in cp.get('resource-nodes', {}).iteritems():

        group_vars = deepcopy(cp_group_vars)
        group_vars['group']['services'] = []

        host_prefix = "%s-%s-%s" % (cloud_data['name'], cp['name'], res_name)
        _build_ansible_group_vars(cp, group_vars,  cp_prefix, host_prefix, resources['service-components'], resources['servers'], components)

        filename = "%s/group_vars/%s-%s-%s" %(ansible_dir, cloud_name,  cp['name'], res_name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        f = open(filename, "w")

        with open(filename, 'w') as fp:
            yaml.dump(group_vars, fp, default_flow_style=False, indent=4)


def _build_ansible_group_vars(cp, group_vars, cp_prefix, cluster_prefix,  component_list, cluster_servers, components):

    if not 'group' in group_vars:
        group_vars['group'] = {}

    if not 'services' in group_vars['group']:
        group_vars['group']['services'] = []

    for component_name in component_list:
        if component_name in components:
            component = components[component_name]
            group_vars['group']['services'].append(component['mnemonic'])
            name = component['mnemonic'].replace('-','_')
            group_vars[name] = {}
            component_group_vars = group_vars[name]


            #  Add endpoints for this component
            if component_name in cp['advertises']:
                vips = cp['advertises'].get(component_name, {})
                advertises = {'vips': {}}
  
                for keystone_data in ['keystone-service-name',
                                      'keystone-service-type']:

                    if keystone_data in component:
                        advertises[keystone_data] = \
                            component[keystone_data]


                component_group_vars['advertises'] = advertises
                for role in ['admin', 'internal', 'public']:
                    if role in vips:
                        for region in cp['region-list']:
                            vip = {'host':  vips[role]['hostname'],
                                   'ip_address': vips[role]['ip_address'],
                                   'port': vips[role]['port'],
                                   'protocol': vips[role]['protocol'],
                                   'url': vips[role]['url'],
                                   'region_name': region}
                            if role == 'internal':
                                role_name = 'private'
                            else:
                                role_name = role

                            if not role_name in advertises['vips']:
                                advertises['vips'][role_name] = []
                            advertises['vips'][role_name].append(vip)

            # Add the details of all components we consume
            for consume in component.get('consumes-services', []):
                consume_name =  "consumes_%s" % consume['service-name'].replace('-','_')
                component_group_vars[consume_name] = {}
                consumes = component_group_vars[consume_name]

                if 'relationship-vars' in consume:
                    consumes['vars'] = {}
                    for var in consume['relationship-vars']:
                        consumes['vars'][var['name']] =  var['value']

                consumed_component_name = components_by_mnemonic[consume['service-name']]['name']
                consumed_component = components[consumed_component_name]

                #TODO: Remove once NOVA swicthes to using the advertised VIP directly
                # Hack needed to keep compatiblity with 1.0
                # which declared an internal endpoint as public
                if consumed_component.get('allow-public-to-be-consumed',
                                           False):
                    vips = cp['advertises'].get(consumed_component_name, {})
                    vip = vips['public']
                    consumes['vips'] = {'public': [
                                    {'ip_address': vip['ip_address'],
                                     'host': vip['hostname'],
                                     'port': vip['port']}
                                   ]}

                ep = cp['endpoints'].get(consumed_component_name, {})
                if not ep:
                    if 'parent-cp' in cp:
                        ep = cp['parent-cp']['endpoints'].get(consumed_component_name, {})
                if not ep:
                    print ("Warning: couldn't find %s when building consumes for %s" %
                          (consumed_component_name, component_name))
                    continue

                if 'address' in ep['access']:
                    if ep['access']['use-tls']:
                        protocol = component.get('tls_protocol', 'https')
                    else:
                        protocol = component.get('nontls_protocol', 'http')
                    url = "%s://%s:%s" % (protocol, ep['access']['hostname'],
                                                    ep['access']['port'])
                    consumes['vips'] = {'private': [ {'ip_address': ep['access']['address'],
                                                      'host': ep['access']['hostname'],
                                                      'port': ep['access']['port'],
                                                      'protocol': protocol,
                                                      'url': url,
                                                      'use_tls': ep['access']['use-tls']}
                                                   ]}
                    if 'admin' in ep:
                        if ep['admin']['use-tls']:
                            protocol = component.get('tls_protocol', 'https')
                        else:
                            protocol = component.get('protocol', 'http')
                        url = "%s://%s:%s" % (protocol, ep['admin']['hostname'],
                                                        ep['admin']['port'])
                        consumes['vips']['admin'] = [{'ip_address': ep['admin']['address'],
                                                      'host': ep['admin']['hostname'],
                                                      'port': ep['admin']['port'],
                                                      'protocol': protocol,
                                                      'url': url,
                                                      'use_tls': ep['admin']['use-tls']
                                                     }]
                else:
                    # No VIP
                    consumes['members'] = {'private':  []}
                    for member in ep['access']['members']:
                        consumes['members']['private'].append({'host': member,
                                                               'port': ep['access']['port'],
                                                               'use_tls': ep['access']['use-tls']
                                                              })

                #TODO: Remove once all playbooks have switched to using
                #      internal vips insterad of public
                # Hack needed to keep compatiblity with 1.0
                # which declared an internal endpoint as public
                if consumed_component.get('publish-internal-as-public', False):
                    if 'vips' in consumes:
                        consumes['vips']['public'] = \
                            deepcopy(consumes['vips']['private'])
                    if 'members' in consumes:
                        consumes['members']['public'] = \
                            deepcopy(consumes['members']['private'])

            #
            # Add members if required.   Note that CP prints on a specific network,
            # but we just have one internal endpoint for each component
            #
            if 'advertise-member-list-on' in component:
                member_data = cp['members'][component_name]
                component_group_vars['members'] = {}
                for role, ports in member_data['ports'].iteritems():

                    if role == 'internal':
                        role_name = 'private'
                    else:
                        role_name = role

                    component_group_vars['members'][role_name] = []
                    members = component_group_vars['members'][role_name]
                    for port in ports:
                        for host in member_data['hosts']:
                            members.append({'host': host,
                                            'port': port})


                #TODO: Remove once all playbooks have switched to using
                #      internal vip for mysql and rabbit
                # Hack needed to keep compatiblity with 1.0
                # which declared an internal endpoint as public
                if components[component_name].get(
                           'publish-internal-as-public', False):
                    component_group_vars['members']['public'] = \
                        deepcopy(component_group_vars['members']['private'])

            #
            # Add details of any component we provide a proxy for
            #
            lb_components = cp['load-balancers'].get(component_name, {})
            for lb_component_name, lb_data in lb_components.iteritems():
                if 'has_proxy' not in component_group_vars:
                    component_group_vars['has_proxy'] = {}
                proxied_component = components[lb_component_name]['mnemonic'].replace('-','_')
                component_group_vars['has_proxy'][proxied_component] = \
                                     {'networks': [],
                                      'servers': lb_data['hosts'],
                                      'initiate_tls': lb_data['host-tls'],
                                      'vars': {}}

                if 'vip-options' in lb_data:
                    component_group_vars['has_proxy'][proxied_component]\
                                        ['vip-options'] =\
                                            lb_data['vip-options']

                if 'vip-check' in lb_data:
                    component_group_vars['has_proxy'][proxied_component]\
                                        ['vip-check'] =\
                                            lb_data['vip-check']

                for net_data in lb_data['networks']:
                    proxy_data = {'ports': [net_data['port']],
                                  'vip': net_data['hostname'],
                                  'ip_address': net_data['ip-address'],
                                  'terminate_tls': net_data['vip-tls']}

                    if 'cert-file' in net_data and net_data['vip-tls']:
                        proxy_data['cert-file'] = net_data['cert-file']

                    component_group_vars['has_proxy'][proxied_component]['networks'].append(proxy_data)

            #
            # Add details of contained services
            #
            for contains_name, contains_data in component.get('contains',{}).iteritems():
                rel_name = "%s_has_container" % contains_data['name']
                component_group_vars[rel_name] = {'members': {},
                                                  'vips': {}
                                                 }
                for var in contains_data.get('relationship-vars', []):
                    if not 'vars' in component_group_vars[rel_name]:
                        component_group_vars[rel_name]['vars'] = {}
                    component_group_vars[rel_name]['vars'][var['name']] = var['value']

                vip_data = []
                for net, vips in cp['vip_networks'].iteritems():
                    for vip in vips:
                        if vip['component-name'] == contains_name:
                            vip_data.append(vip)
                for vip in vip_data:
                    for role in vip['roles']:
                        if role == 'internal':
                            role = 'private'
                        component_group_vars[rel_name]['members'][role] = []
                        component_group_vars[rel_name]['vips'][role] = []

                        for host in vip['hosts']:
                            component_group_vars[rel_name]['members'][role].append(
                                {'host': host,
                                 'port': vip['port']
                                })

                        component_group_vars[rel_name]['vips'][role].append(
                            {'vip': vip['hostname'],
                             'port': vip['port']
                            })
            # Add Log info
            if 'produces-log-files' in component:
                component_group_vars['produces_log_files'] = {'vars': {}}
                component_log_info = component_group_vars['produces_log_files']

                for log_info in component['produces-log-files']:
                    for var in log_info['relationship-vars']:
                        component_log_info['vars'][var['name']] = []
                        for val in var['value']:
                            for k,v in val.iteritems():
                                component_log_info['vars'][var['name']].append({k: v})


            # Print out any config set - Not sure if we need this with out config
            # approach ?
            config_set = component.get('config-set', [])
            for config in config_set:
                if 'sysctl-vars' in config:
                    if not 'sysctl_vars' in component_group_vars:
                        component_group_vars['sysctl_vars'] = {}
                    for key,val in config['sysctl-vars'].iteritems():
                        component_group_vars['sysctl_vars'][key] = val
                if 'ansible-vars' in config:
                    if not 'vars' in component_group_vars:
                        component_group_vars['vars'] = {}
                    for var in config['ansible-vars']:
                        component_group_vars['vars'][var['name']] = var['value']

    group_vars['group']['vars']={'control_plane_prefix': cp_prefix,
                                 'network_address_prefix': cluster_prefix}

    for vip_net_name, vip_net_data in cp['vip_networks'].iteritems():
        #
        # Build a list of all VIPs on this network
        #
        vips = set()
        for vip_data in vip_net_data:
            vips.add(vip_data['address'])


        # Find the device for this network from the first server
        # Note: cluster uses a single server role, so this is safe
        device='unknown'
        for server_name, server in cluster['servers'].iteritems():
            for iface_name, iface_data in server['interfaces'].iteritems():
                if vip_net_name in iface_data['networks']:
                    device = iface_data['name']
                    break

        for vip in vips:
            device_data = {'device': device,
                           'interface': vip_net_name,
                            'vip_address': vip}
            if not 'network_interfaces' in group_vars['group']:
                group_vars['group']['network_interfaces'] = []
            group_vars['group']['network_interfaces'].append(device_data)



#---------------------------------------
# Build a host vars file
#---------------------------------------
def build_ansible_host_vars(ansible_dir, server, region_endpoints, components):


    filename = "%s/host_vars/%s" % (ansible_dir, server['name'])
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))

    #TODO:  Some plyabooks currenlty use my_network_addr and
    #HACK   my_network_name as the adress to bind to
    #HACK   In the padaawn examples this is always the
    #HACK   network in the MGMT net group, so fo now
    #HACK   make sure this is picked up.
    for if_name, if_data in server['interfaces'].iteritems():
        for net_name, net_data in if_data['networks'].iteritems():
           if net_data['network-group'] == "MGMT":
               my_addr = net_data['addr']
               my_name = net_data['hostname']

    host_vars = {'host': {
                    'vars': {
                        'member_id': server.get('member_id', 'cpn'),
                        'my_network_address': my_addr,
                        'my_network_name': my_name,
                        'my_baremetal_info': {
                            'pxe_interface': 'eth2',
                            'pxe_ip_addr': server['addr']
                        },
                        'my_network_interfaces': {}
                    },
                    'bind': {},
                    'stunnel_in': [],
                    'stunnel_out': []
                 }
                }

    for if_name, if_data in server['interfaces'].iteritems():
        for net_name, net_data in if_data['networks'].iteritems():
            #
            # Hack to map to names that current os-config expects
            #
            if net_data['network-group'] == 'MGMT':
                x_net_names = ['NETCLM', 'NETTUL']
            elif net_data['network-group'] == 'EXTERNAL_VM':
                x_net_names = ['NETEXT']
            else:
                x_net_names = [net_data['network-group']]

            if 'addr' in net_data:
                for x_name in x_net_names:
                    host_vars['host']['vars']['my_network_interfaces'][x_name] = \
                        {'address': net_data['addr'],
                         'device': if_data['name'],
                         'netmask': cidr_to_mask(net_data['cidr'])
                        }
            else:
                for x_name in x_net_names:
                    host_vars['host']['vars']['my_network_interfaces'][x_name] = \
                       {'device': if_data['name'],
                        }

    #
    #  Add list of bind addresses
    #
    for component_name, endpoint_data in region_endpoints.iteritems():
        if component_name in server['components']:
            mnemonic = components[component_name]['mnemonic'].replace('-','_')

            if not mnemonic in host_vars['host']['bind']:
                host_vars['host']['bind'][mnemonic] = {}

            if 'address' in endpoint_data['bind']:
                bind_address = endpoint_data['bind']['address']
            else:
                # May have to map to a network
                for if_name, if_data in server['interfaces'].iteritems():
                    for net_name, net_data in if_data['networks'].iteritems():
                        if endpoint_data['bind']['network_group'] == net_data['network-group']:
                            bind_address = net_data['addr']
                            break
            bind_port = endpoint_data['bind']['port']
            host_vars['host']['bind'][mnemonic]['internal'] = {'ip_address': bind_address,
                                                               'port': bind_port}

            if 'admin-bind' in endpoint_data:
                if 'address' in endpoint_data['admin-bind']:
                    bind_address = endpoint_data['admin-bind']['address']
                else:
                    # May have to map to a network
                    for if_name, if_data in server['interfaces'].iteritems():
                        for net_name, net_data in if_data['networks'].iteritems():
                            if endpoint_data['admin-bind']['network_group'] == net_data['network-group']:
                                bind_address = net_data['addr']
                                break
                bind_port = endpoint_data['admin-bind']['port']
                host_vars['host']['bind'][mnemonic]['admin'] = {'ip_address': bind_address,
                                                                'port': bind_port}

    #
    # Add list of stunnel terminations
    #
    for component_name, endpoint_data in region_endpoints.iteritems():
        if component_name in server['components']:
            if 'tls-term'in endpoint_data:
                # Find the addesss in the right group
                for if_name, if_data in server['interfaces'].iteritems():
                    for net_name, net_data in if_data['networks'].iteritems():
                        if endpoint_data['tls-term']['network_group'] == net_data['network-group']:
                            accept_addr = net_data['addr']
                            break

                accept = {'ip_address': accept_addr,
                          'port': endpoint_data['tls-term']['port']}
                connect = {'ip_address': endpoint_data['bind']['address'],
                           'port': endpoint_data['bind']['port']}
                term = {'name': component_name,
                        'accept': accept,
                        'connect': connect}
                host_vars['host']['stunnel_in'].append(term)

            if 'admin-tls-term'in endpoint_data:
                # Find the addesss in the right group
                for if_name, if_data in server['interfaces'].iteritems():
                    for net_name, net_data in if_data['networks'].iteritems():
                        if endpoint_data['admin-tls-term']['network_group'] == net_data['network-group']:
                            accept_addr = net_data['addr']
                            break

                accept = {'ip_address': accept_addr,
                          'port': endpoint_data['admin-tls-term']['port']}
                connect = {'ip_address': endpoint_data['admin-bind']['address'],
                           'port': endpoint_data['admin-bind']['port']}
                term = {'name': "%s-admin" % component_name,
                        'accept': accept,
                        'connect': connect}
                host_vars['host']['stunnel_in'].append(term)

    #
    # Add a list of stunnel initiations
    #
    #  Build a list of all consumed services from this host
    consumed = set()
    for component_name in server['components']:
        if not component_name in components:
           print "Warning: No data for %s when buiding stunnel list" % component_name
           continue

        component_data = components[component_name]
        for consumes in component_data.get('consumes-services', []):
            consumed.add(consumes['service-name'])

    for consumed_service in consumed:
        service_name = components_by_mnemonic[consumed_service]['name']
        if service_name in region_endpoints:
            endpoint_data = region_endpoints[service_name]
            if 'tls-init'in endpoint_data:
                accept = {'ip_address': endpoint_data['access']['address'],
                          'host': endpoint_data['access']['hostname'],
                          'port': endpoint_data['access']['port']}
                connect = {'ip_address': endpoint_data['tls-init']['address'],
                           'host': endpoint_data['tls-init']['hostname'],
                           'port': endpoint_data['tls-init']['port']}
                init = {'name': service_name,
                        'accept': accept,
                        'connect': connect}

                host_vars['host']['stunnel_out'].append(init)

    #
    # Add Disk info
    #
    host_vars['host']['my_disk_models'] = server['disk-model']


    #
    # Generate os-config network data
    #
    # create network_interface role compatible host_vars
    service_tags, ovs_bridge_host_vars, vlan_host_vars, bond_host_vars, ether_host_vars = build_network_host_vars(server)
    host_vars['host']['my_network_tags'] = service_tags

    with open(filename, 'w') as fp:
        yaml.dump(host_vars, fp, default_flow_style=False, indent=4)
        if ovs_bridge_host_vars['ovs_bridge_interfaces']:
            yaml.dump(ovs_bridge_host_vars, fp, default_flow_style=False, indent=4)
        if vlan_host_vars['network_vlan_interfaces']:
            yaml.dump(vlan_host_vars, fp, default_flow_style=False, indent=4)
        if bond_host_vars['network_bond_interfaces']:
            yaml.dump(bond_host_vars, fp, default_flow_style=False, indent=4)
        if ether_host_vars['network_ether_interfaces']:
            yaml.dump(ether_host_vars, fp, default_flow_style=False, indent=4)


def build_network_host_vars(server):
    server_bond_dictionary = {}
    server_ether_dictionary = {}
    server_vlan_dictionary = {}
    server_ovs_bridge_dictionary = {}
    server_service_tags_list = []
    server_bond_dictionary['network_bond_interfaces'] = []
    server_ether_dictionary['network_ether_interfaces'] = []
    server_vlan_dictionary['network_vlan_interfaces'] = []
    server_ovs_bridge_dictionary['ovs_bridge_interfaces'] = []

    # get all the interfaces on this server
    interfaces = server.get('interfaces', None)
    for interface, interface_attrs in interfaces.items():
        # get the bond data for this interface
        bond_data = interface_attrs.get('bond-data', None)
        # get the ports
        ports = getPorts(bond_data)
        # get the device definition
        interface_name = getInterfaceName(interface_attrs.get('device', None))

        # get all networks on this interface
        networks = interface_attrs.get('networks', None)
        for network_name, network_attrs in networks.items():
            addr = network_attrs.get('addr', None)
            cidr = network_attrs.get('cidr', None)
            gateway_ip = network_attrs.get('gateway-ip', None)
            tagged_vlan = network_attrs.get('tagged-vlan', True)
            vlanid = network_attrs.get('vlanid', None)
            routes = network_attrs.get('routes' , None)
            service_tags = network_attrs.get('service-tags', None)
            # use service tags to determine if a bridge is needed
            needs_bridge = getBridgeInfo(service_tags)
            # the interface on which to add the bridge will get determined later as
            # we build the interfaces
            bridge_interface = ''

            # for each network, build the desired server network dict

            # The existence of bond_data indicates that this is a bonded interface
            if bond_data:
                bond_dictionary = {}
                bond_service_tag_dict = getServiceTags(service_tags)
                bond_service_tag_dict['network'] = network_name
                bond_dictionary['device'] = interface_name
                bond_service_tag_dict['device'] = interface_name
                bond_mode, bond_miimon = getBondOptions(bond_data)
                bond_dictionary['bond_mode'] = bond_mode
                bond_dictionary['bond_miimon'] = bond_miimon
                bond_dictionary['bond_slaves'] = []
                for port in ports:
                    bond_dictionary['bond_slaves'].append(port)
                bond_dictionary['route'] = []
                for route in routes:
                    rte_network, rte_netmask, rte_gateway = getRouteInfo(route, gateway_ip)
                    route_dictionary = {}
                    route_dictionary['network'] = rte_network
                    route_dictionary['netmask'] = getNetmask(rte_netmask)
                    route_dictionary['gateway'] = rte_gateway
                    bond_dictionary['route'].append(route_dictionary)
                if needs_bridge:
                    bridge_interface = interface_name
                    bond_dictionary['bootproto'] = getBootProto("")
                    bond_dictionary['ovs_bridge'] = getBridgeName(bridge_interface)
                else:
                    bond_dictionary['address'] = addr
                    bond_dictionary['netmask'] = getNetmask(cidr)
                    bond_dictionary['gateway'] = gateway_ip
                    bond_dictionary['bootproto'] = getBootProto(addr)
                    bond_service_tag_dict['address'] = addr
                    # save service tag info if a tag exists
                    if bond_service_tag_dict.get('tag', None):
                        server_service_tags_list.append(bond_service_tag_dict)
                # clean out any null values
                bond_dict_clean = { k: v for k, v in bond_dictionary.items() if v }
                server_bond_dictionary['network_bond_interfaces'].append(bond_dict_clean)

            # set attributes for vlan interface
            if tagged_vlan:
                vlan_dictionary = {}
                vlan_service_tag_dict = getServiceTags(service_tags)
                vlan_service_tag_dict['network'] = network_name
                vlan_dictionary['vlanid'] = vlanid
                vlan_device = 'vlan' + str(vlanid)
                vlan_dictionary['device'] = vlan_device
                vlan_service_tag_dict['device'] = vlan_device
                vlan_dictionary['vlanrawdevice'] = interface_name
                vlan_dictionary['route'] = []
                for route in routes:
                    rte_network, rte_netmask, rte_gateway = getRouteInfo(route, gateway_ip)
                    route_dictionary = {}
                    route_dictionary['network'] = rte_network
                    route_dictionary['netmask'] = getNetmask(rte_netmask)
                    route_dictionary['gateway'] = rte_gateway
                    vlan_dictionary['route'].append(route_dictionary)
                if needs_bridge:
                    bridge_interface = vlan_device
                    vlan_dictionary['bootproto'] = getBootProto("")
                    vlan_dictionary['ovs_bridge'] = getBridgeName(bridge_interface)
                else:
                    vlan_dictionary['address'] = addr
                    vlan_dictionary['netmask'] = getNetmask(cidr)
                    vlan_dictionary['gateway'] = gateway_ip
                    vlan_dictionary['bootproto'] = getBootProto(addr)
                    vlan_service_tag_dict['address'] = addr
                    # save service tag info if a tag exists
                    if vlan_service_tag_dict.get('tag', None):
                        server_service_tags_list.append(vlan_service_tag_dict)
                # clean out any null values
                vlan_dict_clean = { k: v for k, v in vlan_dictionary.items() if v }
                server_vlan_dictionary['network_vlan_interfaces'].append(vlan_dict_clean)
            elif not tagged_vlan and not bond_data:
                ether_dictionary = {}
                ether_service_tag_dict = getServiceTags(service_tags)
                ether_service_tag_dict['network'] = network_name
                ether_dictionary['device'] = interface_name
                ether_service_tag_dict['device'] = interface_name
                ether_dictionary['route'] = []
                for route in routes:
                    rte_network, rte_netmask, rte_gateway = getRouteInfo(route, gateway_ip)
                    route_dictionary = {}
                    route_dictionary['network'] = rte_network
                    route_dictionary['netmask'] = getNetmask(rte_netmask)
                    route_dictionary['gateway'] = rte_gateway
                    ether_dictionary['route'].append(route_dictionary)
                if needs_bridge:
                    bridge_interface = interface_name
                    ether_dictionary['bootproto'] = getBootProto("")
                    ether_dictionary['ovs_bridge'] = getBridgeName(bridge_interface)
                else:
                    ether_dictionary['address'] = addr
                    ether_dictionary['netmask'] = getNetmask(cidr)
                    ether_dictionary['gateway'] = gateway_ip
                    ether_dictionary['bootproto'] = getBootProto(addr)
                    ether_service_tag_dict['address'] = addr
                    # save service tag info if a tag exists
                    if ether_service_tag_dict.get('tag', None):
                        server_service_tags_list.append(ether_service_tag_dict)
                # clean out any null values
                ether_dict_clean = { k: v for k, v in ether_dictionary.items() if v }
                server_ether_dictionary['network_ether_interfaces'].append(ether_dict_clean)

            # set attributes for a bridge
            if needs_bridge:
                ovsbr_dictionary = {}
                ovsbr_service_tag_dict = getServiceTags(service_tags)
                ovsbr_service_tag_dict['network'] = network_name
                ovsbr_dictionary['device'] = getBridgeName(bridge_interface)
                ovsbr_service_tag_dict['device'] = getBridgeName(bridge_interface)
                ovsbr_dictionary['bootproto'] = getBootProto(addr)
                ovsbr_dictionary['address'] = addr
                ovsbr_service_tag_dict['address'] = addr
                ovsbr_dictionary['netmask'] = getNetmask(cidr)
                ovsbr_dictionary['gateway'] = gateway_ip
                ovsbr_dictionary['port'] = bridge_interface
                # TODO where does hwaddr come from and do we even need this ?
                ovsbr_dictionary['hwaddr'] = ''
                # clean out any null values
                ovsbr_dict_clean = { k: v for k, v in ovsbr_dictionary.items() if v }
                server_ovs_bridge_dictionary['ovs_bridge_interfaces'].append(ovsbr_dict_clean)
                # save service tag info if a tag exists
                if ovsbr_service_tag_dict.get('tag', None):
                    server_service_tags_list.append(ovsbr_service_tag_dict)

    return server_service_tags_list, server_ovs_bridge_dictionary, server_vlan_dictionary, server_bond_dictionary, server_ether_dictionary


def getBridgeInfo(service_tags):
    needs_bridge = False
    for tag in service_tags:
        # get the definition dictionary from each tag
        definition = tag.get('definition', None)
        if definition:
            needs_bridge = definition.get('needs-bridge', False)
    return needs_bridge


def getBridgeName(interface):
    return "br-"+ interface


def getBootProto(addr):
    # We don't need to support dhcp
    if addr:
        return 'static'
    else:
        return 'manual'


def getRouteInfo(route, gateway):
    rte_network = ''
    rte_netmask = ''
    if route == 'default':
        rte_network = '0.0.0.0'
        rte_netmask = '0.0.0.0'
    else:
        # If route is not 'default',
        # route is expected to be of the form 'x.x.x.x/y (NET_GROUP)'
        cidr, group = route.split()
        rte_network, rte_netmask = cidr.split("/")

    return rte_network, rte_netmask, gateway


def getBondOptions(bond_data):
    options = bond_data.get('options', None)
    bond_mode = options.get('bond-mode', '')
    bond_miimon = options.get('bond-miimon', '')
    return bond_mode, bond_miimon

def getNetmask(netmask):
    # netmask could be xx.xx.xx.xx or xx.xx.xx.xx/yy
    if netmask and '/' in netmask:
        ip, routing_prefix = netmask.split("/")
        return int(routing_prefix)
    else:
        return netmask

# interface could be specified by nam ( eth0, bond0 )
# or could be specified by a nic_mapping
def getInterfaceName(device):
    name = device.get('name', None)
    nic_mapping = device.get('nic-mapping', None)
    if nic_mapping:
        # TODO: do something to map the port to an ethx
        # TODO: don't know how to do this yet
        return name
    else:
        return name


def getPorts(bond_data):
    ports = []
    if not bond_data:
        return ports
    devices = bond_data.get('devices', None)
    if not devices:
        return ports

    for device in devices:
        name = device.get('name', None)
        nic_mapping = device.get('nic-mapping', None)
        if nic_mapping:
            # TODO: do something to map the port to an ethx
            # TODO: don't know how to do this yet
            ports.append(name)
        else:
            ports.append(name)
    return ports

def getServiceTags(service_tags):
    service_tag_dict = {}
    for tag in service_tags:
        service = tag.get('service', None)
        # TODO What do we do with tags which aren't neutron tags
        # TODO Can there be more than one neutron tag?
        # TODO This code will only handle one ( the first ) neutron tag
        if service == 'neutron':
            service_tag_dict['tag'] = tag.get('name', None)
            service_tag_dict['service'] = tag.get('service', None)
            service_tag_dict['values'] = tag.get('values', None)
            service_tag_dict['component'] = tag.get('component', None)
            break
    return service_tag_dict

#---------------------------------------
# Build the ansible hosts files
#---------------------------------------
def build_ansible_hosts(ansible_dir, cloud, components, servers):

    cloud_name = cloud['cloud_info']['name']

    filename = "%s/hosts/localhost" % (ansible_dir)
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))

    with open(filename, 'w') as f:
        f.write("localhost\n")


    filename = "%s/hosts/verb_hosts" % (ansible_dir)
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))

    with open(filename, 'w') as f:
        f.write("[localhost]\n")
        f.write("localhost\n")
        f.write("\n")

        f.write("[ARDANA-NETCLM]\n")
        f.write("ARDANA-NETCLM ansible_ssh_host=192.268.245.2\n")
        f.write("\n")

        f.write("[resources]\n")
        for role, nodes in servers.iteritems():
            for s in nodes:
                if not s['available']:
                    f.write("%s ansible_ssh_host=%s\n" % (s['name'], s['addr']))
        f.write("\n")

        # Build a list of all regions
        f.write("[%s:children]\n" % (cloud_name))
        for region_name in cloud['regions']:
            f.write("%s-%s\n" % (cloud_name, region_name))
        f.write("\n")

        # List all clusters and resource in a region
        for region_name, region in cloud['regions'].iteritems():
            f.write("[%s-%s:children]\n" % (cloud_name, region_name))
            for cluster in region['member-groups']:
                f.write("%s-%s-%s\n" % (cloud_name, region_name, cluster['name']))
            for resource_group_name in region.get('resource-nodes',[]):
                f.write("%s-%s-%s\n" % (cloud_name, region_name, resource_group_name))
            f.write("\n")


        # List all members of each clusters in a region
        for region_name, region in cloud['regions'].iteritems():
            for cluster in region['member-groups']:
                f.write("[%s-%s-%s:children]\n" % (cloud_name, region_name, cluster['name']))
                for server_name in cluster['servers']:
                    f.write("%s\n" % server_name)
                f.write("\n")

                for server_name, server in cluster['servers'].iteritems():
                    f.write("[%s]\n" % server_name)
                    f.write("%s ansible_ssh_host=%s\n" % (server_name, server['addr']))
                    f.write("\n")

            for resource_group_name, resource_group in region.get('resource-nodes',{}).iteritems():
                f.write("[%s-%s-%s:children]\n" % (cloud_name, region_name, resource_group_name))
                for server_name in resource_group['servers']:
                    f.write("%s\n" % server_name)
                f.write("\n")

                for server_name, server in resource_group['servers'].iteritems():
                    f.write("[%s]\n" % server_name)
                    f.write("%s ansible_ssh_host=%s\n" % (server_name, server['addr']))
                    f.write("\n")


        # Build list of hosts by component accross all regions
        component_list={}
        for region_name, region in cloud['regions'].iteritems():
            for component_name, component_data in region['components'].iteritems():
                if not component_name in components:
                    print "Warning: No data for %s when building host_vars" % component_name
                    continue

                component_mnemonic = components[component_name]['mnemonic']

                if not component_mnemonic in component_list:
                    component_list[component_mnemonic] = []

                component_list[component_mnemonic].extend(component_data['hosts'])


        for component_name, hosts in component_list.iteritems():
            f.write("[%s:children]\n" % (component_name))
            for host in hosts:
                f.write("%s\n" % host)
            f.write("\n")



#---------------------------------------
# Build the etc hosts file
#---------------------------------------
def build_etc_hosts(ansible_dir, cloud_name, addresses, host_aliases):

    filename = "%s/generated_files/etc/hosts" % (ansible_dir)
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))

    with open(filename, 'w') as f:
        f.write("# Cloud: %s\n" % (cloud_name))
        f.write("\n")
        f.write("# Localhost Information\n")
        f.write("127.0.0.1	localhost\n")
        f.write("\n")

        for group_name, group in allocated_addresses.iteritems():
            f.write("#\n")
            f.write("# Network Group: %s\n" % (group_name))
            f.write("#\n")
            for network_name, network in group.iteritems():
                f.write("# Network: %s\n" % (network_name))
                for addr in sorted(network):
                    data = network[addr]
                    f.write ("%-16s	%s\n" % (addr, data['host']))
                    aliases = host_aliases.get(group_name,{}).get(network_name,{}).get(addr,[])
                    for name in aliases:
                        f.write ("%-16s	%s\n" % (addr, name))


#---------------------------------------
# Allocate an address from a network
#---------------------------------------
def allocate_address(addresses, used_by, host="", net_name=""):
    addr = None
    for f in addresses:
        if f['free']:
            addr = f['addr']
            f['free'] = False
            f['used-by'] = used_by
            f['host'] = host
            break
    if not addr:
        print "Warning: Could not allocate address from network %s" % net_name
        addr = "0.0.0.0"

    return addr


#---------------------------------------
# Record host name aliases
#---------------------------------------
host_aliases={}
def add_hostname_alias(net, address, name):

    if net['network-group'] not in host_aliases:
        host_aliases[net['network-group']] = {}

    if net['name'] not in host_aliases[net['network-group']]:
        host_aliases[net['network-group']][net['name']] = {}

    if address not in host_aliases[net['network-group']][net['name']]:
        host_aliases[net['network-group']][net['name']][address] = set()

    host_aliases[net['network-group']][net['name']][address].add(name)


#---------------------------------------
# Resolve network config for a server.
#---------------------------------------
def resolve_server_networks(s, components, network_groups, network_addresses):

    # Find which networks we need for this server
    required_nets = set()
    related_nets = {}
    components_included = set()
    for group_name, net_group in network_groups.iteritems():

        # Build a list of all components on ths network
        component_endpoints = net_group.get('component-endpoints', []) +\
                              net_group.get('tls-component-endpoints', [])
        for lb in net_group.get('load-balancers', []):
            component_endpoints.append(lb['provider'])

        for component_name in s['components']:

            if component_name not in component_endpoints:
                continue

            component = components.get(component_name, {})

            if (component_name in component_endpoints):
                required_nets.add(group_name)
                components_included.add(component_name)


    # Add in entries for default endpoints, network tags, or default route
    for group_name, net_group in network_groups.iteritems():

        component_endpoints = net_group.get('component-endpoints', []) +\
                              net_group.get('tls-component-endpoints', [])

        for component_name in s['components']:
            if ('default' in component_endpoints
                    and component_name not in components_included):
                required_nets.add(group_name)

            if not component_name in components:
                print ("Warning: Can't find component %s during "
                       "network resolution" % component_name)
                continue

            component = components.get(component_name, {})

            # Add any networks that are required due to a service tag
            network_group_tags = net_group.get('tags', [])
            for tag in network_group_tags:
                if tag.get('component', '') == component['name']:

                    # Add to the list of required networks
                    required_nets.add(group_name)

                    # Add to the list of related networks
                    if group_name not in related_nets:
                        related_nets[group_name] = []

                    related_nets[group_name].append(tag)

            # Always add the network with the default route
            if 'default' in net_group.get('routes', []):
                required_nets.add(group_name)


    # Build a new list of networks limited to the ones needed on this server
    components_attached = set()
    for iface in s['interfaces']:
        server_networks = {}
        server_models = []
        for net_name, net in iface['networks'].iteritems():
            if net['network-group'] in required_nets:
                server_networks[net_name] = net
                server_models.append(net['network-group'])

        iface['networks'] = server_networks
        iface['network-groups'] = server_models

        for net_name, net in iface['networks'].iteritems():
            if 'cidr' in net:
                net['addr'] = allocate_address(network_addresses[net['name']],
                                               used_by = 'server',
                                               host = s['name'],
                                               net_name = net_name)
                net_suffix = network_groups[net['network-group']].get('hostname-suffix', net['network-group'])
                net['hostname'] = "%s-%s" % (s['name'], net_suffix)
                add_hostname_alias(net, net['addr'], net['hostname'])

            net['endpoints'] = {}
            net_group = network_groups[net['network-group']]
            net_group_endpoints = net_group.get('component-endpoints', [])
            net_group_tls_endpoints = net_group.get('tls-component-endpoints', [])

            # Add explicit endpoint attachments
            for component_name in s['components']:
                component = components.get(component_name, {})
                if (component_name in net_group_endpoints):
                    components_attached.add(component_name)
                    net['endpoints'][component_name] =  {'use-tls': False}
                if (component_name in net_group_tls_endpoints):
                    components_attached.add(component_name)
                    net['endpoints'][component_name] =  {'use-tls': True}

            # Mark any networks added as a tag
            net['service-tags'] = related_nets.get(net['network-group'],{})


    # Add default endpoint attachments
    for iface in s['interfaces']:

        for net_name, net in iface['networks'].iteritems():
            net_group = network_groups[net['network-group']]
            net_group_endpoints = net_group.get('component-endpoints', [])
            net_group_tls_endpoints = net_group.get('tls-component-endpoints', [])

            for component_name in s['components']:
                component = components.get(component_name, {})
                if ('default' in net_group_endpoints
                        and component_name not in components_attached):
                    net['endpoints'][component_name] =  {'use-tls': False}
                elif ('default' in net_group_tls_endpoints
                        and component_name not in components_attached):
                    net['endpoints'][component_name] =  {'use-tls': True}

    # Build a list of interfaces limited to the ones that need to be configured
    server_ifaces = {}
    for iface in s['interfaces']:
        if iface['networks']:
            server_ifaces[iface['name']] = iface

    s['interfaces'] = server_ifaces



#######
# Main
#######


# Cloud
try:
    opts, args = getopt.getopt(sys.argv[1:], "qc:j:a:", ["quiet", "cloud-def=", "json-out=", "ansible="])
except getopt.GetoptError as err:
    print str(err)
    sys.exit(2)

quiet = False

cloud_file = 'cloudConfig.yml'
path = ''
json_out = ''
ansible_out = ''
for o, a in opts:
    if o == "-q":
        quiet = True
    elif o in ("-c", "--cloud-def"):
        cloud_file = a
        path =  os.path.dirname(cloud_file) + "/"
    elif o in ("-j", "--json-out"):
        json_out = a
    elif o in ("-a", "--ansible"):
        ansible_out = a



yaml_data=open(cloud_file)
data  = yaml.load(yaml_data)
cloud_data  = data['cloud']
yaml_data.close()


#Services and Service Components
services={}
components={}
components_by_mnemonic={}

for service_file in find_files(path + cloud_data['services-dir']):
    print "%s" % (service_file)
    yaml_data=open(service_file)
    data  = yaml.load(yaml_data)
    for service in data.get('services', []):
        services[service['name']] = service

    for component in data.get('service-components', []):
        components[component['name']] = component
        components_by_mnemonic[component['mnemonic']] = component

    yaml_data.close()


control_planes={}
network_groups={}
load_balancers=[]
networks={}
network_addresses={}
iface_models={}
disk_models={}
nic_mappings={}
server_roles={}
bm_servers=[]


for file in find_files(path + cloud_data['data-dir']):
    print "%s" % (file)
    yaml_data=open(file)
    data  = yaml.load(yaml_data)

    #Control Planes
    for region in data.get('regions', []):
        control_planes[region['name']] = dict(region)

    #Network Groups
    for net in data.get('network-groups', []):
        network_groups[net['name']] = net
        network_groups[net['name']]['networks'] = []


    #Networks
    for net in data.get('networks', []):

        networks[net['name']] = net

        network_addresses[net['name']] = []
        if 'cidr' in net:
            for ipaddr in ipaddress.ip_network(unicode(net['cidr'])).hosts():
                addr = str(ipaddr)
                if addr != net.get('gateway-ip', ''):
                    network_addresses[net['name']].append(
                                 {'addr': str(addr),
                                  'free': True})

    #Interface Models
    for iface in data.get('interface-models', []):
        iface_models[iface['name']] = iface


    # Disk Models
    for disk_model in data.get('disk-models', []):
        disk_models[disk_model['name']] = disk_model


    # NIC Mapping
    for nic_map in data.get('nic-mappings', []):
        nic_mappings[nic_map['name']] = nic_map


    # Server Roles
    for role in data.get('server-roles', []):
        server_roles[role['name']] = role


    # Servers
    if 'servers' in data:
        bm_servers.extend(data['servers'])

    yaml_data.close()

####################################
#
# End of reading input data
#
###################################


#Useful debug if you want a list of Mnemonic mappings
#for men in sorted(components_by_mnemonic):
#    print "%s: %s" % (men, components_by_mnemonic[men]['name'])

# Map service components into services:
for service_name, service in services.iteritems():
    for resource_type, data in service['components'].iteritems():
        for service_component_name, counts in data.iteritems():

            # Resolve Mnemonics
            if service_component_name not in components:
                if service_component_name not in components_by_mnemonic:
                    print ("Warning: Service %s has an undefined"
                           " component %s" % (service_name, service_component_name))
                else:
                    service_component_name = \
                        components_by_mnemonic[service_component_name]['name']

            components[service_component_name]['service'] = service_name


# Add proxy relationships
for component_name, component in components.iteritems():
    for container_data in component.get('has-container', []):
        container_name = container_data['service-name']
        if container_name in components_by_mnemonic:
            container_name = components_by_mnemonic[container_name]['name']
        if not 'contains' in components[container_name]:
            components[container_name]['contains'] = {}
        components[container_name]['contains'][component_name] =  \
            {'name': component['mnemonic'].replace('-','_'),
             'data': container_data
            }


#Add networks into their respective groups
for net_name, net in networks.iteritems():
    network_groups[net['network-group']]['networks'].append(net)

#
# Expand any network group tags to include the definition
# from the service component
#
for net_group_name, net_group in network_groups.iteritems():
    tags = []
    for raw_tag in net_group.get('tags', []):
        # Convert any network group tags that are just a string to a dict
        # so that we have a consistent type
        if isinstance(raw_tag, basestring):
             tag = {raw_tag: None}
        elif isinstance(tag, dict):
             tag = raw_tag
        else:
            print ("Warning: tag %s on net group %s is an invalid format"
                   " - ignoring tag" % (raw_tag, net_group_name))
            continue

        for tag_name, tag_value in tag.iteritems():
            for component_name, component in components.iteritems():
                for comp_tag in component.get('network-tags', []):
                    if comp_tag['name'] == tag_name:
                        tag_definition = comp_tag

                        needs_value = tag_definition.get('needs-value', False)
                        if needs_value and not tag_value:
                            print ("Warning: Missing value on tag %s in "
                                   "network group %s - ignoring tag" %
                                   (tag_name, net_group_name))
                            continue

                        tag_data = {'name': tag_name,
	                            'values': tag_value,
	                            'definition': tag_definition,
	                            'component': component_name,
	                            'service': components[component_name].get('service', 'foundation')
	                           }
                        tags.append(tag_data)

    net_group['tags'] = tags


#Load Balancers
for netgroup_name, netgroup in network_groups.iteritems():
    for lb in netgroup.get('load-balancers', []):
        lb['network-group'] = netgroup_name
        load_balancers.append(lb)


# Create a default interface-model for any roles that don't define one
default_net_iface = [{'name': 'default_iface',
                      'network-groups': [x for x in network_groups],
                      'ports': ['ethX']}]


# Create a list of servers by server_role with the network details for each resolved
servers={}
for s in bm_servers:

    server_role = server_roles[s['role']]

    if not s['role'] in servers:
        servers[s['role']] = []

    # resolve the networking

    # Find the interface model, and take a copy of the interfaces, as we may only use part of the model
    # If there is no interface-model in the server role then all networks map to the existing NIC
    if 'interface-model' in server_role:
        iface_model = iface_models[server_role['interface-model']]
        server_interfaces = deepcopy(iface_model['network-interfaces'])
    else:
        server_interfaces = deepcopy(default_net_iface)

    # Find the disk model, and take a copy of the interfaces, as we may only use part of the model
    if 'disk-model' in server_role:
        disk_model = deepcopy(disk_models[server_role['disk-model']])
    else:
        disk_model = {'drives': {}}

    # Translate network groups to the specific networks for this server
    # Note:  At this stage we have all possible networks groups defined
    #        by the interface model.  We will reduce that to just those
    #        needed once we have assinged the server to a particular role
    for iface in server_interfaces:
        iface['networks'] = {}
        for net_group in iface['network-groups']:
            # Find network in the group for this server
            for net_name, network in networks.iteritems():
                if net_group == networks[net_name]['network-group']:
                    if (not network.get('racks')
                        or s['rack'] in network.get('racks',[])):
                        iface['networks'][network['name']] = deepcopy(network)
                        break

    server = {'type': s['role'],
              'rack': s.get('rack'),
              'addr': s['ip-addr'],
              'if-model': server_role.get('interface-model', 'default'),
              'disk-model': disk_model,
              'interfaces': server_interfaces,
              'nic_map': nic_mappings.get(s.get('nic-mapping', 'none')),
              'available': True}
    servers[s['role']].append(server)


# Fix up parents
for cp_name, cp in control_planes.iteritems():
    cp['region-list'] = []
    if 'region-name' in cp:
        cp['region-list'].append(cp['region-name'])

    if 'parent' in cp:
        cp['parent-cp'] = control_planes[cp['parent']]


# Add child region names to parent
for cp_name, cp in control_planes.iteritems():

    if 'parent' in cp:
        if 'region-name' in cp:
            cp['parent-cp']['region-list'].append(cp['region-name'])


# Add common services to all Control Planes
for cp_name, cp in control_planes.iteritems():
    for cluster in cp['member-groups']:
        cluster['service-components'].extend(cp.get('common-service-components', []))

    for r in cp.get('resource-nodes', []):
        r['service-components'].extend(cp.get('common-service-components', []))


# Walk through the Control Planes Allocating servers

names={}
for cp_name in sorted(control_planes):
    cp = control_planes[cp_name]

    hostname_data = cloud_data.get('hostname-data',
                                   {'host-prefix': cloud_data['name'],
                                    'member-prefix': '-m',
                                    'rack-prefix': '-r'})
    cp['hostname-data'] = hostname_data

    # Try to get from separate rack first
    for cluster in cp['member-groups']:
        cluster['servers'] = {}
        cluster_racks = set()
        for s in servers[cluster['server-role']]:
            server_rack = s.get('rack', '')
            cp_racks = cp.get('racks', [])
            if (s['available']
                and (not server_rack
                     or not cp_racks
                     or server_rack in cp_racks)
                and server_rack not in cluster_racks):

                s['available'] = False
                s['components'] = cluster['service-components']
                s['region'] = cp['region-name']
                if server_rack:
                    cluster_racks.add(server_rack)

                name = "%s-%s-%s" % (hostname_data['host-prefix'],
                                     cp['name'],
                                     cluster['name'])
                if server_rack:
                    name += '%s%s' % (
                        hostname_data.get('rack-prefix', ''), server_rack)

                index = names.get(name,0)
                index += 1
                names[name] = index
                s['name'] =  name + "%s%d" % (
                       hostname_data.get('member-prefix', ''), index)

                cluster['servers'][s['name']] = s
                s['member_id'] = len(cluster['servers'])

                if len(cluster['servers']) == cluster['member-count']:
                    break


    if len(cluster['servers']) != cluster['member-count']:
        print("Couldn't allocate %d servers for %s:%s" %
              (cluster['member-count'], cp_name, cluster['name']))

        for s in cluster['servers']:
            print ("addr: %s rack: %s " % (s['addr'], s['rack']))
        sys.exit(2)



    if 'resource-nodes' in cp:

        # Convert the list to a dict so we can reference it by name
        resource_nodes = {}
        for r in cp['resource-nodes']:
            resource_nodes[r['name']] = r
        cp['resource-nodes'] = resource_nodes

        for r_name, resources in cp['resource-nodes'].iteritems():
            resources['servers'] = {}
            for s in servers[resources['server-role']]:
                server_rack = s.get('rack', '')
                cp_racks = cp.get('racks', [])
                if (s['available']
                    and (not server_rack
                         or not cp_racks
                         or server_rack in cp_racks)):

                    s['available'] = False
                    s['components'] = resources['service-components']
                    s['region'] = cp['region-name']

                    name = "%s-%s-%s" % (
                               hostname_data['host-prefix'],
                               cp['name'],
                               resources.get('resource-prefix', cluster['name']))

                    if server_rack:
                        name += '%s%s' % (
                            hostname_data.get('rack-prefix', ''), server_rack)

                    index = names.get(name,0)
                    index += 1
                    names[name] = index
                    s['name'] =  name + "%04d" % (index)

                    resources['servers'][s['name']] = s



# Resolve the networks for each server
for cp_name, cp in control_planes.iteritems():
    for cluster in cp['member-groups']:
        for name, s in cluster['servers'].iteritems():

            resolve_server_networks(s, components, network_groups, network_addresses)

    if 'resource-nodes' in cp:
        for r_name, resources in cp['resource-nodes'].iteritems():
            for name, s in resources['servers'].iteritems():
                resolve_server_networks(s, components, network_groups, network_addresses)



# Populate the service views
service_view = {'by_region': {},
                'by_service': {},
                'by_rack': {}}

for cp_name in sorted(control_planes):
    cp = control_planes[cp_name]
    cp_service_view = service_view['by_region'][cp_name] = {}

    cp['components'] = {}

    for cluster in cp['member-groups']:
        for name, s in cluster['servers'].iteritems():
            for component_name in s['components']:
                component = components.get(component_name, {})
                component_parent = component.get('service', 'foundation')

                # Add to list of components in this cp
                if component_name not in cp['components']:
                    cp['components'][component_name] = {'hosts': []}
                cp['components'][component_name]['hosts'].append(s['name'])

                # Add to by region service view
                if component_parent not in cp_service_view:
                    cp_service_view[component_parent] = {}
                if component_name not in cp_service_view[component_parent]:
                    cp_service_view[component_parent][component_name] = []
                cp_service_view[component_parent][component_name].append(s['name'])

                # Add to by_service service view
                if component_parent not in service_view['by_service']:
                    service_view['by_service'][component_parent] = {}
                if cp_name not in service_view['by_service'][component_parent]:
                    service_view['by_service'][component_parent][cp_name] = {}
                if component_name not in service_view['by_service'][component_parent][cp_name]:
                    service_view['by_service'][component_parent][cp_name][component_name] = []
                service_view['by_service'][component_parent][cp_name][component_name].append(s['name'])

                # Add to by_rack service view
                if s['rack'] not in service_view['by_rack']:
                    service_view['by_rack'][s['rack']] = {}
                if s['name'] not in service_view['by_rack'][s['rack']]:
                    s_view = service_view['by_rack'][s['rack']][s['name']] = {}
                if component_parent not in s_view:
                    s_view[component_parent] = []
                if component_name not in s_view[component_parent]:
                    s_view[component_parent].append(component_name)

    if 'resource-nodes' in cp:

        for r_name, resources in cp['resource-nodes'].iteritems():
            for name, s in resources['servers'].iteritems():
                for component_name in s['components']:
                    component = components.get(component_name, {})
                    component_parent = component.get('service', 'foundation')

                    # Add to list of components in this cp
                    if component_name not in cp['components']:
                        cp['components'][component_name] = {'hosts': []}
                    cp['components'][component_name]['hosts'].append(s['name'])

                    # Add to by region service view
                    if component_parent not in cp_service_view:
                        cp_service_view[component_parent] = {}
                    if component_name not in cp_service_view[component_parent]:
                        cp_service_view[component_parent][component_name] = []
                    cp_service_view[component_parent][component_name].append(s['name'])

                    # Add to by_service service view
                    if component_parent not in service_view['by_service']:
                        service_view['by_service'][component_parent] = {}
                    if cp_name not in service_view['by_service'][component_parent]:
                        service_view['by_service'][component_parent][cp_name] = {}
                    if component_name not in service_view['by_service'][component_parent][cp_name]:
                        service_view['by_service'][component_parent][cp_name][component_name] = []
                    service_view['by_service'][component_parent][cp_name][component_name].append(s['name'])

                    # Add to by_rack service view
                    if s['rack'] not in service_view['by_rack']:
                        service_view['by_rack'][s['rack']] = {}
                    if s['name'] not in service_view['by_rack'][s['rack']]:
                        s_view = service_view['by_rack'][s['rack']][s['name']] = {}
                    if component_parent not in s_view:
                        s_view[component_parent] = []
                    if component_name not in s_view[component_parent]:
                        s_view[component_parent].append(component_name)

#
# Add network routes and VIPs
#

for cp_name in sorted(control_planes):
    cp = control_planes[cp_name]

    # build a list of all servers in the region
    region_servers = []
    for cluster in cp['member-groups']:
        for s_name, s in cluster['servers'].iteritems():
            region_servers.append(s)

    for r_name, resources in cp.get('resource-nodes', {}).iteritems():
        for s_name, s in resources['servers'].iteritems():
            region_servers.append(s)

    # Find all of the networks, services and endpoints in this region
    region_components = set()
    region_networks = set()
    region_network_groups = set()
    region_endpoints = {}

    for cluster in cp['member-groups']:
        for component_name in cluster['service-components']:
            region_components.add(component_name)

    for s in region_servers:
        for iface_name, iface in s['interfaces'].iteritems():
            for net_name, net in iface['networks'].iteritems():
                region_networks.add(net_name)
                region_network_groups.add(net['network-group'])
                for component_name, ep in net['endpoints'].iteritems():
                    if component_name not in region_endpoints:
                        region_endpoints[component_name] = {'network-group': net['network-group'],
                                                            'host-tls': ep['use-tls'],
                                                            'hosts': [],
                                                            'has-vip': False}
                    region_endpoints[component_name]['hosts'].append(net['hostname'])


    region_routes = {}
    # Add routes to each network for any other networks in the same group in this region
    for net_name in region_networks:
        net = networks[net_name]
        if net_name not in region_routes:
            region_routes[net_name] = []
        for other_net_name in region_networks:
            other_net = networks[other_net_name]
            if (net != other_net
                and net['network-group'] == other_net['network-group']):
                region_routes[net_name].append(other_net['cidr']+' ('+other_net_name+')')

        # Add other routes required by this group
        for route in network_groups[net['network-group']].get('routes',[]):
            if route in network_groups:
               # If this is a route to another group, add in all of the netwokrs in that group
               for other_net in network_groups[route].get('networks', []):
                   region_routes[net_name].append(other_net['cidr']+' ('+route+')')
            else:
                # Add in routes such a "deault"
                region_routes[net_name].append(route)

    # Add the routes for each server
    for s in region_servers:
        for iface_name, iface in s['interfaces'].iteritems():
            for net_name, net in iface['networks'].iteritems():
                net['routes'] = region_routes.get(net['name'],[])

    # Find networks that have Load Balancers
    vip_networks = {}
    vips_by_role = {}
    for lb in load_balancers:
        address = ''
        shared_address = ''
        vip_net_group = lb.get('network-group', 'External')

        vip_provider = lb.get('provider', 'external')
        if vip_provider == 'external':
            vip_net = "External"
            for ext_ep in lb.get('vip-address', []):
                if ext_ep['region'] == cp.get('region-name', '') or ext_ep['region'] == "*":
                    address = ext_ep.get('ip-address' , '???')
                    cert_file = ext_ep.get('cert-file', '')
            if not address:
                continue
        else:
            for net in network_groups[vip_net_group]['networks']:
                if net['name'] in region_networks:
                    vip_net = net['name']
                    break
            cert_file = lb.get('cert-file', '')

            # If services on this LB share a vip allocate it now

            if lb.get('shared-address', True):

                vip_name = "%s-%s-vip-%s-%s" % (
                         hostname_data['host-prefix'],
                         cp['name'],
                         lb.get('name', 'lb'),
                         network_groups[vip_net_group].get(
                                       'hostname-suffix',
                                       network_groups[vip_net_group]['name']))

                address = allocate_address(network_addresses[net['name']],
                                           "vip %s" % (lb['name']),
                                           vip_name, net['name'])

        #
        # Loop through all services in thie region, and find which need to have a vip on this LB
        # A service might be excplictly on a lb, or included as "default"
        #

        #
        # When not sharing VIPs between services we need to keep track of them
        #
        component_vips = {}

        for component_name, component_endpoint in region_endpoints.iteritems():

             lb_components = lb.get('components', []) + lb.get('tls-components', [])

             if (component_name in lb_components or "default" in lb_components):
                for component_ep in components.get(component_name, {}).get('endpoints', []):
                    if component_ep.get('has-vip'):

                        # Check Service allows this VIP role
                        vip_roles = [r for r in lb.get('roles',[]) if r in component_ep.get('roles',[])]
                        if not vip_roles:
                            continue

                        # So now we know that ths component should have a VIP on this LB
                        # for one or more of its roles.
                        if 'internal' in vip_roles:
                            region_endpoints[component_name]['has-vip'] = True

                        # Create an entry in vip_networks
                        # for this network if it doesn't already exist

                        if vip_net not in vip_networks:
                             vip_networks[vip_net] = []
                        vip_network = vip_networks[vip_net]

                        # Build an Alias for the VIP for this component
                        vip_alias = "%s-%s-vip-%s-%s" % (
                                 hostname_data['host-prefix'],
                                 cp['name'],
                                 components[component_name]['mnemonic'],
                                 network_groups[vip_net_group].get(
                                        'hostname-suffix',
                                        network_groups[vip_net_group]['name']))

                        vip_public_alias = "%s-%s-vip-public-%s-%s" % (
                               hostname_data['host-prefix'],
                               cp['name'],
                               components[component_name]['mnemonic'],
                               network_groups[vip_net_group].get(
                                    'hostname-suffix',
                                    network_groups[vip_net_group]['name']))

                        vip_admin_alias = "%s-%s-vip-admin-%s-%s" % (
                               hostname_data['host-prefix'],
                               cp['name'],
                               components[component_name]['mnemonic'],
                               network_groups[vip_net_group].get(
                                    'hostname-suffix',
                                    network_groups[vip_net_group]['name']))

                        # If we have a shared address create an alias
                        if lb.get('shared-address', True):
                            if 'internal' in vip_roles:
                                add_hostname_alias(net, address, vip_alias)
                            if 'public' in vip_roles:
                                add_hostname_alias(net, address, vip_public_alias)
                            if 'admin' in vip_roles:
                                add_hostname_alias(net, address, vip_admin_alias)

                        else:
                            # See if we already have an address for this VIP
                            if component_name in component_vips:
                                address = component_vips[component_name]
                                print "Got address %s for %s" % (address, component_name)
                            else:
                                # Allocate an addtress for the vip for this component
                                if 'internal' in vip_roles:
                                    vip_name = vip_alias
                                elif 'public' in vip_roles:
                                    vip_name = vip_public_alias
                                elif 'admin' in vip_roles:
                                    vip_name =  vip_admin_alias

                                address = allocate_address(network_addresses[net['name']],
                                                           "vip for %s" % component_name,
                                                           vip_name, net['name'])
                                component_vips[component_name] = address

                            if 'internal' in vip_roles and vip_name != vip_alias:
                                add_hostname_alias(net, address, vip_alias)
                            if 'public' in vip_roles and vip_name != vip_public_alias:
                                add_hostname_alias(net, address, vip_public_alias)
                            if 'admin' in vip_roles and vip_name != vip_admin_alias:
                                add_hostname_alias(net, address, vip_admin_alias)

                        # Always use the service name / alias for clarity in haproxy config
                        if 'internal' in vip_roles:
                            vip_hostname = vip_alias
                        elif 'admin' in vip_roles:
                            vip_hostname = vip_admin_alias
                        elif 'public' in vip_roles:
                            vip_hostname = vip_public_alias
                        else:
                            # Not sure this can happen, but just in case
                            vip_hostname = vip_name

                        # Is this a component or an tls_component
                        if component_name in lb.get('components', []):
                            use_tls = False
                        elif (component_name in lb.get('tls-components', [])
                              or "default" in lb.get('tls-components', [])):
                            vip_tls = True
                        else:
                            vip_tls = False

                        # Create an entry for the vip for this component
                        vip_data = {'component-name': component_name,
                                    'provider': lb.get('provider', "External"),
                                    'port': component_ep['port'],
                                    'target': component_endpoint['network-group'],
                                    'hosts': component_endpoint['hosts'],
                                    'host-tls': component_endpoint['host-tls'],
                                    'roles': vip_roles,
                                    'advertise': False,
                                    'address': address,
                                    'hostname': vip_hostname,
                                    'vip-tls': vip_tls
                                    }

                        if 'internal' in vip_roles:
                            vip_data['alias'] = vip_alias
                        if 'admin' in vip_roles:
                            vip_data['admin_alias'] = vip_admin_alias
                        if 'public' in vip_roles:
                            vip_data['public_alias'] = vip_public_alias

                        if lb.get('external-name'):
                            vip_data['external-name'] = lb['external-name']

                        if cert_file:
                            vip_data['cert-file'] = \
                                cloud_data['certs-dir'] + '/' + cert_file

                        if 'vip-options' in component_ep:
                            vip_data['vip-options'] = component_ep['vip-options']

                        if 'vip-check' in component_ep:
                            vip_data['vip-check'] = component_ep['vip-check']

                        # Record if the VIP is on this LB as part of the default set
                        if "default" in lb.get('components', []) + lb.get('tls-components', []):
                            vip_data['default'] = True
                        else:
                            vip_data['default'] = False

                            # Keep track of the components added by name so we can remove
                            # any entries for those components added to the list via a
                            # "default" match for the same role.
                            for role in vip_roles:
                                if role not in vips_by_role:
                                    vips_by_role[role] = []
                                vips_by_role[role].append(component_name)

                        # See if this endpoint should be advertised
                        if 'advertises-to-services' in \
                                     components[component_name]:
                            vip_data['advertise'] = True

                        vip_networks[vip_net].append(vip_data)


    # Now we have a full list of LBs on all networks build a list of
    # load-balancers by provider and service for this region
    # At the same time as we're going through this list build a list of
    # all of the endpoints that are to be advertised
    cp['load-balancers'] = {}
    cp['advertises'] = {}
    for vip_net_name, vip_net in vip_networks.iteritems():
        for vip_data in vip_net:
            vip_component_name = vip_data['component-name']

            # If this VIP was added as a result of a default service role
            # remove any roles that also exist on other LB in this region
            if vip_data['default']:
                default_roles = []
                for role in vip_data['roles']:
                    if not vip_component_name in vips_by_role.get(role, []):
                        default_roles.append(role)
                vip_data['roles'] = default_roles

            if vip_data['roles']:

                if not vip_data['provider'] in cp['load-balancers']:
                    cp['load-balancers'][vip_data['provider']] = {}

                if not vip_component_name in cp['load-balancers'][vip_data['provider']]:
                    cp['load-balancers'][vip_data['provider']][vip_component_name] = \
                                   {'hosts': vip_data['hosts'],
                                    'host-tls': vip_data['host-tls'],
                                    'networks': []
                                   }

                    if 'vip-options' in vip_data:
                        cp['load-balancers'][vip_data['provider']] \
                          [vip_component_name]['vip-options'] = \
                                    vip_data['vip-options']

                    if 'vip-check' in vip_data:
                        cp['load-balancers'][vip_data['provider']] \
                          [vip_component_name]['vip-check'] = \
                                    vip_data['vip-check']

                lb_networks = cp['load-balancers'][vip_data['provider']][vip_component_name]['networks']


                lb_data = {'hostname': vip_data['hostname'],
                           'ip-address':  vip_data['address'],
                           'port': vip_data['port'],
                           'roles': vip_data['roles'],
                           'vip-tls': vip_data['vip-tls']}

                if 'cert-file' in vip_data:
                    lb_data['cert-file'] = vip_data['cert-file']

                lb_networks.append(lb_data)

                if vip_data.get('advertise'):
                    if not vip_component_name in cp['advertises']:
                        cp['advertises'][vip_component_name] = {}

                    for r in vip_data['roles']:
                        if vip_data['vip-tls']:
                            protocol = 'https'
                        else:
                            protocol = 'http'

                        # Only use ip address or the external name form the LB on public urls
                        if r == 'public':
                            url = "%s://%s:%s" % (protocol,
                                                  vip_data.get('external-name', vip_data['address']),
                                                  vip_data['port'])
                        else:
                            url = "%s://%s:%s" % (protocol,
                                                  vip_data['hostname'],
                                                  vip_data['port'])


                        data = {'hostname': vip_data['hostname'],
                                'ip_address': vip_data['address'],
                                'port': vip_data['port'],
                                'protocol': protocol,
                                'use_tls': vip_data['vip-tls'],
                                'url': url}
                        cp['advertises'][vip_component_name][r] = data


    #
    # Build a list of endpoints for the region
    #
    #  access - what do clients call
    #  bind  - what does the sevice listen on
    #  tls_term - what does the tls terminator listen on
    #  tls_init - what does an tls initiator connect to
    endpoints = {}
    for component_name, endpoint in region_endpoints.iteritems():

        for component_ep in components.get(component_name, {}).get('endpoints', []):
            if 'internal' in component_ep.get('roles', []):
                endpoints[component_name] = {}
                if endpoint['has-vip']:
                    for vip_net_name, vip_net in vip_networks.iteritems():
                        for vip_data in vip_net:
                            vip_component_name = vip_data['component-name']
                            if (component_name == vip_component_name
                                and 'internal' in vip_data['roles']):
                                if vip_data['vip-tls'] and component_ep.get('tls-initiator', False):
                                    endpoints[component_name]['access'] = \
                                        {'address':  '127.0.0.1',
                                         'hostname': 'localhost',
                                         'port': vip_data['port'],
                                         'use-tls': False}
                                    endpoints[component_name]['tls-init'] = \
                                        {'address':  vip_data['address'],
                                         'hostname': vip_data['alias'],
                                         'port': vip_data['port'],
                                         'use-tls': vip_data['vip-tls']}
                                else:
                                    endpoints[component_name]['access'] = \
                                        {'address':  vip_data['address'],
                                         'hostname': vip_data['alias'],
                                         'port': vip_data['port'],
                                         'use-tls': vip_data['vip-tls']}

                                if endpoint['host-tls']:
                                    endpoints[component_name]['bind'] = \
                                        {'address':  '127.0.0.1',
                                         'port': vip_data['port']}
                                    endpoints[component_name]['tls-term'] = \
                                        {'network_group':  vip_data['target'],
                                         'port': vip_data['port']}
                                else:
                                    endpoints[component_name]['bind'] = \
                                        {'network_group':  vip_data['target'],
                                         'port': vip_data['port']}

                            if (component_name == vip_component_name
                                and 'admin' in vip_data['roles']):
                                if vip_data['vip-tls'] and component_ep.get('tls-initiator', False):
                                    endpoints[component_name]['admin'] = \
                                        {'address':  '127.0.0.1',
                                         'hostname': 'localhost',
                                         'port': vip_data['port'],
                                         'use-tls': False}
                                    endpoints[component_name]['admin-tls-init'] = \
                                        {'address':  vip_data['address'],
                                         'hostname': vip_data['admin_alias'],
                                         'port': vip_data['port'],
                                         'use-tls': vip_data['vip-tls']}
                                else:
                                    endpoints[component_name]['admin'] = \
                                        {'address':  vip_data['address'],
                                         'hostname': vip_data['admin_alias'],
                                         'port': vip_data['port'],
                                         'use-tls': vip_data['vip-tls']}

                                if endpoint['host-tls']:
                                    endpoints[component_name]['admin-bind'] = \
                                        {'address':  '127.0.0.1',
                                         'port': vip_data['port']}
                                    endpoints[component_name]['admin-tls-term'] = \
                                        {'network_group':  vip_data['target'],
                                         'port': vip_data['port']}
                                else:
                                    endpoints[component_name]['admin-bind'] = \
                                        {'network_group':  vip_data['target'],
                                         'port': vip_data['port']}
                else:
                    # No VIP - so add list of members instead
                    endpoints[component_name]['access'] = \
                        {'members':  endpoint['hosts'],
                         'port': component_ep['port'],
                         'use-tls': endpoint['host-tls']}

                    if endpoint['host-tls']:
                        endpoints[component_name]['bind'] = \
                            {'address':  '127.0.0.1',
                             'port': component_ep['port']}
                        endpoints[component_name]['tls-term'] = \
                            {'network_group':  endpoint['network-group'],
                             'port': component_ep['port']}
                    else:
                        endpoints[component_name]['bind'] = \
                            {'network_group':  endpoint['network-group'],
                             'port': component_ep['port']}

    cp['endpoints'] = endpoints
    cp['vip_networks'] = vip_networks

    # Add internal endpoints to services
    for component_name, component in cp['components'].iteritems():
        vip_found = False
        for vip_net_name, vip_net in vip_networks.iteritems():
            for vip_data in vip_net:
                vip_component_name = vip_data['component-name']
                if (component_name == vip_component_name
                    and 'internal' in vip_data['roles']):
                    vip_found = True
                    component['endpoint'] = {'ip_address': vip_data['address'],
                                           'port': vip_data['port']}
                    component['targets'] = vip_data['hosts']
        if not vip_found and component_name in cp['endpoints']:
            component['targets'] = cp['endpoints'][component_name]['access']['members']
            component['endpoint'] = {'port': cp['endpoints'][component_name]['access']['port']}


    # Build a list of members by service
    cp ['members'] = {}
    for component_name, r_endpoint in region_endpoints.iteritems():
        for endpoint in components[component_name].get('endpoints', []):
            if not component_name in cp['members']:
                cp['members'][component_name] = {'hosts': r_endpoint['hosts'],
                                                 'ports': {}}
                member_data = cp['members'][component_name]
            for role in endpoint.get('roles', []):
                if not role in member_data['ports']:
                    member_data['ports'][role] = []
                member_data['ports'][role].append(endpoint['port'])


    # Resolve service consumption
    for component_name, component in cp['components'].iteritems():
        for consumes in components.get(component_name, {}).get('consumes-services', {}):
            needs = consumes['service-name']
            if needs in components:
                ref_component_name = components[needs]
            elif needs in components_by_mnemonic:
                ref_component_name = components_by_mnemonic[needs]['name']
            else:
                continue

            if not ref_component_name in cp['components']:
                continue

            if not 'consumes' in component:
                component['consumes'] = {}


            if 'endpoint' in cp['components'][ref_component_name]:
                component['consumes'][ref_component_name] = cp['components'][ref_component_name]['endpoint']
            else:
                # No VIP
                if not ref_component_name in cp['endpoints']:
                    print "Warning: can't find endpoint for %s needed by %s" % (ref_component_name, component_name)
                else:
                    component['consumes'][ref_component_name] = cp['endpoints'][ref_component_name]['access']


# Build a list of allocated addresses
allocated_addresses={}
for group_name, group  in network_groups.iteritems():
    allocated_addresses[group_name] = {}
    for network in group['networks']:
        allocated_addresses[group_name][network['name']] = {}
        for addr in network_addresses[network['name']]:
            if not addr['free']:
                allocated_addresses[group_name][network['name']][addr['addr']] = {'host': addr['host'],
                                                                                  'used-by': addr['used-by']}

######################
#
# End of Generators
#
######################

cloud = {
    'cloud_info': cloud_data,
    'regions': control_planes,
    'service_view': service_view,
    'address_allocations': allocated_addresses,
    'servers': servers
}

if json_out:
    with open(json_out, 'w') as fp:
        json.dump(cloud, fp)

######################
#
# Print Output Builders
#
######################

if not quiet:
    for cp_name in sorted(control_planes):
        print_cp(control_planes[cp_name])

    print
    print "Service View"
    print
    for cp_name in sorted(service_view['by_region']):
        cp_view = service_view['by_region'][cp_name]
        print ("Control Plane: " + cp_name)
        for service_name, service in cp_view.iteritems():
            print "  %s" % (service_name)
            for component_name, hosts in service.iteritems():
                print "      %s" % (component_name)
                for host in hosts:
                    print "         %s" % (host)
        print

    print
    print "Address Allocations"
    print
    for group_name, group in allocated_addresses.iteritems():
        print group_name
        for network_name, network in group.iteritems():
            print "  %s" % network_name
            for addr in sorted(network):
                data = network[addr]
                print "    %-16s %s" % (addr, data['host'])
                aliases = host_aliases.get(group_name,{}).get(network_name,{}).get(addr,[])
                for name in aliases:
                    print "    %-16s %s" % ("", name)
        print



######################
#
# Network File Builders
#
######################
if ansible_out:

    # Hosts file
    build_etc_hosts(ansible_out, cloud_data['name'], allocated_addresses, host_aliases)


######################
#
# Ansible Vars Builders
#
######################


# Generate Ansible Vars
if ansible_out:

    # Group Vars
    for cp_name,cp in control_planes.iteritems():
        build_ansible_group_vars(ansible_out, cloud_data['name'], cp, components)

    build_ansible_group_vars_all(ansible_out, cloud, components,
                                 service_view['by_region'])


    # Host Vars
    for cp_name,cp in control_planes.iteritems():
        for cluster in cp['member-groups']:
            for s_name, s in cluster['servers'].iteritems():
                build_ansible_host_vars(ansible_out, s, cp['endpoints'], components)

        for r_name, resources in cp.get('resource-nodes', {}).iteritems():
            for s_name, s in resources['servers'].iteritems():
                build_ansible_host_vars(ansible_out, s, cp['endpoints'], components)

    # Hosts
    build_ansible_hosts(ansible_out, cloud, components, servers)


