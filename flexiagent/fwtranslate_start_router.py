#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################


import fwglobals
import fwutils
import fwlte
import fw_nat_command_helpers
import fwtranslate_add_tunnel

# start_router
# --------------------------------------
# Translates request:
#
#    {
#      "entity": "agent",
#      "message": "start-router",
#      "params": {
#        "dev_id": [
#           "0000:00:08.00",
#           "0000:00:09.00"
#        ]
#      }
#    }
#|
# into list of commands:
#
#    1. generates ospfd.conf for FRR
#    01. print CONTENT > ospfd.conf
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#
#    2.Linux_sh1.sh
#    ------------------------------------------------------------
#    02. sudo ip link set dev enp0s8 down &&
#        sudo ip addr flush dev enp0s8
#    03. sudo ip link set dev enp0s9 down &&
#        sudo ip addr flush dev enp0s9
#
#    3.vpp.cfg
#    ------------------------------------------------------------
#    04. sudo systemtctl start vpp
#    05. sudo vppctl enable tap-inject
#
#
def start_router(params=None):
    """Generate commands to start VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    # Initialize some stuff before router start
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_start_router_before"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "Prepare router VPP activities"
    cmd['revert'] = {}
    cmd['revert']['func']   = "_on_stop_router_after"
    cmd['revert']['object'] = "fwglobals.g.router_api"
    cmd['revert']['descr']  = "fwrouter_api._on_stop_router_after()"
    cmd_list.append(cmd)

    vpp_startup_conf_dev_ids = [] # only interfaces that should be in the dpdk section in startup.conf
    linux_if_name_list       = [] # dpdk and non-dpdk interfaces should be listed here
    vmxnet3_dev_id_list      = []
    dev_ids                  = []

    interfaces = fwglobals.g.router_cfg.get_interfaces()
    for params in interfaces:
        dev_ids.append(params['dev_id'])
        linux_if  = fwutils.dev_id_to_linux_if(params['dev_id'])
        if linux_if:

            # Collect names of interfaces that should be controlled by VPP.
            # We have to shutdown them before VPP start.
            #
            linux_if_name_list.append(linux_if)

            # Non-dpdk interface should not appear in /etc/vpp/startup.conf because they don't have a pci address.
            # Additional spacial logic for these interfaces is at add_interface translator
            if fwutils.is_non_dpdk_interface(params['dev_id']):
                # LTE interface requires startup conf entry for creating tap interface
                if fwlte.is_lte_interface_by_dev_id(params['dev_id']):
                    vpp_startup_conf_dev_ids.append(params['dev_id'])
                continue

            # Mark 'vmxnet3' interfaces as they need special care:
            #   They require additional VPP call vmxnet3_create on start
            #      and complement vmxnet3_delete on stop
            if fwutils.dev_id_is_vmxnet3(params['dev_id']):
                vmxnet3_dev_id_list.append(params['dev_id'])

            vpp_startup_conf_dev_ids.append(params['dev_id'])

    vpp_filename = fwglobals.g.VPP_CONFIG_FILE

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "store_assigned_dev_ids"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['params']  = { 'dev_ids':  dev_ids }
    cmd['cmd']['descr']   = "store assigned dev ids in router_api DB"
    cmd['revert'] = {}
    cmd['revert']['func']    = "store_assigned_dev_ids"
    cmd['revert']['object']  = "fwglobals.g.router_api"
    cmd['revert']['params']  = { 'dev_ids':  [] }
    cmd['revert']['descr']   = "reset assigned dev ids in router_api DB"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "vpp_coredump_setup_startup_conf"
    cmd['cmd']['module']  = "fw_vpp_coredump_utils"
    cmd['cmd']['descr']   = "enable coredump to %s" % vpp_filename
    cmd['cmd']['params']  = { 'vpp_config_filename' : vpp_filename, 'enable': 1 }
    cmd_list.append(cmd)

    # Clean iptables
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = f"clean iptables"
    cmd['cmd']['params']  = {'cmd': 'iptables -F INPUT && iptables -F OUTPUT'}
    cmd['revert'] = {}
    cmd['revert']['func']    = "exec"
    cmd['revert']['module']  = "fwutils"
    cmd['revert']['descr']   = f"clean iptables"
    cmd['revert']['params']  = {'cmd': 'iptables -F INPUT && iptables -F OUTPUT'}
    cmd_list.append(cmd)

    # Setup HQoS worker to startup conf and update QoS context with system settings
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "Setup hqos"
    cmd['cmd']['module']  = 'fwutils'
    cmd['cmd']['func']    = 'vpp_setup_hqos'
    cmd['cmd']['params']  = {
        'vpp_config_filename' : vpp_filename,
        'is_add'              : True,
        'num_interfaces'      : len(vpp_startup_conf_dev_ids),
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "Remove hqos setup"
    cmd['revert']['module'] = 'fwutils'
    cmd['revert']['func']   = 'vpp_setup_hqos'
    cmd['revert']['params'] = {
        'vpp_config_filename' : vpp_filename,
        'is_add'              : False,
        'num_interfaces'      : len(vpp_startup_conf_dev_ids),
    }
    cmd_list.append(cmd)

    # Note: Change of command order can have impact on working:
    # The setting up of hqos workers and required update of cpu workers by the
    # above 'vpp_startup_conf_hqos' function need to precede the dpdk section
    # configuration by the below 'vpp_startup_conf_add_dpdk_config'

    # Add interfaces to the vpp configuration file, thus creating whitelist.
    # If whitelist exists, on bootup vpp captures only whitelisted interfaces.
    # Other interfaces will be not captured by vpp even if they are DOWN.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "vpp_startup_conf_add_dpdk_config"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = "add devices to %s" % vpp_filename
    cmd['cmd']['params']  = { 'vpp_config_filename' : vpp_filename, 'devices': vpp_startup_conf_dev_ids }
    cmd['revert'] = {}
    cmd['revert']['func']   = "vpp_startup_conf_remove_dpdk_config"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "remove devices from %s" % vpp_filename
    cmd['revert']['params'] = { 'vpp_config_filename' : vpp_filename}
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "backup_linux_netplan_files"
    cmd['cmd']['module']  = "fwnetplan"
    cmd['cmd']['descr'] = "backup Linux netplan files"
    cmd['revert'] = {}
    cmd['revert']['func']    = "restore_linux_netplan_files_created_by_vpp"
    cmd['revert']['module']  = "fwnetplan"
    cmd['revert']['descr'] = "restore linux netplan files"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "set_fallback_dns"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = "set fallback DNS"
    cmd['revert'] = {}
    cmd['revert']['func']    = "unset_fallback_dns"
    cmd['revert']['module']  = "fwutils"
    cmd['revert']['descr']   = "set fallback DNS"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['params']  = { 'cmd': 'sudo modprobe vfio-pci  &&  (echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)' }
    cmd['cmd']['descr']   = "enable vfio-pci driver in Linux"
    cmd_list.append(cmd)

    # Shutdown interfaces, so VPP could capture them on start.
    # IMPORTANT: do this as close as possible to the 'systemctl start vpp' invocation
    #            to reduce chances they go up just before VPP start due to some Linux activity,
    #            like DHCP renegotiation, netplan apply, etc.
    # To neutralize the 'netplan apply' completely, remove interfaces from netplan yaml-s.
    #
    if linux_if_name_list:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "netplan_unload_assigned_ports"
        cmd['cmd']['module']  = "fwnetplan"
        cmd['cmd']['descr']   = f"Unload interfaces from {fwglobals.config.exec_file_suffix} netplan files"
        cmd['cmd']['params']  = { 'assigned_linux_interfaces' : linux_if_name_list }
        cmd_list.append(cmd)
        for linux_if in linux_if_name_list:
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['func']   = "exec"
            cmd['cmd']['module'] = "fwutils"
            cmd['cmd']['params'] = { 'cmd': "sudo ip link set dev %s down && sudo ip addr flush dev %s" % (linux_if,linux_if ) }
            cmd['cmd']['descr']  = "shutdown dev %s in Linux" % linux_if
            cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['params']  = { 'cmd': 'sudo systemctl start vpp' }
    cmd['cmd']['descr']   = "start vpp"
    cmd['revert'] = {}
    cmd['revert']['func']   = "stop_vpp"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "stop vpp"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']      = "connect_to_vpp"
    cmd['cmd']['object']    = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']     = "connect to vpp papi"
    cmd['revert'] = {}
    cmd['revert']['func']   = "disconnect_from_vpp"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr']  = "disconnect from vpp papi"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "vpp_enable_tap_inject"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = "enable tap-inject"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "call_vpp_api"
    cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']   = "enable NAT pluging and configure it"
    cmd['cmd']['params']  = {
                    'api':  "nat44_plugin_enable_disable",
                    'args': {
                        'enable':   1,
                        'flags':    1,      # nat.h: _(0x01, IS_ENDPOINT_DEPENDENT)
                        'sessions': 100000  # Defaults: users=1024, sessions=10x1024, in multicore these parameters are per worker thread
                    }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "call_vpp_api"
    cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr']   = "Enable ACL Firewall counters"
    cmd['cmd']['params']  = {
                    'api':  "acl_stats_intf_counters_enable",
                    'args': {
                        'enable':   True
                    }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "exec"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['params'] = { 'cmd': "sudo vppctl ip route add 255.255.255.255/32 via punt" }
    cmd['cmd']['descr'] = "punt ip broadcast"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "reset_config"
    cmd['cmd']['object'] = "fwglobals.g.dhcp_server"
    cmd['cmd']['params']  = { 'assigned_linux_interfaces' : linux_if_name_list }
    cmd['cmd']['descr']  = "backup original DHCP server files and create flexiWAN config"
    cmd['revert'] = {}
    cmd['revert']['func']   = "restore_config"
    cmd['revert']['object'] = "fwglobals.g.dhcp_server"
    cmd['revert']['descr']  = "restore original DHCP server files"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['params']  = { 'cmd': 'sudo systemctl start frr; if [ -z "$(pgrep frr)" ]; then exit 1; fi' }
    cmd['cmd']['descr']   = "start frr"
    cmd['revert'] = {}
    cmd['revert']['func']   = "exec"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr']  = "stop frr"
    cmd['revert']['params'] = { 'cmd': 'sudo systemctl stop frr' }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "frr_setup_config"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['descr'] = "Setup FRR configuration"
    cmd_list.append(cmd)

    # Setup Global VPP NAT parameters
    # Post VPP NAT/Firewall changes - The param need to be false
    cmd_list.append(fw_nat_command_helpers.get_nat_forwarding_config(False))

    # vmxnet3 interfaces are not created by VPP on bootup, so create it explicitly
    # vmxnet3.api.json: vmxnet3_create (..., pci_addr, enable_elog, rxq_size, txq_size, ...)
    # Note we do it here and not on 'add-interface' as 'modify-interface' is translated
    # into 'remove-interface' and 'add-interface', so we want to avoid deletion
    # and creation interface on every 'modify-interface'. There is no sense to do
    # that and it causes problems in FIB, when default route interface is deleted.
    for dev_id in vmxnet3_dev_id_list:
        _, pci = fwutils.dev_id_parse(dev_id)
        pci_bytes = fwutils.pci_str_to_bytes(pci)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "call_vpp_api"
        cmd['cmd']['object']  = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']   = "create vmxnet3 interface for %s" % pci
        cmd['cmd']['params']  = {
                        'api':  "vmxnet3_create",
                        'args': {'pci_addr':pci_bytes}
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "call_vpp_api"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']  = "delete vmxnet3 interface for %s" % pci
        cmd['revert']['params'] = {
                        'api':    "vmxnet3_delete",
                        'args':   {
                            'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
                        }
        }
        cmd_list.append(cmd)

    # Create loopback interface to be used as device logical interface
    if fwglobals.g.cfg.DEVICE_LOGICAL_INTERFACE_IP:
        DEVICE_LOGICAL_INTERFACE_CACHE_KEY = 'device_logical_interface'
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['descr']  = "Create logical device interface"
        cmd['cmd']['func']   = "call_vpp_api"
        cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['params'] = {
            'api':  "create_loopback_instance",
            'args': {
                'is_specified'  : 1,
                'user_instance' : fwglobals.g.DEVICE_LOGICAL_INTERFACE,
            },
            'ignore_retval': False,
        }
        cmd['cmd']['cache_ret_val'] = ('sw_if_index', DEVICE_LOGICAL_INTERFACE_CACHE_KEY)

        cmd['revert'] = {}
        cmd['revert']['descr']  = "Delete logical device interface"
        cmd['revert']['func']   = 'call_vpp_api'
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['params'] = {
            'api':  "delete_loopback",
            'args': {
                'substs': [
                    {
                        'add_param':'sw_if_index',
                        'val_by_key': DEVICE_LOGICAL_INTERFACE_CACHE_KEY
                    }
                ]
            },
        }
        cmd_list.append(cmd)
        fwtranslate_add_tunnel.set_loopback_ip_and_bring_up \
            (cmd_list, fwglobals.g.cfg.DEVICE_LOGICAL_INTERFACE_IP,
             DEVICE_LOGICAL_INTERFACE_CACHE_KEY)


    # Once VPP started, apply configuration to it.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_apply_router_config"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "Apply router configuration"
    cmd_list.append(cmd)

    # Finalize some stuff after VPP start / before VPP stops.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "_on_start_router_after"
    cmd['cmd']['object']  = "fwglobals.g.router_api"
    cmd['cmd']['descr']   = "fwrouter_api._on_start_router_after()"
    cmd['revert'] = {}
    cmd['revert']['func']   = "_on_stop_router_before"
    cmd['revert']['object'] = "fwglobals.g.router_api"
    cmd['revert']['descr']  = "fwrouter_api._on_stop_router_before()"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(*params):
    """Get start router command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'start-router'
