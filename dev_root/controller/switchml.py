#  Copyright 2021 Intel-KAUST-Microsoft
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import sys
import glob
import yaml
import signal
import asyncio
import argparse
import logging
from concurrent import futures

# Add BF Python to search path
bfrt_location = '{}/lib/python*/site-packages/tofino'.format(
    os.environ['SDE_INSTALL'])

placements_file_location='placements.yaml'

sys.path.append(glob.glob(bfrt_location)[0])
import bfrt_grpc.client as gc

from forwarder import Forwarder
from ports import Ports
from pre import PRE
from arp_icmp_responder import ARPandICMPResponder
from drop_simulator import DropSimulator
from rdma_receiver import RDMAReceiver
from udp_receiver import UDPReceiver
from bitmap_checker import BitmapChecker
from workers_counter import WorkersCounter
from exponents import Exponents
from processor import Processor
from next_step_selector import NextStepSelector
from rdma_sender import RDMASender
from udp_sender import UDPSender
from grpc_server import GRPCServer
from cli import Cli
from common import front_panel_regex, mac_address_regex, validate_ip

from dataclasses import dataclass, field

@dataclass
class nodeInfo:
    id: int = 0 
    port: int = 0
    mac: str = ""
    name: str = ""

class SwitchML(object):
    '''SwitchML controller'''

    def __init__(self):
        super(SwitchML, self).__init__()

        self.log = logging.getLogger(__name__)
        self.log.info('SwitchML controller')

        # CPU PCIe port
        self.cpu_port = 320  # Pipe 2 Quad 16

        # UDP port and mask
        self.udp_port = 0xbee0
        self.udp_mask = 0xfff0

        # RDMA partition key
        self.switch_pkey = 0xffff

        # Set all nodes MGID
        self.all_ports_mgid = 0x8000
        self.all_ports_initial_rid = 0x8000

        # Multicast group ID -> replication ID (= node ID) -> port
        self.multicast_groups = {self.all_ports_mgid: {}}

        # places that require change every time we change topology
        # portMaps, nodeMap, Forwarder functions, load_ports_file, set_custom_forward_rules

        # front port to dev port mapping
        self.portMaps = dict({7:6, 8:7, 9:12, 10:13, 11:14, 12:15, 14:29, 15:30, 16:31, 17:44, 18:45, 19:46, 20:47, 21:60, 22:61, 23:62, 24:63, 53:32, 54:48, 55:8, 56:16})

        # server node map
        # self.nodeMap = dict({
        #     0: nodeInfo(0, 11, "86:0C:39:2A:87:31", "maru10"),
        #     1: nodeInfo(1, 10, "90:E2:BA:F7:33:49", "maru11"),
        #     2: nodeInfo(2, 9, "90:E2:BA:F7:34:B5", "maru12"),
        #     3: nodeInfo(3, 12, "EC:F4:BB:D6:10:02", "koala6"),
        #     4: nodeInfo(4, 14, "24:6E:96:14:0F:82", "koala11"),
        #     5: nodeInfo(5, 22, "B8:CE:F6:D0:08:85", "quokka1.1"),
        #     6: nodeInfo(6, 20, "0C:42:A1:81:1B:BB", "quokka2.1"),
        #     7: nodeInfo(7, 18, "0C:42:A1:81:1B:43", "quokka3.1"),
        #     8: nodeInfo(8, 24, "0C:42:A1:81:1B:4B", "quokka4.1"),
        # })
        self.nodeMap = dict({
            0: nodeInfo(0, 22, "B8:CE:F6:D0:08:85", "quokka1.1"),
            1: nodeInfo(1, 20, "0C:42:A1:81:1B:BB", "quokka2.1"),
            2: nodeInfo(2, 18, "0C:42:A1:81:1B:43", "quokka3.1"),
            3: nodeInfo(3, 24, "0C:42:A1:81:1B:4B", "quokka4.1"),
            4: nodeInfo(3, 53, "24:8A:07:A5:AB:4C", "kea04"),
            5: nodeInfo(3, 56, "24:8A:07:A5:AB:50", "kea05"),
            6: nodeInfo(3, 55, "24:8A:07:A5:AA:FC", "kea07"),
            7: nodeInfo(3, 54, "24:8A:07:A5:AF:80", "kea08"),
        })

    def critical_error(self, msg):
        self.log.critical(msg)
        print(msg, file=sys.stderr)
        logging.shutdown()
        #sys.exit(1)
        os.kill(os.getpid(), signal.SIGTERM)

    def setup(self,
              program,
              switch_mac,
              switch_ip,
              bfrt_ip,
              bfrt_port,
              ports_file,
              incPlacement,
              folded_pipe=False):

        # INCAS custom implementation
        # success, params, placements = self.load_placements_file(placements_file)
        # if not success:
        #     self.critical_error(params)
        # print(params, placements)

        # Device 0
        self.dev = 0
        # Target all pipes
        self.target = gc.Target(self.dev, pipe_id=0xFFFF)
        # Folded pipe
        self.folded_pipe = folded_pipe

        # Connect to BFRT server
        try:
            interface = gc.ClientInterface('{}:{}'.format(bfrt_ip, bfrt_port),
                                           client_id=0,
                                           device_id=self.dev)
        except RuntimeError as re:
            msg = re.args[0] % re.args[1]
            self.critical_error(msg)
        else:
            self.log.info('Connected to BFRT server {}:{}'.format(
                bfrt_ip, bfrt_port))

        try:
            interface.bind_pipeline_config(program)
        except gc.BfruntimeForwardingRpcException:
            self.critical_error('P4 program {} not found!'.format(program))

        try:
            # Get all tables for program
            self.bfrt_info = interface.bfrt_info_get(program)

            # Ports table
            self.ports = Ports(self.target, gc, self.bfrt_info)

            if self.folded_pipe:
                try:
                    # Enable loopback on front panel ports
                    loopback_ports = (
                        [64] +  # Pipe 0 CPU ethernet port
                        # Pipe 0: all 16 front-panel ports
                        #list(range(  0,  0+64,4)) +
                        # Pipe 1: all 16 front-panel ports
                        list(range(128, 128 + 64, 4)) +
                        # Pipe 2: all 16 front-panel ports
                        list(range(256, 256 + 64, 4)) +
                        # Pipe 3: all 16 front-panel ports
                        list(range(384, 384 + 64, 4)))
                    print(
                        'Setting {} front panel ports in loopback mode'.format(
                            len(loopback_ports)))
                    self.ports.set_loopback_mode(loopback_ports)

                    # Enable loopback on PktGen ports
                    pktgen_ports = [192, 448]

                    if not self.ports.get_loopback_mode_pktgen(pktgen_ports):
                        # Not all PktGen ports are in loopback mode

                        print(
                            '\nYou must \'remove\' the ports in the BF ucli:\n')
                        for p in pktgen_ports:
                            print('    bf-sde> dvm rmv_port 0 {}'.format(p))
                        input('\nPress Enter to continue...')

                        if not self.ports.set_loopback_mode_pktgen(
                                pktgen_ports):
                            self.critical_error(
                                'Failed setting front panel ports in loopback mode'
                            )

                        print('\nAdd the ports again:\n')
                        for p in pktgen_ports:
                            print(
                                '    bf-sde> dvm add_port 0 {} 100 0'.format(p))
                        input('\nPress Enter to continue...')

                        if not self.ports.get_loopback_mode_pktgen(
                                pktgen_ports):
                            self.critical_error(
                                'Front panel ports are not in loopback mode')

                except gc.BfruntimeReadWriteRpcException:
                    self.critical_error(
                        'Error while setting ports in loopback mode. \
                        If the switch has only 2 pipes, the folded pipeline cannot be enabled.'
                    )

            # Packet Replication Engine table
            self.pre = PRE(self.target, gc, self.bfrt_info)

            # Setup tables
            # Forwarder
            self.forwarder = Forwarder(self.target, self.portMaps, incPlacement, gc, self.bfrt_info,
                                       self.all_ports_mgid)
            # ARP and ICMP responder
            self.arp_and_icmp = ARPandICMPResponder(self.target, gc,
                                                    self.bfrt_info)
            # Drop simulator
            # self.drop_simulator = DropSimulator(self.target, gc, self.bfrt_info)
            # RDMA receiver
            self.rdma_receiver = RDMAReceiver(self.target, gc, self.bfrt_info)
            # UDP receiver
            self.udp_receiver = UDPReceiver(self.target, gc, self.bfrt_info)
            # Bitmap checker
            self.bitmap_checker = BitmapChecker(self.target, gc, self.bfrt_info)
            # Workers counter
            self.workers_counter = WorkersCounter(self.target, gc,
                                                  self.bfrt_info)
            # Exponents
            self.exponents = Exponents(self.target, gc, self.bfrt_info)
            # Processors
            self.processors = []
            for i in range(32):
                p = Processor(self.target, gc, self.bfrt_info, i)
                self.processors.append(p)
            # Next step selector
            self.next_step_selector = NextStepSelector(self.target, gc,
                                                       self.bfrt_info,
                                                       self.folded_pipe)
            # RDMA sender
            self.rdma_sender = RDMASender(self.target, gc, self.bfrt_info)
            # UDP sender
            self.udp_sender = UDPSender(self.target, gc, self.bfrt_info)

            # Add multicast group for flood
            self.pre.add_multicast_group(self.all_ports_mgid)

            # Enable ports
            success, ports = self.load_ports_file(ports_file)
            if not success:
                self.critical_error(ports)

            # Set switch addresses
            self.set_switch_mac_and_ip(switch_mac, switch_ip)

            # Set custom forwarding rules
            success, msg = self.set_custom_forward_rules(incPlacement)
            if not success:
                self.critical_error(msg)

            # CLI setup
            self.cli = Cli()
            self.cli.setup(self, prompt='SwitchML', name='SwitchML controller')

            # Set up gRPC server
            self.grpc_server = GRPCServer(ip='[::]',
                                          port=50099,
                                          folded_pipe=self.folded_pipe)

            # Run event loop for gRPC server in a separate thread
            # limit concurrency to 1 to avoid synchronization problems in the BFRT interface
            self.grpc_executor = futures.ThreadPoolExecutor(max_workers=1)

            self.event_loop = asyncio.get_event_loop()

        except KeyboardInterrupt:
            self.critical_error('Stopping controller.')
        except Exception as e:
            self.log.exception(e)
            self.critical_error('Unexpected error. Stopping controller.')

    def load_placements_file(self, placements_file: str):
        placements = {}
        params = {}

        with open(placements_file) as f:
            yaml_placemenets = yaml.safe_load(f)

            for param, value in yaml_placemenets['params'].items():
                params[param] = value

            for task, node in yaml_placemenets['placements'].items():
                placements[task] = node
            
        
        return (True, params, placements)
    
    def set_custom_forward_rules(self, incPlacement):
        # add manual forwarding rules

        if incPlacement == 8:
            #left aggr

            for nodeIdx in range(6,8):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[21])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[23])
                self.forwarder.add_entry(self.portMaps[7], node.mac)
    
            self.forwarder.add_full_manual_forw_entry(self.portMaps[23], self.switch_mac, self.portMaps[8])

            for nodeIdx in range(4,6):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[19])
                self.forwarder.add_entry(self.portMaps[7], node.mac)

            self.forwarder.add_full_manual_forw_entry(self.portMaps[19], self.switch_mac, self.portMaps[8])

            for nodeIdx in range(2,4):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[15])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[15], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[16])
                self.forwarder.add_entry(self.portMaps[7], node.mac)

            self.forwarder.add_full_manual_forw_entry(self.portMaps[16], self.switch_mac, self.portMaps[8])

            for nodeIdx in range(0,2):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_entry(self.portMaps[node.port], node.mac)
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[8])

        elif incPlacement == 9:
            #middle left aggr

            for nodeIdx in range(6,8):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[21])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[23])
                self.forwarder.add_entry(self.portMaps[15], node.mac)
    
            self.forwarder.add_full_manual_forw_entry(self.portMaps[23], self.switch_mac, self.portMaps[16])

            for nodeIdx in range(4,6):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
                self.forwarder.add_entry(self.portMaps[15], node.mac)
    
            self.forwarder.add_full_manual_forw_entry(self.portMaps[19], self.switch_mac, self.portMaps[16])

            for nodeIdx in range(2,4):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_entry(self.portMaps[node.port], node.mac)
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[16])

            for nodeIdx in range(0,2):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[8])
                self.forwarder.add_entry(self.portMaps[15], node.mac)
            
            self.forwarder.add_full_manual_forw_entry(self.portMaps[8], self.switch_mac, self.portMaps[16])
        
        elif incPlacement == 10:
            #middle right aggr

            for nodeIdx in range(6,8):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[21])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[23])
                self.forwarder.add_entry(self.portMaps[17], node.mac)
    
            self.forwarder.add_full_manual_forw_entry(self.portMaps[23], self.switch_mac, self.portMaps[19])

            for nodeIdx in range(4,6):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_entry(self.portMaps[node.port], node.mac)
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[19])

            for nodeIdx in range(2,4):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[15])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[15], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[16])
                self.forwarder.add_entry(self.portMaps[17], node.mac)
            
            self.forwarder.add_full_manual_forw_entry(self.portMaps[16], self.switch_mac, self.portMaps[19])

            for nodeIdx in range(0,2):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[8])
                self.forwarder.add_entry(self.portMaps[17], node.mac)
            
            self.forwarder.add_full_manual_forw_entry(self.portMaps[8], self.switch_mac, self.portMaps[19])
        elif incPlacement == 11:
            #right aggr

            for nodeIdx in range(6,8):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_entry(self.portMaps[node.port], node.mac)
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[23])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[23])

            for nodeIdx in range(4,6):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[19])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
                self.forwarder.add_entry(self.portMaps[21], node.mac)
    
            self.forwarder.add_full_manual_forw_entry(self.portMaps[19], self.switch_mac, self.portMaps[23])

            for nodeIdx in range(2,4):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[15])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[15], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[16])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[16])
                self.forwarder.add_entry(self.portMaps[21], node.mac)
            
            self.forwarder.add_full_manual_forw_entry(self.portMaps[16], self.switch_mac, self.portMaps[23])

            for nodeIdx in range(0,2):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[16], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[8])
                self.forwarder.add_entry(self.portMaps[21], node.mac)
            
            self.forwarder.add_full_manual_forw_entry(self.portMaps[8], self.switch_mac, self.portMaps[23])
        elif incPlacement == 12:
            #top aggr

            for nodeIdx in range(6,8):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[21])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[node.port])
                self.forwarder.add_entry(self.portMaps[23], node.mac)

            for nodeIdx in range(4,6):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
                self.forwarder.add_entry(self.portMaps[19], node.mac)
            
            for nodeIdx in range(2,4):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[15])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[15], node.mac, self.portMaps[node.port])
                self.forwarder.add_entry(self.portMaps[16], node.mac)

            for nodeIdx in range(0,2):
                node = self.nodeMap[nodeIdx]
                self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
                self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
                self.forwarder.add_entry(self.portMaps[8], node.mac)

        # if incPlacement == 9:
        #     #left aggr

        #     for nodeIdx in range(6,9):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[23])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[21])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[21])
        #         self.forwarder.add_entry(self.portMaps[7], node.mac)
    
        #     self.forwarder.add_full_manual_forw_entry(self.portMaps[21], self.switch_mac, self.portMaps[8])

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[19])
        #         self.forwarder.add_entry(self.portMaps[7], node.mac)

        #     self.forwarder.add_full_manual_forw_entry(self.portMaps[19], self.switch_mac, self.portMaps[8])

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_entry(self.portMaps[node.port], node.mac)
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[8])

        # elif incPlacement == 10:
        #     #middle aggr

        #     for nodeIdx in range(6,9):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[23])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[21])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[21])
        #         self.forwarder.add_entry(self.portMaps[17], node.mac)
    
        #     self.forwarder.add_full_manual_forw_entry(self.portMaps[21], self.switch_mac, self.portMaps[19])

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_entry(self.portMaps[node.port], node.mac)
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[19])

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[8])
        #         self.forwarder.add_entry(self.portMaps[17], node.mac)
            
        #     self.forwarder.add_full_manual_forw_entry(self.portMaps[8], self.switch_mac, self.portMaps[19])
        
        # elif incPlacement == 11:
        #     #right aggr

        #     for nodeIdx in range(6,9):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_entry(self.portMaps[node.port], node.mac)
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[21])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[21])

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[8], node.mac, self.portMaps[19])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[19])
        #         self.forwarder.add_entry(self.portMaps[23], node.mac)
            
        #     self.forwarder.add_full_manual_forw_entry(self.portMaps[19], self.switch_mac, self.portMaps[21])

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[19], node.mac, self.portMaps[8])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[21], node.mac, self.portMaps[8])
        #         self.forwarder.add_entry(self.portMaps[23], node.mac)
            
        #     self.forwarder.add_full_manual_forw_entry(self.portMaps[8], self.switch_mac, self.portMaps[21])

        # elif incPlacement == 12:
        #     #top aggr

        #     for nodeIdx in range(6,9):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[23])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[21], node.mac)

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[19], node.mac)

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[7])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[7], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[8], node.mac)

        # if incPlacement == 6:
        #     #left aggr

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[23])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[17], node.mac)
            
        #     self.forwarder.add_manual_forw_entry(self.portMaps[19],self.portMaps[21])
        #     self.forwarder.add_manual_forw_entry(self.portMaps[21],self.portMaps[19])

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_entry(self.portMaps[node.port], node.mac)

        # elif incPlacement == 7:
        #     #right aggr

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[23], node.mac)
            
        #     self.forwarder.add_manual_forw_entry(self.portMaps[19],self.portMaps[21])
        #     self.forwarder.add_manual_forw_entry(self.portMaps[21],self.portMaps[19])

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_entry(self.portMaps[node.port], node.mac)

        # elif incPlacement == 8:
        #     #top aggr

        #     for nodeIdx in range(0,3):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[17])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[17], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[19], node.mac)
            

        #     for nodeIdx in range(3,6):
        #         node = self.nodeMap[nodeIdx]
        #         self.forwarder.add_manual_forw_entry(self.portMaps[node.port],self.portMaps[23])
        #         self.forwarder.add_full_manual_forw_entry(self.portMaps[23], node.mac, self.portMaps[node.port])
        #         self.forwarder.add_entry(self.portMaps[21], node.mac)

        else:
            return (False, 'Unknown INC placement')
        
        return (True, '')

        #bypass1718222324/top aggr
        # self.forwarder.add_manual_forw_entry(self.portMaps[24], self.portMaps[23])
        # self.forwarder.add_manual_forw_entry(self.portMaps[20], self.portMaps[23])
        # self.forwarder.add_manual_forw_entry(self.portMaps[18], self.portMaps[17])
        # self.forwarder.add_manual_forw_entry(self.portMaps[22], self.portMaps[17])
        # self.forwarder.add_manual_forw_entry(self.portMaps[15], self.portMaps[17])

        #bypass19212324/left aggr
        # self.forwarder.add_manual_forw_entry(self.portMaps[24], self.portMaps[23])
        # self.forwarder.add_manual_forw_entry(self.portMaps[20], self.portMaps[23])
        # self.forwarder.add_manual_forw_entry(self.portMaps[21], self.portMaps[19])
        # self.forwarder.add_manual_forw_entry(self.portMaps[19], self.portMaps[21])

        #bypass 1718192122/right aggr
        # self.forwarder.add_manual_forw_entry(self.portMaps[22],self.portMaps[17])
        # self.forwarder.add_manual_forw_entry(self.portMaps[18],self.portMaps[17])
        # self.forwarder.add_manual_forw_entry(self.portMaps[15],self.portMaps[17])
        # self.forwarder.add_manual_forw_entry(self.portMaps[19],self.portMaps[21])
        # self.forwarder.add_manual_forw_entry(self.portMaps[21],self.portMaps[19])

        # bypass 1718222324
        # self.forwarder.add_full_manual_forw_entry(44, "0C:42:A1:81:1B:43", 45)
        # self.forwarder.add_full_manual_forw_entry(44, "B8:CE:F6:D0:08:85", 61)
        # self.forwarder.add_full_manual_forw_entry(44, "B8:CE:F6:D0:08:84", 30) #quokka01

        # self.forwarder.add_full_manual_forw_entry(62, "0C:42:A1:81:1B:4B", 63)
        # self.forwarder.add_full_manual_forw_entry(62, "0C:42:A1:81:1B:BB", 47)
        # self.forwarder.add_full_manual_forw_entry(62, "0C:42:A1:81:1B:BA", 31) #quokka02

        #bypass1718222324/top aggr
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[23], "0C:42:A1:81:1B:4B", self.portMaps[24])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[23], "0C:42:A1:81:1B:BB", self.portMaps[20])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[17], "B8:CE:F6:D0:08:85", self.portMaps[22])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[17], "0C:42:A1:81:1B:43", self.portMaps[18])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[17], "B8:CE:F6:D0:08:84", self.portMaps[15])

        #bypass 19212324/left aggr
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[23], "0C:42:A1:81:1B:4B", self.portMaps[24])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[23], "0C:42:A1:81:1B:BB", self.portMaps[20])

        # bypass 1718192122/ right aggr
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[17], "B8:CE:F6:D0:08:85", self.portMaps[22])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[17], "0C:42:A1:81:1B:43", self.portMaps[18])
        # self.forwarder.add_full_manual_forw_entry(self.portMaps[17], "B8:CE:F6:D0:08:84", self.portMaps[15])
        

        # Add forwarding entries
        # here we also let the controller know under which ports to finds the end hosts
        # bypass182224
        # self.forwarder.add_entry(46, "0C:42:A1:81:1B:43")
        # self.forwarder.add_entry(46, "B8:CE:F6:D0:08:85")
        # self.forwarder.add_entry(60, "0C:42:A1:81:1B:4B")
        # self.forwarder.add_entry(60, "0C:42:A1:81:1B:BB")

        # bypass1718222324/top aggr
        # self.forwarder.add_entry(self.portMaps[19], "0C:42:A1:81:1B:43")
        # self.forwarder.add_entry(self.portMaps[19], "B8:CE:F6:D0:08:85")
        # self.forwarder.add_entry(self.portMaps[21], "0C:42:A1:81:1B:4B")
        # self.forwarder.add_entry(self.portMaps[19], "B8:CE:F6:D0:08:84")
        # self.forwarder.add_entry(self.portMaps[21], "0C:42:A1:81:1B:BB")

        # bypasss19212324/left aggr
        # self.forwarder.add_entry(self.portMaps[18], "0C:42:A1:81:1B:43")
        # self.forwarder.add_entry(self.portMaps[22], "B8:CE:F6:D0:08:85")
        # self.forwarder.add_entry(self.portMaps[17], "0C:42:A1:81:1B:4B")
        # self.forwarder.add_entry(self.portMaps[15], "B8:CE:F6:D0:08:84")
        # self.forwarder.add_entry(self.portMaps[17], "0C:42:A1:81:1B:BB")

        #bypass 1718192122/ right aggr
        # self.forwarder.add_entry(self.portMaps[23], "0C:42:A1:81:1B:43")
        # self.forwarder.add_entry(self.portMaps[23], "B8:CE:F6:D0:08:85")
        # self.forwarder.add_entry(self.portMaps[24], "0C:42:A1:81:1B:4B")
        # self.forwarder.add_entry(self.portMaps[23], "B8:CE:F6:D0:08:84")
        # self.forwarder.add_entry(self.portMaps[20], "0C:42:A1:81:1B:BB")

    def load_ports_file(self, ports_file):
        ''' Load ports yaml file and enable front panel ports.

            Keyword arguments:
                ports_file -- yaml file name

            Returns:
                (success flag, list of ports or error message)
        '''

        ports = []
        fib = {}

        with open(ports_file) as f:
            yaml_ports = yaml.safe_load(f)

            for port, value in yaml_ports['ports'].items():

                re_match = front_panel_regex.match(port)
                if not re_match:
                    return (False, 'Invalid port {}'.format(port))

                fp_port = int(re_match.group(1))
                fp_lane = int(re_match.group(2))

                # Convert all keys to lowercase
                value = {k.lower(): v for k, v in value.items()}

                if 'speed' in value:
                    try:
                        speed = int(value['speed'].upper().replace('G',
                                                                   '').strip())
                    except ValueError:
                        return (False, 'Invalid speed for port {}'.format(port))

                    if speed not in [10, 25, 40, 50, 100]:
                        return (
                            False,
                            'Port {} speed must be one of 10G,25G,40G,50G,100G'.
                            format(port))
                else:
                    speed = 100

                if 'fec' in value:
                    fec = value['fec'].lower().strip()
                    if fec not in ['none', 'fc', 'rs']:
                        return (False,
                                'Port {} fec must be one of none, fc, rs'.
                                format(port))
                else:
                    fec = 'none'

                if 'autoneg' in value:
                    an = value['autoneg'].lower().strip()
                    if an not in ['default', 'enable', 'disable']:
                        return (
                            False,
                            'Port {} autoneg must be one of default, enable, disable'
                            .format(port))
                else:
                    an = 'default'

                if 'mac' not in value:
                    return (False,
                            'Missing MAC address for port {}'.format(port))

                success, dev_port = self.ports.get_dev_port(fp_port, fp_lane)
                if success:
                    fib[dev_port] = value['mac'].upper()
                else:
                    return (False, dev_port)

                ports.append((fp_port, fp_lane, speed, fec, an))

        # add manual entries for port looping 
        # temp_port = ports
        # temp_port.append((34, 0, 10, "none", "disable"))
        # temp_port.append((17, 0, 10, "none", "disable"))
        # temp_port.append((18, 0, 10, "none", "disable"))
        # temp_port.append((22, 0, 10, "none", "disable"))
        # temp_port.append((23, 0, 10, "none", "disable"))
        # temp_port.append((24, 0, 10, "none", "disable"))
        # temp_port.append((20, 0, 10, "none", "disable"))
        # temp_port.append((15, 0, 25, "rs", "disable"))
        # temp_port.append((16, 0, 25, "rs", "disable"))
        # temp_port.append((38, 0, 10, "none", "disable"))
        # temp_port.append((42, 0, 10, "none", "disable"))
        # temp_port.append((46, 0, 10, "none", "disable"))

        # Add ports
        success, error_msg = self.ports.add_ports(ports)
        if not success:
            return (False, error_msg)

        
        # self.forwarder.add_entries(fib.items())

        # Add ports to flood multicast group
        # rids_and_ports = [
        #     (self.all_ports_initial_rid + dp, dp) for dp in fib.keys()
        # ]
        # ports_list = [self.portMaps[9],self.portMaps[10], self.portMaps[11], self.portMaps[12], self.portMaps[14], self.portMaps[18], self.portMaps[20], self.portMaps[22], self.portMaps[24]]
        ports_list = [self.portMaps[pp.port] for pp in self.nodeMap.values()]
        print(ports_list)
        rids_and_ports = [
            (self.all_ports_initial_rid + dp, dp) for dp in ports_list
        ]
        success, error_msg = self.pre.add_multicast_nodes(
            self.all_ports_mgid, rids_and_ports)
        if not success:
            return (False, error_msg)

        for r, p in rids_and_ports:
            self.multicast_groups[self.all_ports_mgid][r] = p

        return (True, ports)

    def set_switch_mac_and_ip(self, switch_mac, switch_ip):
        ''' Set switch MAC and IP '''
        self.switch_mac = switch_mac.upper()
        self.switch_ip = switch_ip

        self.arp_and_icmp.set_switch_mac_and_ip(self.switch_mac, self.switch_ip)
        self.rdma_receiver.set_switch_mac_and_ip(self.switch_mac,
                                                 self.switch_ip)
        self.udp_receiver.set_switch_mac_and_ip(self.switch_mac, self.switch_ip)
        self.rdma_sender.set_switch_mac_and_ip(self.switch_mac, self.switch_ip)
        self.udp_sender.set_switch_mac_and_ip(self.switch_mac, self.switch_ip)

    def get_switch_mac_and_ip(self):
        ''' Get switch MAC and IP '''
        return self.switch_mac, self.switch_ip

    def clear_multicast_group(self, session_id):
        ''' Remove multicast group and nodes for this session '''

        if session_id in self.multicast_groups:
            for node_id in self.multicast_groups[session_id]:
                self.pre.remove_multicast_node(node_id)
            self.pre.remove_multicast_group(session_id)

            del self.multicast_groups[session_id]

    def reset_workers(self):
        ''' Reset all workers state '''
        #TODO clear counters
        self.udp_receiver._clear()
        self.udp_sender.clear_udp_workers()
        self.rdma_receiver._clear()
        self.rdma_sender.clear_rdma_workers()
        self.bitmap_checker._clear()
        self.workers_counter._clear()
        self.exponents._clear()
        for p in self.processors:
            p._clear()

        for session_id in self.multicast_groups.copy():
            if session_id != self.all_ports_mgid:
                self.clear_multicast_group(session_id)

        # Reset gRPC broadcast/barrier state
        self.grpc_server.reset()

    def clear_rdma_workers(self, session_id):
        ''' Reset UDP workers state for this session '''
        #TODO selectively remove workers (RDMA or UDP) for
        #this session, clear RDMA sender/receiver counters,
        #clear bitmap/count/exponents/processors
        self.rdma_receiver._clear()
        self.rdma_sender.clear_rdma_workers()
        self.bitmap_checker._clear()
        self.workers_counter._clear()
        self.exponents._clear()
        for p in self.processors:
            p._clear()

        # Multicast groups below 0x8000 are used for sessions
        # (the mgid is the session id)
        #TODO session_id = session_id % 0x8000
        session_id = 0  # Single session supported for now

        self.clear_multicast_group(session_id)

    def add_rdma_worker(self, session_id, worker_id, num_workers, worker_mac,
                        worker_ip, worker_rkey, packet_size, message_size,
                        qpns_and_psns):
        ''' Add SwitchML RDMA worker.

            Keyword arguments:
                session_id -- ID of the session
                worker_id -- worker rank
                num_workers -- number of workers in this session
                worker_mac -- worker MAC address
                worker_ip -- worker IP address
                worker_rkey -- worker remote key
                packet_size -- MTU for this session
                message_size -- RDMA message size for this session
                qpns_and_psns -- list of (QPn, initial psn) tuples

            Returns:
                (success flag, None or error message)
        '''
        if worker_id >= 32:
            error_msg = 'Worker ID {} too large; only 32 workers supported'.format(
                worker_id)
            self.log.error(error_msg)
            return (False, error_msg)

        if num_workers > 32:
            error_msg = 'Worker count {} too large; only 32 workers supported'.format(
                num_workers)
            self.log.error(error_msg)
            return (False, error_msg)

        # Get port for node
        success, dev_port = self.forwarder.get_dev_port(worker_mac)
        if not success:
            return (False, dev_port)

        # Multicast groups below 0x8000 are used for sessions
        # (the mgid is the session id)
        #TODO session_id = session_id % 0x8000
        session_id = 0  # Single session supported for now

        # Add RDMA receiver/sender entries
        success, error_msg = self.rdma_receiver.add_rdma_worker(
            worker_id, worker_ip, self.switch_pkey, packet_size, num_workers,
            session_id)
        if not success:
            return (False, error_msg)

        self.rdma_sender.add_rdma_worker(worker_id, worker_mac, worker_ip,
                                         worker_rkey, packet_size, message_size,
                                         qpns_and_psns)

        # Add multicast group if not present
        if session_id not in self.multicast_groups:
            self.pre.add_multicast_group(session_id)
            self.multicast_groups[session_id] = {}

        if worker_id in self.multicast_groups[
                session_id] and self.multicast_groups[session_id][
                    worker_id] != dev_port:
            # Existing node with different port, remove it
            self.pre.remove_multicast_node(worker_id)
            del self.multicast_groups[session_id][worker_id]

        # Add multicast node if not present
        if worker_id not in self.multicast_groups[session_id]:
            # Add new node
            success, error_msg = self.pre.add_multicast_node(
                session_id, worker_id, dev_port)
            if not success:
                return (False, error_msg)

            self.multicast_groups[session_id][worker_id] = dev_port

        self.log.info('Added RDMA worker {}:{} {}'.format(
            worker_id, worker_mac, worker_ip))

        return (True, None)

    def clear_udp_workers(self, session_id):
        ''' Reset UDP workers state for this session '''
        #TODO selectively remove workers (RDMA or UDP) for
        #this session, clear UDP sender/receiver counters,
        #clear bitmap/count/exponents/processors
        self.udp_receiver._clear()
        self.udp_sender.clear_udp_workers()
        self.bitmap_checker._clear()
        self.workers_counter._clear()
        self.exponents._clear()
        for p in self.processors:
            p._clear()

        # Multicast groups below 0x8000 are used for sessions
        # (the mgid is the session id)
        #TODO session_id = session_id % 0x8000
        session_id = 0  # Single session supported for now

        self.clear_multicast_group(session_id)

    def add_udp_worker(self, session_id, worker_id, num_workers, worker_mac,
                       worker_ip):
        ''' Add SwitchML UDP worker.

            Keyword arguments:
                session_id -- ID of the session
                worker_id -- worker rank
                num_workers -- number of workers in this session
                worker_mac -- worker MAC address
                worker_ip -- worker IP address

            Returns:
                (success flag, None or error message)
        '''
        #TODO session packet size
        if worker_id >= 32:
            error_msg = 'Worker ID {} too large; only 32 workers supported'.format(
                worker_id)
            self.log.error(error_msg)
            return (False, error_msg)

        if num_workers > 32:
            error_msg = 'Worker count {} too large; only 32 workers supported'.format(
                num_workers)
            self.log.error(error_msg)
            return (False, error_msg)

        # Get port for node
        success, dev_port = self.forwarder.get_dev_port(worker_mac)
        if not success:
            return (False, dev_port)

        # Multicast groups below 0x8000 are used for sessions
        # (the mgid is the session id)
        #TODO session_id = session_id % 0x8000
        session_id = 0  # Single session supported for now

        # Add UDP receiver/sender entries
        success, error_msg = self.udp_receiver.add_udp_worker(
            worker_id, worker_mac, worker_ip, self.udp_port, self.udp_mask,
            num_workers, session_id)
        if not success:
            return (False, error_msg)

        self.udp_sender.add_udp_worker(worker_id, worker_mac, worker_ip)

        # Add multicast group if not present
        if session_id not in self.multicast_groups:
            self.pre.add_multicast_group(session_id)
            self.multicast_groups[session_id] = {}

        if worker_id in self.multicast_groups[
                session_id] and self.multicast_groups[session_id][
                    worker_id] != dev_port:
            # Existing node with different port, remove it
            self.pre.remove_multicast_node(worker_id)
            del self.multicast_groups[session_id][worker_id]

        # Add multicast node if not present
        if worker_id not in self.multicast_groups[session_id]:
            # Add new node
            success, error_msg = self.pre.add_multicast_node(
                session_id, worker_id, dev_port)
            if not success:
                return (False, error_msg)

            self.multicast_groups[session_id][worker_id] = dev_port

        self.log.info('Added UDP worker {}:{} {}'.format(
            worker_id, worker_mac, worker_ip))

        return (True, None)

    def run(self):
        try:
            # Start listening for RPCs
            self.grpc_future = self.grpc_executor.submit(
                self.grpc_server.run, self.event_loop, self)

            self.log.info('gRPC server started')

            # Start CLI
            self.cli.run()

            # Stop gRPC server and event loop
            self.event_loop.call_soon_threadsafe(self.grpc_server.stop)

            # Wait for gRPC thread to end
            self.grpc_future.result()

            # Stop event loop
            self.event_loop.close()

            # Close gRPC executor
            self.grpc_executor.shutdown()

            self.log.info('gRPC server stopped')

        except Exception as e:
            self.log.exception(e)

        self.log.info('Stopping controller')


if __name__ == '__main__':

    # Parse arguments
    argparser = argparse.ArgumentParser(description='SwitchML controller.')
    argparser.add_argument('--program',
                           type=str,
                           default='SwitchML',
                           help='P4 program name. Default: SwitchML')
    argparser.add_argument(
        '--inc-placement',
        type=int,
        default=7,
        help='INC placement.')
    
    argparser.add_argument(
        '--bfrt-ip',
        type=str,
        default='127.0.0.1',
        help='Name/address of the BFRuntime server. Default: 127.0.0.1')
    argparser.add_argument('--bfrt-port',
                           type=int,
                           default=50052,
                           help='Port of the BFRuntime server. Default: 50052')
    argparser.add_argument(
        '--switch-mac',
        type=str,
        default='00:11:22:33:44:55',
        help='MAC address of the switch. Default: 00:11:22:33:44:55')
    argparser.add_argument('--switch-ip',
                           type=str,
                           default='10.0.0.254',
                           help='IP address of the switch. Default: 10.0.0.254')
    argparser.add_argument(
        '--ports',
        type=str,
        default='ports.yaml',
        help=
        'YAML file describing machines connected to ports. Default: ports.yaml')
    argparser.add_argument(
        '--enable-folded-pipe',
        default=False,
        action='store_true',
        help='Enable the folded pipeline (requires a 4 pipes switch)')
    argparser.add_argument('--log-level',
                           default='INFO',
                           choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'],
                           help='Default: INFO')

    args = argparser.parse_args()

    # Configure logging
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        sys.exit('Invalid log level: {}'.format(args.log_level))

    logformat = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='switchml.log',
                        filemode='w',
                        level=numeric_level,
                        format=logformat,
                        datefmt='%H:%M:%S')

    args.switch_mac = args.switch_mac.strip().upper()
    args.switch_ip = args.switch_ip.strip()
    args.bfrt_ip = args.bfrt_ip.strip()

    if not mac_address_regex.match(args.switch_mac):
        sys.exit('Invalid Switch MAC address')
    if not validate_ip(args.switch_ip):
        sys.exit('Invalid Switch IP address')
    if not validate_ip(args.bfrt_ip):
        sys.exit('Invalid BFRuntime server IP address')

    ctrl = SwitchML()
    ctrl.setup(args.program, args.switch_mac, args.switch_ip, args.bfrt_ip,
               args.bfrt_port, args.ports, args.inc_placement, args.enable_folded_pipe)

    # Start controller
    ctrl.run()

    # Flush log, stdout, stderr
    sys.stdout.flush()
    sys.stderr.flush()
    logging.shutdown()

    # Exit
    os.kill(os.getpid(), signal.SIGTERM)
