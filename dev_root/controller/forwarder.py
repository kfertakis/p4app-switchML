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

import logging

from control import Control


class Forwarder(Control):

    def __init__(self, target, portMaps, incPlacement, gc, bfrt_info, mgid):
        # Set up base class
        super(Forwarder, self).__init__(target, gc)

        self.log = logging.getLogger(__name__)

        self.portMaps = portMaps

        self.tables = [bfrt_info.table_get('pipe.Ingress.forwarder.forward')]
        self.table = self.tables[0]

        self.port_meta_tables = [bfrt_info.table_get('pipe.IngressParser.$PORT_METADATA')]
        self.port_meta_table = self.port_meta_tables[0]

        # Annotations
        self.table.info.key_field_annotation_add('hdr.ethernet.dst_addr', 'mac')

        # Multicast group ID for flood
        self.mgid = mgid

        # Keep set of mac addresses so we can delete them all without deleting the flood rule
        self.mac_addresses = {}

        # Clear table and add defaults
        self._clear()

        # self.add_default_entries()
        self.add_default_entries_modified(incPlacement)

        # add port metadata for skipping processing
        self.add_process_type_meta_per_port(incPlacement)

    def _clear(self):
        ''' Remove all entries (except broadcast) '''

        self.table.entry_del(self.target, [
            self.table.make_key(
                [self.gc.KeyTuple('hdr.ethernet.dst_addr', mac_address)])
            for mac_address in self.mac_addresses
        ])
        self.mac_addresses.clear()

    def add_default_entries(self):
        ''' Add broadcast and default entries '''

        # Add broadcast entry
        self.table.entry_add(self.target, [
            self.table.make_key([
                self.gc.KeyTuple('$MATCH_PRIORITY', 1),
                self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
                self.gc.KeyTuple('ig_intr_md.ingress_port',  0x00, 0x00)
            ])
        ], [
            self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
                                 'Ingress.forwarder.flood')
        ])

        # Add default entry
        self.table.default_entry_set(
            self.target,
            self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
                                 'Ingress.forwarder.flood'))
    
    def add_default_entries_modified(self, incPlacement):
        ''' Add broadcast and default entries '''

        port_list = []

        # Add broadcast entry
        if incPlacement == 6:
            #left aggr
            port_list = [15, 17, 18, 22]
        elif incPlacement == 7:
            #right aggr
            port_list = [16, 20, 23, 24]
        elif incPlacement == 8:
            #top aggr
            port_list = [19, 21]
        else:
            return False
        
        for port in port_list:
                self.table.entry_add(self.target, [
                    self.table.make_key([
                        self.gc.KeyTuple('$MATCH_PRIORITY', 1),
                        self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
                        self.gc.KeyTuple('ig_intr_md.ingress_port',  self.portMaps[port], 0xff)
                    ])
                ], [
                    self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
                                         'Ingress.forwarder.flood')
                ])
        
        self.table.default_entry_set(
            self.target,
            self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
                                 'Ingress.forwarder.flood'))

        return True
        #top aggr
        
        # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x2E, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        # # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x3C, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        #left aggr

        # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x1E, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        # # # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x2C, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        # #         # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x2D, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        # #         # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x3D, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        #right aggr

        # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x3F, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        #         # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x2F, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        #         # Add broadcast entry
        # self.table.entry_add(self.target, [
        #     self.table.make_key([
        #         self.gc.KeyTuple('$MATCH_PRIORITY', 1),
        #         self.gc.KeyTuple('hdr.ethernet.dst_addr', 'ff:ff:ff:ff:ff:ff', 0xffffffffffff),
        #         self.gc.KeyTuple('ig_intr_md.ingress_port',  0x3E, 0xff)
        #     ])
        # ], [
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood')
        # ])

        # Add default entry
        # self.table.default_entry_set(
        #     self.target,
        #     self.table.make_data([self.gc.DataTuple('flood_mgid', self.mgid)],
        #                          'Ingress.forwarder.flood'))
    
    def add_process_type_meta_per_port(self, incPlacement):

        for port in range(29,64):
            self.port_meta_table.entry_add(
                self.target,
                [self.port_meta_table.make_key([self.gc.KeyTuple('ig_intr_md.ingress_port', port)])],
                [self.port_meta_table.make_data([self.gc.DataTuple('processing_type', 1)])]
            )
        
        port_list = []
        if incPlacement == 6:
            #left aggr
            port_list = [19, 21, 23, 24, 16, 20]
        elif incPlacement == 7:
            #right aggr
            port_list = [17, 18, 19, 21, 22, 15]
        elif incPlacement == 8:
            #top aggr
            port_list = [15, 16, 17, 18, 20, 22, 23, 24]
        else: 
            return False
        
        for fp_port in port_list:
            self.port_meta_table.entry_add(
                self.target,
                [self.port_meta_table.make_key([self.gc.KeyTuple('ig_intr_md.ingress_port', self.portMaps[fp_port])])],
                [self.port_meta_table.make_data([self.gc.DataTuple('processing_type', 0)])]
            )

        # left aggr
        # for port in [19, 21, 23, 24]:
        # right aggr
        # for fp_port in [17, 18, 19, 21, 22]:
        #     self.port_meta_table.entry_add(
        #         self.target,
        #         [self.port_meta_table.make_key([self.gc.KeyTuple('ig_intr_md.ingress_port', self.portMaps[fp_port])])],
        #         [self.port_meta_table.make_data([self.gc.DataTuple('processing_type', 0)])]
        #     )

        # self.port_meta_table.entry_add(self.target, [
        #     self.port_meta_table.make_key([self.gc.KeyTuple('ig_intr_md.ingress_port', p)])
        #     for p in [46, 60, 62, 63]
        # ], [
        #     self.port_meta_table.make_data([
        #         self.gc.DataTuple('ingress_drop_probability',
        #                               0),
        #         self.gc.DataTuple('egress_drop_probability',
        #                               0),
        #         self.gc.DataTuple('processing_type', 0x00)
        #     ])
        # ] * 4)

    def add_entry(self, dev_port, mac_address):
        ''' Add one entry.

            Keyword arguments:
                dev_port -- dev port number
                mac_address -- MAC address reachable through the port
        '''

        self.table.entry_add(self.target, [
            self.table.make_key([
                self.gc.KeyTuple('$MATCH_PRIORITY', 1),
                self.gc.KeyTuple('hdr.ethernet.dst_addr', mac_address, 0xffffffffffff),
                self.gc.KeyTuple('ig_intr_md.ingress_port', 0x00, 0x00)
            ])
        ], [
            self.table.make_data([self.gc.DataTuple('egress_port', dev_port)],
                                 'Ingress.forwarder.set_egress_port')
        ])
        
        self.mac_addresses[mac_address] = dev_port
    
    def add_manual_forw_entry(self, ingress_dev_port, egress_dev_port):
        ''' Add one entry.

            Keyword arguments:
                dev_port -- dev port number
                mac_address -- MAC address reachable through the port
        '''

        self.table.entry_add(
            self.target,
            [
                self.table.make_key([
                    self.gc.KeyTuple('$MATCH_PRIORITY', 0),
                    self.gc.KeyTuple(
                        'hdr.ethernet.dst_addr',  # 48 bits
                        0x000000000000,  # dst_addr mac
                        0x000000000000),
                    self.gc.KeyTuple(
                        'ig_intr_md.ingress_port',  # port
                        ingress_dev_port,
                        0xff)
                ])
            ],
            [
               self.table.make_data([self.gc.DataTuple('egress_port', egress_dev_port)],
                                 'Ingress.forwarder.set_egress_port')
            ])
        
    def add_full_manual_forw_entry(self, ingress_dev_port, dst_mac, egress_dev_port):
        ''' Add one entry.

            Keyword arguments:
                dev_port -- dev port number
                mac_address -- MAC address reachable through the port
        '''

        self.table.entry_add(
            self.target,
            [
                self.table.make_key([
                    self.gc.KeyTuple('$MATCH_PRIORITY', 0),
                    self.gc.KeyTuple(
                        'hdr.ethernet.dst_addr',  # 48 bits
                        dst_mac,  # dst_addr mac
                        0xffffffffffff),
                    self.gc.KeyTuple(
                        'ig_intr_md.ingress_port',  # port
                        ingress_dev_port,
                        0xff)
                ])
            ],
            [
               self.table.make_data([self.gc.DataTuple('egress_port', egress_dev_port)],
                                 'Ingress.forwarder.set_egress_port')
            ])

    def add_entries(self, entry_list):
        ''' Add entries.

            Keyword arguments:
                entry_list -- a list of tuples: (dev_port, mac_address)
        '''

        for (dev_port, mac_address) in entry_list:
            self.add_entry(dev_port, mac_address)
    
    def add_manual_forw_entries(self, entry_list):
        ''' Add entries.

            Keyword arguments:
                entry_list -- a list of tuples: (ingress_dev_port, egress_dev_port)
        '''

        for (ingress_dev_port, egress_dev_port) in entry_list:
            self.add_manual_forw_entry(ingress_dev_port, egress_dev_port)

    def remove_entry(self, mac_address):
        ''' Remove one entry '''
        self.table.entry_del(self.target, [
            self.table.make_key(
                [self.gc.KeyTuple('hdr.ethernet.dst_addr', mac_address)])
        ])
        del self.mac_addresses[mac_address]

    def get_dev_port(self, mac):
        ''' Get dev port for MAC address.

            Returns:
                (success flag, dev port or error message)
        '''

        mac = mac.upper()
        if mac not in self.mac_addresses:
            return (False, 'MAC address not found')
        return (True, self.mac_addresses[mac])

    def get_macs_on_port(self, dev_port):
        ''' Get MAC addresses associated to a dev port '''

        results = []
        for mac_address, port in self.mac_addresses.items():
            if port == dev_port:
                results.append(mac_address)

        return results

    def get_entries(self):
        ''' Get all forwarding entries.

            Returns:
                list of (MAC address, dev port)
        '''

        return self.mac_addresses.items()
