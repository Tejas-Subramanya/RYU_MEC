# Copyright (C) 2017 Tejas Subramanya, FBK-CREATE-NET
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}	

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
	table_id = 1
	self.remove_flows(datapath, table_id)
        self.add_flow(datapath, 0, match, actions)
	#self.install_decap_rules(datapath)
	#self.install_encap_rules(datapath) #2nd try
	#self.install_decap_encap_rules(datapath #3rd try)
	self.install_decap_ul_rules(datapath) #1st try
	#self.install_encap_ul_rules(datapath)

    def install_decap_rules(self, datapath):
	"Create and install static flow entries for decap"
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser

	type_ip = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
	type_udp = (ofproto.OFPHTN_IP_PROTO << 16) | 17
	type_gtpu = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
	type_next = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_USE_NEXT_PROTO
	type_ethernet = (ofproto.OFPHTN_ONF << 16) | 0

	match = parser.OFPMatch(in_port=1,eth_type=2048,ip_proto=17,ipv4_src='172.21.5.9',ipv4_dst='192.168.51.10',udp_src=2152,udp_dst=2152)
	
	encap_ethernet = parser.OFPActionEncap(type_ethernet)
	set_eth_dst = parser.OFPActionSetField(eth_dst='f8:ca:b8:33:6c:f7')
	set_eth_src = parser.OFPActionSetField(eth_src='00:1b:17:bb:d9:15')	
	set_eth_type = parser.OFPActionSetField(eth_type=2048)

	decap_ip = parser.OFPActionDecap(type_ip,type_udp)
	decap_udp = parser.OFPActionDecap(type_udp,type_gtpu)
	decap_gtpu = parser.OFPActionDecap(type_gtpu,type_ip)
	decap_ethernet = parser.OFPActionDecap(type_ethernet, type_ip)

	output = parser.OFPActionOutput(3) # Change this to port 3 considering it has only IP packets after decapsulation

	actions = [decap_ethernet, decap_ip, decap_udp, decap_gtpu, encap_ethernet, set_eth_src, set_eth_dst, output]
	flow_mod = self.add_flow(datapath, 2, match, actions)

    def install_encap_rules(self, datapath):
	"Create and install static flow entries for encap"
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser

	match = parser.OFPMatch(in_port=3,eth_type=2048) # Caching for example(IP packets)

	type_ip = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
	type_udp = (ofproto.OFPHTN_IP_PROTO << 16) | 17
	type_gtpu = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
	type_next = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_USE_NEXT_PROTO
	type_ethernet = (ofproto.OFPHTN_ONF << 16) | 0
	
	decap_ethernet = parser.OFPActionDecap(type_ethernet, type_ip)
	encap_ethernet = parser.OFPActionEncap(type_ethernet)
	set_eth_dst = parser.OFPActionSetField(eth_dst='f8:ca:b8:33:6c:f7')
	set_eth_src = parser.OFPActionSetField(eth_src='00:1b:17:bb:d9:15')	
	encap_gtpu = parser.OFPActionEncap(type_gtpu)
	set_gtpu_teid = parser.OFPActionSetField(gtpu_teid=3396329693)
	encap_udp = parser.OFPActionEncap(type_udp)	
	set_udp_src = parser.OFPActionSetField(udp_src=2152)
	set_udp_dst = parser.OFPActionSetField(udp_dst=2152)
	encap_ip = parser.OFPActionEncap(type_ip)
	set_ipsrc = parser.OFPActionSetField(ipv4_src='172.21.5.9')
	set_ipdst = parser.OFPActionSetField(ipv4_dst='192.168.51.10')
	output = parser.OFPActionOutput(2) # eNB (GTP encapsulated packets)
	
	actions = [decap_ethernet, encap_gtpu, set_gtpu_teid, encap_udp, set_udp_src, set_udp_dst, encap_ip, set_ipsrc, set_ipdst, encap_ethernet, set_eth_src, set_eth_dst, output]
	flow_mod = self.add_flow(datapath, 2, match, actions)


    def install_decap_encap_rules(self, datapath):
	"Create and install static flow entries for decap"
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser

	type_ip = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
	type_udp = (ofproto.OFPHTN_IP_PROTO << 16) | 17
	type_gtpu = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
	type_ethernet = (ofproto.OFPHTN_ONF << 16) | 0

	match = parser.OFPMatch(in_port=1,eth_type=2048,ip_proto=17,ipv4_src='172.21.5.9',ipv4_dst='192.168.51.10',udp_src=2152,udp_dst=2152)
	
	set_eth_dst = parser.OFPActionSetField(eth_dst='f8:ca:b8:33:6c:f7')
	set_eth_src = parser.OFPActionSetField(eth_src='00:1b:17:bb:d9:15')	
	set_eth_type = parser.OFPActionSetField(eth_type=2048)

	decap_ip = parser.OFPActionDecap(type_ip,type_udp)
	decap_udp = parser.OFPActionDecap(type_udp,type_gtpu)
	decap_gtpu = parser.OFPActionDecap(type_gtpu,type_ip)
	decap_ethernet = parser.OFPActionDecap(type_ethernet, type_ip)

	type_ip = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
	type_udp = (ofproto.OFPHTN_IP_PROTO << 16) | 17
	type_gtpu = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
	type_next = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_USE_NEXT_PROTO
	type_ethernet = (ofproto.OFPHTN_ONF << 16) | 0
	
	encap_ethernet = parser.OFPActionEncap(type_ethernet)
	encap_gtpu = parser.OFPActionEncap(type_gtpu)
	set_gtpu_teid = parser.OFPActionSetField(gtpu_teid=3396329693)
	encap_udp = parser.OFPActionEncap(type_udp)	
	set_udp_src = parser.OFPActionSetField(udp_src=2152)
	set_udp_dst = parser.OFPActionSetField(udp_dst=2152)
	encap_ip = parser.OFPActionEncap(type_ip)
	set_ipsrc = parser.OFPActionSetField(ipv4_src='172.21.5.9')
	set_ipdst = parser.OFPActionSetField(ipv4_dst='192.168.51.10')
	output = parser.OFPActionOutput(2) # eNB (GTP encapsulated packets)
	
	actions = [decap_ethernet, decap_ip, decap_udp, decap_gtpu, encap_ethernet, set_eth_src, set_eth_dst, decap_ethernet, encap_gtpu, set_gtpu_teid, encap_udp, set_udp_src, set_udp_dst, encap_ip, set_ipsrc, set_ipdst, encap_ethernet, set_eth_src, set_eth_dst, output]
	flow_mod = self.add_flow(datapath, 2, match, actions)


    def install_decap_ul_rules(self, datapath):
	"Create and install static flow entries for decap"
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser

	type_ip = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
	type_udp = (ofproto.OFPHTN_IP_PROTO << 16) | 17
	type_gtpu = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
	type_next = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_USE_NEXT_PROTO
	type_ethernet = (ofproto.OFPHTN_ONF << 16) | 0

	match = parser.OFPMatch(in_port=2,eth_type=2048,ip_proto=17,ipv4_src='192.168.51.10',ipv4_dst='172.21.5.9',udp_src=2152,udp_dst=2152)
	
	encap_ethernet = parser.OFPActionEncap(type_ethernet)
	set_eth_dst = parser.OFPActionSetField(eth_dst='00:1b:17:bb:d9:15')
	set_eth_src = parser.OFPActionSetField(eth_src='f8:ca:b8:33:6c:f7')	

	decap_ip = parser.OFPActionDecap(type_ip,type_udp)
	decap_udp = parser.OFPActionDecap(type_udp,type_gtpu)
	decap_gtpu = parser.OFPActionDecap(type_gtpu,type_ip)
	decap_ethernet = parser.OFPActionDecap(type_ethernet, type_ip)

	output = parser.OFPActionOutput(3) # Change this to port 3 considering it has only IP packets after decapsulation

	actions = [decap_ethernet, decap_ip, decap_udp, decap_gtpu, encap_ethernet, set_eth_src, set_eth_dst, output]
	flow_mod = self.add_flow(datapath, 2, match, actions)


    def install_encap_ul_rules(self, datapath):
	"Create and install static flow entries for encap"
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser

	match = parser.OFPMatch(in_port=3,eth_type=2048) # Caching for example(IP packets)

	type_ip = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
	type_udp = (ofproto.OFPHTN_IP_PROTO << 16) | 1
	type_gtpu = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
	type_next = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_USE_NEXT_PROTO
	type_ethernet = (ofproto.OFPHTN_ONF << 16) | 0
	
	decap_ethernet = parser.OFPActionDecap(type_ethernet, type_ip)
	encap_ethernet = parser.OFPActionEncap(type_ethernet)
	set_eth_src = parser.OFPActionSetField(eth_src='f8:ca:b8:33:6c:f7')
	set_eth_dst = parser.OFPActionSetField(eth_dst='00:1b:17:bb:d9:15')	
	encap_gtpu = parser.OFPActionEncap(type_gtpu)
	set_gtpu_teid = parser.OFPActionSetField(gtpu_teid=33)
	encap_udp = parser.OFPActionEncap(type_udp)	
	set_udp_src = parser.OFPActionSetField(udp_src=2152)
	set_udp_dst = parser.OFPActionSetField(udp_dst=2152)
	encap_ip = parser.OFPActionEncap(type_ip)
	set_ipsrc = parser.OFPActionSetField(ipv4_src='192.168.51.10')
	set_ipdst = parser.OFPActionSetField(ipv4_dst='172.21.5.9')
	output = parser.OFPActionOutput(2) # eNB (GTP encapsulated packets)
	
	actions = [decap_ethernet, encap_gtpu, set_gtpu_teid, encap_udp, set_udp_src, set_udp_dst, encap_ip, set_ipsrc, set_ipdst, encap_ethernet, set_eth_src, set_eth_dst, output]
	flow_mod = self.add_flow(datapath, 2, match, actions)

	
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def remove_flows(self, datapath, table_id):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        print "deleting all flow entries in table ", table_id
        datapath.send_msg(flow_mod)
    

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0,0,						      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

	print 'msg=%s'%msg # ----------------------------------------------------------------------------Newly added comment
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	
	print 'eth= %s'%eth # ---------------------------------------------------------------------------Newly added comment
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
