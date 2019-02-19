from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
import threading
from ryu.lib import hub

class ARP_PROXY_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(ARP_PROXY_13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.total_port = [4,5,6]
	self.now_port=0
        self.isFirst = 1
        self.datapath = None
        self.eth_dst = None
        self.doit_thread = hub.spawn(self._doit)
        self.mac_dst = None
        self.ip_dst = None

    def send_flow_mod(self, datapath):
        if self.eth_dst is not None:
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            parser = datapath.ofproto_parser
            cookie = cookie_mask = 0
            table_id = 0
            idle_timeout = hard_timeout = 0
            priority = 10
	    out_port = 0
            if self.now_port != 0:
                if self.now_port == 4:
                    self.now_port = 5
                elif self.now_port == 5:
                    self.now_port = 6
                elif self.now_port == 6:
                    self.now_port = 4
                out_port = self.now_port
            buffer_id = ofp.OFP_NO_BUFFER
            match = ofp_parser.OFPMatch(in_port=1, eth_dst=self.eth_dst)
            actions = [parser.OFPActionOutput(out_port)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                        table_id, ofp.OFPFC_ADD,
                                        idle_timeout, hard_timeout,
                                        priority, buffer_id,
                                        ofp.OFPP_ANY, ofp.OFPG_ANY,
                                        ofp.OFPFF_SEND_FLOW_REM,
                                        match, inst)
            datapath.send_msg(req)
            self.send_flow_stats_request(datapath)
    def _doit(self):
        while True:
            if self.isFirst !=1:
                if self.datapath !=None:
                    self.send_flow_mod(self.datapath)
            hub.sleep(8)
            self.isFirst = self.isFirst+1

    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = None
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                                 ofp.OFPTT_ALL,
                                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                 cookie, cookie_mask,
                                                 match)
        datapath.send_msg(req)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d '
                         'match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout, stat.flags,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))
            if ev.msg.datapath.id == 1:
                if stat.match.get('in_port') is not None:
                    in_port = stat.match.get('in_port')
                    out_port = stat.instructions[0].actions[0].port
                    eth_dst = stat.match.get('eth_dst')
                    if eth_dst == self.eth_dst:
                        self.logger.info('in_port: %s', stat.match.get('in_port'))
                        self.logger.info('out_port: %s', stat.instructions[0].actions[0].port)
                        self.now_port = stat.instructions[0].actions[0].port
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        if ev.msg.datapath.id == 1:
            self.datapath = ev.msg.datapath
        datapath = ev.msg.datapath      
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #match all flow
        match = parser.OFPMatch()
        #send the flow to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
 
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #apply the action immediately
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        #how the buffer_id works : if exist,data in catch will work.else send the all
        #data to controller rather than the buffer_id
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                             priority=priority, match=match,
                             instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                             match=match, instructions=inst)
        datapath.send_msg(mod)
        if datapath.id ==1:
            self.send_flow_stats_request(datapath)

#mac learning
    def mac_learning(self, datapath, src, in_port):
        self.mac_to_port.setdefault((datapath,datapath.id), {})
        # learn a mac address to avoid FLOOD next time.
        if src in self.mac_to_port[(datapath,datapath.id)]:
            if in_port != self.mac_to_port[(datapath,datapath.id)][src]:
                return False
        else:
            self.mac_to_port[(datapath,datapath.id)][src] = in_port
            return True
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #get the in_port
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
 
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:

            match = parser.OFPMatch(eth_type=eth.ethertype)
            #what?
            actions = []
            self.add_flow(datapath, 10, match, actions)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 10, match, actions)
            return
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        dst = eth.dst
        src = eth.src
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            # avoid the arp packet
            if ip_src != '0.0.0.0':
                self.mac_dst = dst
                self.ip_dst = ip_dst
                self.eth_dst = dst
        self.mac_learning(datapath, src, in_port)
        if dst in self.mac_to_port[(datapath,datapath.id)]:
            out_port = self.mac_to_port[(datapath,datapath.id)][dst]
        else:
            if self.mac_learning(datapath, src, in_port) is False:
                #drap the packet arousing the strom
                out_port = ofproto.OFPPC_NO_RECV
            else:
                out_port = ofproto.OFPP_FLOOD
 	
        actions = [parser.OFPActionOutput(out_port)]
 
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
