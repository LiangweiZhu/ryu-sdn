from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp


class MainApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MainApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.eth_dst = ""
        self.eth_src = ""
        self.ip_src = ""
        self.ip_dst = ""
        self.ip_proto = ""
        self.tcp_src = 0
        self.tcp_dst = 0
        self.eth_type = ""
        self.IP1 = '10.0.0.1'
        self.IP2 = '10.0.0.2'
        self.CACHE_IP = '10.0.0.4'
        self.CACHE_MAC = '12:31:e6:e5:05:ee'
        self.in_port_list = {}
        self.IPinService = [self.IP1,self.IP2]
        self.service_nginx_dict = {self.IP1: self.CACHE_IP,self.IP2: self.CACHE_IP}

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)
    def set_defalut_flow_request(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,0x0800)
        match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,6)
        match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,80)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions))
        mod = parser.OFPFlowMod(datapath = datapath,priority=1,
                                match = match,instructions = inst)
        datapath.send_msg(mod)
    def set_defalut_flow_echo(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,0x0800)
        match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,6)
        match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,80)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions))
        mod = parser.OFPFlowMod(datapath = datapath,priority=1,
                                match = match,instructions = inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.set_defalut_flow_request(datapath)
        self.set_defalut_flow_echo(datapath)
        self.add_flow(datapath,0,match,actions)

    # mac learning
    def mac_learning(self, datapath, src, in_port):
        self.mac_to_port.setdefault((datapath, datapath.id), {})
        # learn a mac address to avoid FLOOD next time.
        if src in self.mac_to_port[(datapath, datapath.id)]:
            if in_port != self.mac_to_port[(datapath, datapath.id)][src]:
                return False
        else:
            self.mac_to_port[(datapath, datapath.id)][src] = in_port
            return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            match = parser.OFPMatch(eth_type=eth.ethertype)
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
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        #ip_pkt = pkt.get_protocol(arp.arp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        eth_dst = eth.dst
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
        actions = []
        if  icmp_pkt:
     #       self.logger.info('if tcp_pkt and ip_pkt:')
            if ip_pkt.src in self.IPinService\
                and ip_pkt.dst != self.CACHE_IP:
      #          self.logger.info('ip_pkt.src in self.IPinService')
      #          self.logger.info(ip_pkt.src)
      #          self.logger.info(eth_dst)
                if (eth.src) not in self.in_port_list:
                    self.in_port_list[(eth.src)] = (in_port,ip_pkt.dst,eth_dst)
                actions.append(parser.OFPActionSetField(ipv4_dst = self.CACHE_IP))
                actions.append(parser.OFPActionSetField(eth_dst=self.CACHE_MAC))
                actions = [parser.OFPActionOutput(1)]
                eth_dst = self.CACHE_MAC
                inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),parser.OFPInstructionGotoTable(0)]
                mod = parser.OFPFlowMod(datapath = datapath,priority = 2,table_id = 0,
                                        match = match,
                                        instructions = inst)
                datapath.send_msg(mod)

            if  ip_pkt.dst in self.IPinService\
                and eth_dst != self.CACHE_MAC:
 #               self.logger.info('ip_pkt.dst in self.IPinService')
 #               self.logger.info(ip_pkt.dst)
                value = self.in_port_list.get((eth_dst),-1)
                if value != -1:
                    actions.append(parser.OFPActionSetField(ipv4_src = value[1]))
                    actions.append(parser.OFPActionSetField(eth_src=value[2]))
                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
                    inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),parser.OFPInstructionGotoTable(0)]
                    mod = parser.OFPFlowMod(datapath = datapath,priority = 2,table_id = 0,
                                        match = match,
                                        instructions = inst)
                    datapath.send_msg(mod)

        self.mac_learning(datapath, eth.src, in_port)
        if eth_dst in self.mac_to_port[(datapath, datapath.id)]:
            self.logger.info('eth_dst in self.mac_to_port')
            out_port = self.mac_to_port[(datapath, datapath.id)][eth_dst]
        else:
            if self.mac_learning(datapath, eth.src, in_port) is False:
                self.logger.info('if self.mac_learning')
                out_port = ofproto.OFPPC_NO_RECV
            else:
                self.logger.info('out_port = ofproto.OFPP_FLOOD')
                out_port = ofproto.OFPP_FLOOD

        actions=[parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                if not arp_pkt:
                    self.logger.info('out_port != ofproto.OFPP_FLOOD:')
                    self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                    return
        else:
            if not arp_pkt:
                self.logger.info('if not arp_pkt:')
        #        match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
        #        self.add_flow(datapath, 10, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
