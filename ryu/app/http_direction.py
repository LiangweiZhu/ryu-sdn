# -*- coding:utf-8 -*-
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


CACHE_IP = '10.0.0.10'
CACHE_MAC = 'fa:16:3e:e6:c0:7f'
SWITCH_TO_NET = 4
SWITCH_TO_NGNIX = 3
NGNIX_PORT = 80
NGNIX_REDIRECT_TABLE = 1
IP1 = '10.0.0.8'
IP2 = '10.0.0.6'

class Http_Direction(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __int__(self, *args, **kwargs):
        super(Http_Direction,self).__init__(*args, **kwargs)
        self.IPinService = [IP1, IP2]
        self.service_nginx_dict = {IP1 : CACHE_IP, IP2 : CACHE_IP}
        self.local_cache = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.set_default_flow_pc(datapath)
        self.set_default_flow_server(datapath)

    def set_default_flow_pc(self, datapath, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, 0x0800)
        match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO, 6)
        match.append_field(ofproto_v1_3.OXM_OF_TCP_DST, NGNIX_PORT)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(datapath=datapath, priority =1,
                                table_id = NGNIX_REDIRECT_TABLE,
                                match = match, instructions = inst)
        datapath.send_msg(mod)

    def set_default_flow_server(self, datapath, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, 0x0800)
        match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO, 6)
        match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC, NGNIX_PORT)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(datapath=datapath, priority =1,
                                table_id = NGNIX_REDIRECT_TABLE,
                                match = match, instructions = inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _redirect(self, ev):
        # 先接收流信息储存，再重定向
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        header_list = dict ((p.protocol_name, p) for p in packet.Packet(msg.data).protocols if type(p) != str)
        in_port = msg.match['in_port'] #终端接入交换机入端口号
        eth_dst = header_list[ethernet].dst #终端请求目的端的MAC地址
        eth_src = header_list[ethernet].src #终端的MAC地址
        ip_src = header_list[ipv4].src #终端的IP地址
        ip_proto = header_list[ipv4].proto #请求的IP协议类型
        ip_dst = header_list[ipv4].dst #终端请求目的端的IP地址
        tcp_src = header_list[tcp].src_port #数据包的传输层的源端口号
        tcp_dst = header_list[tcp].dst_port #数据包的传输层目的端口号
        eth_type = header_list[ethernet].ethertype #请求数据包的以太网协议类型
        self.local_cache.setdefault((eth_src, tcp_src), (in_port, ip_dst, eth_dst))
        # 键：终端MAC地址，传输层源端口号 值：交换机入端口，终端请求目的端的IP地址，终端请求目的端的MAC地址

        # 重定向过程
        if tcp_dst == 80 and ip_src in self.IPinService and eth_src != CACHE_MAC and ip_dst != CACHE_IP:
            # 主机侧 传输层目的端口号是80 且 终端是需要提供加速代理的用户 且 过滤由代理服务器发出和主动发往代理服务器的流量。

            actions = []
            actions.append(parser.OFPActionSetField(ipv4_dst = CACHE_IP))  #修改目的IP，MAC为代理服务器
            actions.append(parser.OFPActionSetField(eth_dst = CACHE_MAC))
            actions.append(parser.OFPActionOutput(SWITCH_TO_NGNIX))
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(NGNIX_REDIRECT_TABLE + 1)]
            match = parser.OFPMatch(ip_src = ip_src, tcp_src = tcp_src) # 修改对应主机IP和主机端口号的流表
            mod = parser.OFPFlowMod(datapath = datapath, priority = 2,
                                    table_id = NGNIX_REDIRECT_TABLE,
                                    idle_timeout = 0, hard_timeout =10,
                                    match = match, instructions = inst)
            datapath.send_msg(mod)

        elif (tcp_dst == 80 and ip_src not in self.IPinService ) or eth_src == CACHE_MAC:
            # 目的端口号为80 且 不需要重定向的机器 或者 是代理服务器发出的流量 向网关转发
            actions = [parser.OFPActionOutput(SWITCH_TO_NET)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            match = parser.OFPMatch(ip_src = ip_src, tcp_src = tcp_src)
            mod = parser.OFPFlowMod(datapath = datapath, priority = 2,
                                    idle_timeout = 0, hard_timeout = 10,
                                    match = match, instructions = inst)
            datapath.send_msg(mod)

        if tcp_src == 80 and ip_dst in self.IPinService and eth_dst != CACHE_MAC:
            # 代理服务器侧 传输层源端口号是80 且 终端是需要提供加速代理的用户 且 过滤发往代理服务器的流量。
            values = self.local_cache.get((eth_src, tcp_src))
            if values:
                actions = []
                actions.append(parser.OFPActionSetField(ipv4_src = values[1]))
                actions.append(parser.OFPActionSetField(eth_src = values[2]))
                actions.append(parser.OFPActionOutput(values[0]))
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(NGNIX_REDIRECT_TABLE + 1)]
                match = parser.OFPMatch(ip_dst = ip_dst, tcp_dst = tcp_dst)
                mod = parser.OFPFlowMod(datapath = datapath, priority = 2,
                                        table_id = NGNIX_REDIRECT_TABLE,
                                        idle_timeout = 0, hard_timeout =10,
                                        match = match, instructions = inst)
                datapath.send_msg(mod)
            else: print('Error:[2] No Cache')

        elif (tcp_src == 80 and ip_dst not in self.IPinService) or ip_dst == CACHE_IP:
            # 源端口号为80 且 目的IP是不需要代理的机器 或者 目的IP为代理服务器
            actions = []
            if ip_dst == CACHE_IP:
                # 若目的IP是代理服务器，将包转向代理服务器
                actions.append(parser.OFPActionOutput(SWITCH_TO_NGNIX))
            else:
                # 若目的IP是非代理的PC，获取Cache,确定出端口
                values = self.local_cache.get((eth_dst, tcp_dst))
                if values:
                    actions.append(parser.OFPActionOutput(values[0]))
                else: print('Error: [3] key not found :key: ' + eth_dst +','+ tcp_dst)

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            match = parser.OFPMatch(ip_dst = ip_dst, tcp_dst = tcp_dst)
            mod = parser.OFPFlowMod(datapath = datapath, match = match, instructions = inst)
            datapath.send_msg(mod)


