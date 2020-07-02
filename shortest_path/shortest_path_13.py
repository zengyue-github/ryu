from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import ether_types
import networkx as nx


class SimpleShortestForwarding(app_manager.RyuApp):
    """docstring for SimpleShortestForwarding"""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleShortestForwarding, self).__init__(*args, **kwargs)
        self.topology_api_app = self

        # initialize network
        self.ip_network=nx.DiGraph()    # ip network
        self.mac_network=nx.DiGraph()   # mac network

        # record information
        self.ip_to_mac = {}     # host ip to mac dic
        self.hosts_mac = []     # hosts mac
        self.hosts_mac_unknow = [] # unknow host mac
        self.hosts_ip = []      # hosts ip

        self.link_to_port = {}  # link to port
        self.dpid_to_obj = {}       # dpid to datapath object
        self.host_to_switch = {}    # host to switch dpid

        # configure
        self.show_or_not = True

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # install table-miss flow entry.
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath=datapath, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.dpid_to_obj:
                self.dpid_to_obj[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.dpid_to_obj:
                self.dpid_to_obj.pop(datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.get_topology()
        msg = ev.msg

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)   # get mac data
        ip_pkt = pkt.get_protocol(ipv4.ipv4)    # get ip data
        arp_pkt = pkt.get_protocol(arp.arp)     # get arp data

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        if arp_pkt:
            # Processing ARP packages
            self.print_data('Processing ARP package:')

            self.processing_ARP_package(msg, arp_pkt)
        
        if ip_pkt and eth:
            # Processing IP packages
            self.print_data('Processing IP package:')

            self.processing_IP_package(msg, eth, ip_pkt)

    def processing_IP_package(self, msg, eth, ip_pkt):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        eth_mac_src = eth.src
        eth_mac_dst = eth.dst
        eth_type = eth.ethertype

        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst

        ip_path = nx.shortest_path(self.ip_network,ip_src,ip_dst)
        mac_path = nx.shortest_path(self.mac_network,eth_mac_src,eth_mac_dst)
        print 'ip path: ',ip_path
        print 'mac path: ',mac_path

        #install path rule in reverse order
        for i in range(len(mac_path)-2,0,-1):
            dpid = mac_path[i]
            out_port = self.link_to_port[(dpid,mac_path[i+1])]
            in_port = self.link_to_port[(dpid,mac_path[i-1])]
            datapath = self.dpid_to_obj[dpid]

            #install forwarding rule
            self.install_rule(ofp_parser,datapath=datapath,out_port=out_port,in_port=in_port,eth_type=eth_type,ip_src=ip_src,ip_dst=ip_dst,priority=1)

            #install backward rule
            self.install_rule(ofp_parser,datapath=datapath,out_port=in_port,in_port=out_port,eth_type=eth_type,ip_src=ip_dst,ip_dst=ip_src,priority=1)

        #send back no buffer data
        datapath = msg.datapath
        dpid = datapath.id
        next_dpid_index = mac_path.index(datapath.id) + 1
        next_dpid = mac_path[next_dpid_index]

        in_port = msg.match['in_port']
        out_port = self.link_to_port[(dpid,next_dpid)]
        self.send_data(msg,ofp_parser,ofproto,datapath=msg.datapath,in_port=in_port,out_port=out_port)

    def processing_ARP_package(self, msg, arp_pkt):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        dpid = datapath.id
        arp_ip_src = arp_pkt.src_ip
        arp_ip_dst = arp_pkt.dst_ip
        arp_mac_src = arp_pkt.src_mac
        arp_mac_dst = arp_pkt.dst_mac
        print 'arp ip src:',arp_ip_src,'arp ip dst:',arp_ip_dst,'dpid:',dpid

        # update info        
        if arp_ip_src not in self.ip_to_mac.keys():
            self.ip_to_mac[arp_ip_src] = arp_mac_src
            self.ip_network.add_edge(arp_ip_src,dpid)
            self.ip_network.add_edge(dpid,arp_ip_src)
            self.hosts_ip = self.ip_to_mac.keys()
            self.hosts_mac_unknow = set(self.hosts_mac) - set(self.ip_to_mac.values())

        if arp_mac_dst not in self.hosts_mac and arp_ip_dst not in self.hosts_ip: 
            # send data to unknown hosts
            for host_mac in self.hosts_mac_unknow:
                dpid = self.host_to_switch[host_mac]
                datapath = self.dpid_to_obj[dpid]
                out_port = self.link_to_port[dpid,host_mac]
                in_port = ofproto.OFPP_CONTROLLER

                #send data
                self.send_data(msg,ofp_parser,ofproto,datapath=datapath,in_port=in_port,out_port=out_port)
                print 'unknown: dpid, ',datapath.id,',in_port ,',in_port,',out_port,',out_port
        else:
            # send data to dst host
            dpid = self.host_to_switch[self.ip_to_mac[arp_ip_dst]]
            datapath = self.dpid_to_obj[dpid]
            out_port = self.link_to_port[dpid,self.ip_to_mac[arp_ip_dst]]
            in_port = ofproto.OFPP_CONTROLLER

            #send data
            self.send_data(msg,ofp_parser,ofproto,datapath=datapath,in_port=in_port,out_port=out_port)
            print 'known: dpid, ',datapath.id,',in_port ,',in_port,',out_port,',out_port

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            actions)]
        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,
                               match=match, instructions=inst)
        datapath.send_msg(mod)

    def get_topology(self):
        # add switches
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        self.mac_network.add_nodes_from(switches)
        self.ip_network.add_nodes_from(switches)

        # add switch links
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid,link.dst.dpid) for link in links_list]
        self.mac_network.add_edges_from(links)
        self.ip_network.add_edges_from(links)

        # add link to port
        for link in links_list:
            self.link_to_port[(link.src.dpid,link.dst.dpid)] = link.src.port_no

        # add hosts
        hosts_list = get_host(self.topology_api_app, None)
        hosts = [host.mac for host in hosts_list]
        self.mac_network.add_nodes_from(hosts)
        self.hosts_mac = hosts

        # add host links
        host_links = [(host.port.dpid,host.mac) for host in hosts_list]
        self.mac_network.add_edges_from(host_links)

        host_links = [(host.mac,host.port.dpid) for host in hosts_list]
        self.mac_network.add_edges_from(host_links)

        # add switch to host port
        for host in hosts_list:
            self.link_to_port[(host.port.dpid,host.mac)] = host.port.port_no
            self.host_to_switch[host.mac] = host.port.dpid

        if self.show_or_not and False:
            print '**********************************topology*****************************************'
            self.show_varible()

    def show_varible(self):
        print 'host mac: ',self.hosts_mac
        print 'host ip: ',self.hosts_ip
        print 'ip to mac:',self.ip_to_mac
        print 'unknow hosts:',self.hosts_mac_unknow
        print 'host mac to switch:',self.host_to_switch
        print 'link to port:',self.link_to_port

        print 'mac network edges: ',self.mac_network.edges()
        print 'mac network_nodes: ',self.mac_network.nodes()

        print 'ip network_edges: ',self.ip_network.edges()
        print 'ip network_nodes: ',self.ip_network.nodes()

    def print_data(self,data):
        if self.show_or_not:
            print ''
            print data

    def install_rule(self,ofp_parser,datapath=None,out_port=None,in_port=None,eth_type=None,ip_src=None,ip_dst=None,priority=1):
        actions = [ofp_parser.OFPActionOutput(out_port)]
        match = ofp_parser.OFPMatch(in_port=in_port, eth_type=eth_type,
                ipv4_src=ip_src, ipv4_dst=ip_dst)
        self.add_flow(datapath, priority, match, actions)

    def send_data(self,msg,ofp_parser,ofproto,datapath=None,in_port=None,out_port=None):
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        actions = [ofp_parser.OFPActionOutput(out_port)]
        out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)