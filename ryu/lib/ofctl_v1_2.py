# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import struct
import socket
import logging
import netaddr

from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.lib import hub
from ryu.lib import mac


LOG = logging.getLogger('ryu.lib.ofctl_v1_2')

DEFAULT_TIMEOUT = 1.0


def to_actions(dp, acts):
    inst = []

    for a in acts:
        action_type = a.get('type')
        if action_type == 'OUTPUT':
            out_port = int(a.get('port', ofproto_v1_2.OFPP_ANY))
            max_len = int(a.get('max_len', ofproto_v1_2.OFPCML_MAX))
            actions = [dp.ofproto_parser.OFPActionOutput(
                       out_port, max_len=max_len)]
            inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS
            inst = [dp.ofproto_parser.OFPInstructionActions(
                    inst_type, actions)]
        else:
            LOG.debug('Unknown action type')

    return inst


def actions_to_str(instructions):
    actions = []

    for instruction in instructions:
        if not isinstance(instruction,
                          ofproto_v1_2_parser.OFPInstructionActions):
            continue
        for a in instruction.actions:
            action_type = a.cls_action_type

            if action_type == ofproto_v1_2.OFPAT_OUTPUT:
                buf = 'OUTPUT:' + str(a.port)
            else:
                buf = 'UNKNOWN'
            actions.append(buf)

    return actions


def to_match(dp, attrs):
    match = dp.ofproto_parser.OFPMatch()

    convert = {'in_port': int,
               'dl_src': mac.haddr_to_bin,
               'dl_dst': mac.haddr_to_bin,
               'dl_type': int,
               'dl_vlan': int,
               'nw_src': to_match_ip,
               'nw_dst': to_match_ip,
               'nw_proto': int,
               'tp_src': int,
               'tp_dst': int,
               'eth_src': mac.haddr_to_bin,
               'eth_dst': mac.haddr_to_bin,
               'eth_type': int,
               'vlan_vid': int,
               'ipv4_src': to_match_ip,
               'ipv4_dst': to_match_ip,
               'ip_proto': int,
               'tcp_src': int,
               'tcp_dst': int,
               'udp_src': int,
               'udp_dst': int,
               'ipv6_src': to_match_ipv6,
               'ipv6_dst': to_match_ipv6}

    match_append = {'in_port': match.set_in_port,
                    'dl_src': match.set_dl_src,
                    'dl_dst': match.set_dl_dst,
                    'dl_type': match.set_dl_type,
                    'dl_vlan': match.set_vlan_vid,
                    'nw_src': match.set_ipv4_src_masked,
                    'nw_dst': match.set_ipv4_dst_masked,
                    'nw_proto': match.set_ip_proto,
                    'tp_src': to_match_tpsrc,
                    'tp_dst': to_match_tpdst,
                    'eth_src': match.set_dl_src,
                    'eth_dst': match.set_dl_dst,
                    'eth_type': match.set_dl_type,
                    'vlan_vid': match.set_vlan_vid,
                    'ipv4_src': match.set_ipv4_src_masked,
                    'ipv4_dst': match.set_ipv4_dst_masked,
                    'ip_proto': match.set_ip_proto,
                    'tcp_src': to_match_tpsrc,
                    'tcp_dst': to_match_tpdst,
                    'udp_src': to_match_tpsrc,
                    'udp_dst': to_match_tpdst,
                    'ipv6_src': match.set_ipv6_src_masked,
                    'ipv6_dst': match.set_ipv6_dst_masked}

    for key, value in attrs.items():
        if key in convert:
            value = convert[key](value)
        if key in match_append:
            if key == 'nw_src' or key == 'nw_dst' or \
                    key == 'ipv4_src' or key == 'ipv4_dst' or \
                    key == 'ipv6_src' or key == 'ipv6_dst':
                # IP address
                ip = value[0]
                mask = value[1]
                match_append[key](ip, mask)
            elif key == 'tp_src' or key == 'tp_dst' or \
                    key == 'tcp_src' or key == 'tcp_dst' or \
                    key == 'udp_src' or key == 'udp_dst':
                # tp_src/dst
                match_append[key](value, match, attrs)
            else:
                # others
                match_append[key](value)

    return match


def to_match_tpsrc(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_src,
                    inet.IPPROTO_UDP: match.set_udp_src}

    nw_proto = rest.get('nw_proto', rest.get('ip_proto', 0))
    if nw_proto in match_append:
        match_append[nw_proto](value)

    return match


def to_match_tpdst(value, match, rest):
    match_append = {inet.IPPROTO_TCP: match.set_tcp_dst,
                    inet.IPPROTO_UDP: match.set_udp_dst}

    nw_proto = rest.get('nw_proto', rest.get('ip_proto', 0))
    if nw_proto in match_append:
        match_append[nw_proto](value)

    return match


def to_match_ip(value):
    ip_mask = value.split('/')
    # ip
    ipv4 = struct.unpack('!I', socket.inet_aton(ip_mask[0]))[0]
    # netmask
    mask = 32
    if len(ip_mask) == 2:
        mask = int(ip_mask[1])
    netmask = ofproto_v1_2_parser.UINT32_MAX << 32 - mask\
        & ofproto_v1_2_parser.UINT32_MAX

    return ipv4, netmask


def to_match_ipv6(value):
    ip = netaddr.IPNetwork(value)
    return ip.ip.words, ip.netmask.words


def match_to_str(ofmatch):
    keys = {ofproto_v1_2.OXM_OF_IN_PORT: 'in_port',
            ofproto_v1_2.OXM_OF_ETH_SRC: 'dl_src',
            ofproto_v1_2.OXM_OF_ETH_DST: 'dl_dst',
            ofproto_v1_2.OXM_OF_ETH_TYPE: 'dl_type',
            ofproto_v1_2.OXM_OF_VLAN_VID: 'dl_vlan',
            ofproto_v1_2.OXM_OF_IPV4_SRC: 'nw_src',
            ofproto_v1_2.OXM_OF_IPV4_DST: 'nw_dst',
            ofproto_v1_2.OXM_OF_IPV4_SRC_W: 'nw_src',
            ofproto_v1_2.OXM_OF_IPV4_DST_W: 'nw_dst',
            ofproto_v1_2.OXM_OF_IP_PROTO: 'nw_proto',
            ofproto_v1_2.OXM_OF_TCP_SRC: 'tp_src',
            ofproto_v1_2.OXM_OF_TCP_DST: 'tp_dst',
            ofproto_v1_2.OXM_OF_UDP_SRC: 'tp_src',
            ofproto_v1_2.OXM_OF_UDP_DST: 'tp_dst',
            ofproto_v1_2.OXM_OF_IPV6_SRC: 'ipv6_src',
            ofproto_v1_2.OXM_OF_IPV6_DST: 'ipv6_dst',
            ofproto_v1_2.OXM_OF_IPV6_SRC_W: 'ipv6_src',
            ofproto_v1_2.OXM_OF_IPV6_DST_W: 'ipv6_dst'}

    match = {}
    for match_field in ofmatch.fields:
        key = keys[match_field.header]
        if key == 'dl_src' or key == 'dl_dst':
            value = mac.haddr_to_str(match_field.value)
        elif key == 'nw_src' or key == 'nw_dst':
            value = match_ip_to_str(match_field.value, match_field.mask)
        elif key == 'ipv6_src' or key == 'ipv6_dst':
            value = match_ipv6_to_str(match_field.value, match_field.mask)
        else:
            value = match_field.value
        match.setdefault(key, value)

    return match


def match_ip_to_str(value, mask):
    ip = socket.inet_ntoa(struct.pack('!I', value))

    if mask is not None and mask != 0:
        binary_str = bin(mask)[2:].zfill(8)
        netmask = '/%d' % len(binary_str.rstrip('0'))
    else:
        netmask = ''

    return ip + netmask


def match_ipv6_to_str(value, mask):
    ip_list = []
    for word in value:
        ip_list.append('%04x' % word)
    ip = netaddr.IPNetwork(':'.join(ip_list))

    netmask = 128
    if mask is not None:
        mask_list = []
        for word in mask:
            mask_list.append('%04x' % word)
        mask_v = netaddr.IPNetwork(':'.join(mask_list))
        netmask = len(mask_v.ip.bits().replace(':', '').rstrip('0'))

    if netmask == 128:
        ip_str = str(ip.ip)
    else:
        ip.prefixlen = netmask
        ip_str = str(ip)

    return ip_str


def send_stats_request(dp, stats, waiters, msgs):
    dp.set_xid(stats)
    waiters_per_dp = waiters.setdefault(dp.id, {})
    lock = hub.Event()
    waiters_per_dp[stats.xid] = (lock, msgs)
    dp.send_msg(stats)

    try:
        lock.wait(timeout=DEFAULT_TIMEOUT)
    except hub.Timeout:
        del waiters_per_dp[stats.xid]


def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    s = {}
    for msg in msgs:
        stats = msg.body
        s = {'mfr_desc': stats.mfr_desc,
             'hw_desc': stats.hw_desc,
             'sw_desc': stats.sw_desc,
             'serial_num': stats.serial_num,
             'dp_desc': stats.dp_desc}
    desc = {str(dp.id): s}
    return desc


def get_flow_stats(dp, waiters):
    table_id = 0
    out_port = dp.ofproto.OFPP_ANY
    out_group = dp.ofproto.OFPG_ANY
    cookie = 0
    cookie_mask = 0
    match = dp.ofproto_parser.OFPMatch()

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, table_id, out_port, out_group, cookie, cookie_mask, match)

    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            actions = actions_to_str(stats.instructions)
            match = match_to_str(stats.match)
            s = {'priority': stats.priority,
                 'cookie': stats.cookie,
                 'idle_timeout': stats.idle_timeout,
                 'hard_timeout': stats.hard_timeout,
                 'actions': actions,
                 'match': match,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'packet_count': stats.packet_count,
                 'table_id': stats.table_id}
            flows.append(s)
    flows = {str(dp.id): flows}

    return flows


def get_port_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, dp.ofproto.OFPP_ANY, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = {'port_no': stats.port_no,
                 'rx_packets': stats.rx_packets,
                 'tx_packets': stats.tx_packets,
                 'rx_bytes': stats.rx_bytes,
                 'tx_bytes': stats.tx_bytes,
                 'rx_dropped': stats.rx_dropped,
                 'tx_dropped': stats.tx_dropped,
                 'rx_errors': stats.rx_errors,
                 'tx_errors': stats.tx_errors,
                 'rx_frame_err': stats.rx_frame_err,
                 'rx_over_err': stats.rx_over_err,
                 'rx_crc_err': stats.rx_crc_err,
                 'collisions': stats.collisions}
            ports.append(s)
    ports = {str(dp.id): ports}
    return ports


def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    table_id = int(flow.get('table_id', 0))
    idle_timeout = int(flow.get('idle_timeout', 0))
    hard_timeout = int(flow.get('hard_timeout', 0))
    priority = int(flow.get('priority', 0))
    buffer_id = int(flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = int(flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = int(flow.get('out_group', dp.ofproto.OFPG_ANY))
    flags = int(flow.get('flags', 0))
    match = to_match(dp, flow.get('match', {}))
    inst = to_actions(dp, flow.get('actions', []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        flags, match, inst)

    dp.send_msg(flow_mod)


def send_experimenter(dp, exp):
    experimenter = exp.get('experimenter', 0)
    exp_type = exp.get('exp_type', 0)
    data_type = exp.get('data_type', 'ascii')
    if data_type != 'ascii' and data_type != 'base64':
        LOG.debug('Unknown data type: %s', data_type)
    data = exp.get('data', '')
    if data_type == 'base64':
        data = base64.b64decode(data)

    expmsg = dp.ofproto_parser.OFPExperimenter(
        dp, experimenter, exp_type, data)

    dp.send_msg(expmsg)
