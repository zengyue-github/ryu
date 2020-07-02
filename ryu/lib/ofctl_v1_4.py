# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
import logging
import netaddr
import six

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_4_parser
from ryu.lib import hub
from ryu.lib import ofctl_utils

LOG = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 1.0

UTIL = ofctl_utils.OFCtlUtil(ofproto_v1_4)


def to_action(dp, dic):
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    action_type = dic.get('type')

    if action_type == 'OUTPUT':
        out_port = UTIL.ofp_port_from_user(dic.get('port', ofp.OFPP_ANY))
        max_len = UTIL.ofp_cml_from_user(dic.get('max_len', ofp.OFPCML_MAX))
        action = parser.OFPActionOutput(out_port, max_len)
    elif action_type == 'COPY_TTL_OUT':
        action = parser.OFPActionCopyTtlOut()
    elif action_type == 'COPY_TTL_IN':
        action = parser.OFPActionCopyTtlIn()
    elif action_type == 'SET_MPLS_TTL':
        mpls_ttl = int(dic.get('mpls_ttl'))
        action = parser.OFPActionSetMplsTtl(mpls_ttl)
    elif action_type == 'DEC_MPLS_TTL':
        action = parser.OFPActionDecMplsTtl()
    elif action_type == 'PUSH_VLAN':
        ethertype = int(dic.get('ethertype'))
        action = parser.OFPActionPushVlan(ethertype)
    elif action_type == 'POP_VLAN':
        action = parser.OFPActionPopVlan()
    elif action_type == 'PUSH_MPLS':
        ethertype = int(dic.get('ethertype'))
        action = parser.OFPActionPushMpls(ethertype)
    elif action_type == 'POP_MPLS':
        ethertype = int(dic.get('ethertype'))
        action = parser.OFPActionPopMpls(ethertype)
    elif action_type == 'SET_QUEUE':
        queue_id = UTIL.ofp_queue_from_user(dic.get('queue_id'))
        action = parser.OFPActionSetQueue(queue_id)
    elif action_type == 'GROUP':
        group_id = UTIL.ofp_group_from_user(dic.get('group_id'))
        action = parser.OFPActionGroup(group_id)
    elif action_type == 'SET_NW_TTL':
        nw_ttl = int(dic.get('nw_ttl'))
        action = parser.OFPActionSetNwTtl(nw_ttl)
    elif action_type == 'DEC_NW_TTL':
        action = parser.OFPActionDecNwTtl()
    elif action_type == 'SET_FIELD':
        field = dic.get('field')
        value = dic.get('value')
        action = parser.OFPActionSetField(**{field: value})
    elif action_type == 'PUSH_PBB':
        ethertype = int(dic.get('ethertype'))
        action = parser.OFPActionPushPbb(ethertype)
    elif action_type == 'POP_PBB':
        action = parser.OFPActionPopPbb()
    elif action_type == 'EXPERIMENTER':
        experimenter = int(dic.get('experimenter'))
        data_type = dic.get('data_type', 'ascii')
        if data_type != 'ascii' and data_type != 'base64':
            LOG.error('Unknown data type: %s', data_type)
        data = dic.get('data', '')
        if data_type == 'base64':
            data = base64.b64decode(data)
        action = parser.OFPActionExperimenterUnknown(experimenter, data)
    else:
        action = None

    return action


def _get_actions(dp, dics):
    actions = []
    for d in dics:
        action = to_action(dp, d)
        if action is not None:
            actions.append(action)
        else:
            LOG.error('Unknown action type: %s', d)
    return actions


def to_instructions(dp, insts):
    instructions = []
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    for i in insts:
        inst_type = i.get('type')
        if inst_type in ['APPLY_ACTIONS', 'WRITE_ACTIONS']:
            dics = i.get('actions', [])
            actions = _get_actions(dp, dics)
            if actions:
                if inst_type == 'APPLY_ACTIONS':
                    instructions.append(
                        parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions))
                else:
                    instructions.append(
                        parser.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS,
                                                     actions))
        elif inst_type == 'CLEAR_ACTIONS':
            instructions.append(
                parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, []))
        elif inst_type == 'GOTO_TABLE':
            table_id = int(i.get('table_id'))
            instructions.append(parser.OFPInstructionGotoTable(table_id))
        elif inst_type == 'WRITE_METADATA':
            metadata = ofctl_utils.str_to_int(i.get('metadata'))
            metadata_mask = (ofctl_utils.str_to_int(i['metadata_mask'])
                             if 'metadata_mask' in i
                             else parser.UINT64_MAX)
            instructions.append(
                parser.OFPInstructionWriteMetadata(
                    metadata, metadata_mask))
        elif inst_type == 'METER':
            meter_id = int(i.get('meter_id'))
            instructions.append(parser.OFPInstructionMeter(meter_id))
        else:
            LOG.error('Unknown instruction type: %s', inst_type)

    return instructions


def action_to_str(act):
    s = act.to_jsondict()[act.__class__.__name__]
    t = UTIL.ofp_action_type_to_user(s['type'])
    s['type'] = t if t != s['type'] else 'UNKNOWN'

    if 'field' in s:
        field = s.pop('field')
        s['field'] = field['OXMTlv']['field']
        s['mask'] = field['OXMTlv']['mask']
        s['value'] = field['OXMTlv']['value']

    return s


def _remove(d, names):
    f = lambda x: _remove(x, names)
    if isinstance(d, list):
        return list(map(f, d))
    if isinstance(d, dict):
        d2 = {}
        for k, v in d.items():
            if k in names:
                continue
            d2[k] = f(v)
        return d2
    return d


def instructions_to_str(instructions):

    s = []

    for i in instructions:
        v = i.to_jsondict()[i.__class__.__name__]
        t = UTIL.ofp_instruction_type_to_user(v['type'])
        inst_type = t if t != v['type'] else 'UNKNOWN'
        # apply/write/clear-action instruction
        if isinstance(i, ofproto_v1_4_parser.OFPInstructionActions):
            acts = []
            for a in i.actions:
                acts.append(action_to_str(a))
            v['type'] = inst_type
            v['actions'] = acts
            s.append(v)
        # others
        else:
            v['type'] = inst_type
            s.append(v)

    return s


def to_match(dp, attrs):
    convert = {'in_port': UTIL.ofp_port_from_user,
               'in_phy_port': int,
               'metadata': to_match_masked_int,
               'eth_dst': to_match_eth,
               'eth_src': to_match_eth,
               'eth_type': int,
               'vlan_vid': to_match_vid,
               'vlan_pcp': int,
               'ip_dscp': int,
               'ip_ecn': int,
               'ip_proto': int,
               'ipv4_src': to_match_ip,
               'ipv4_dst': to_match_ip,
               'tcp_src': int,
               'tcp_dst': int,
               'udp_src': int,
               'udp_dst': int,
               'sctp_src': int,
               'sctp_dst': int,
               'icmpv4_type': int,
               'icmpv4_code': int,
               'arp_op': int,
               'arp_spa': to_match_ip,
               'arp_tpa': to_match_ip,
               'arp_sha': to_match_eth,
               'arp_tha': to_match_eth,
               'ipv6_src': to_match_ip,
               'ipv6_dst': to_match_ip,
               'ipv6_flabel': int,
               'icmpv6_type': int,
               'icmpv6_code': int,
               'ipv6_nd_target': to_match_ip,
               'ipv6_nd_sll': to_match_eth,
               'ipv6_nd_tll': to_match_eth,
               'mpls_label': int,
               'mpls_tc': int,
               'mpls_bos': int,
               'pbb_isid': to_match_masked_int,
               'tunnel_id': to_match_masked_int,
               'ipv6_exthdr': to_match_masked_int}

    if attrs.get('eth_type') == ether.ETH_TYPE_ARP:
        if 'ipv4_src' in attrs and 'arp_spa' not in attrs:
            attrs['arp_spa'] = attrs['ipv4_src']
            del attrs['ipv4_src']
        if 'ipv4_dst' in attrs and 'arp_tpa' not in attrs:
            attrs['arp_tpa'] = attrs['ipv4_dst']
            del attrs['ipv4_dst']

    kwargs = {}
    for key, value in attrs.items():
        if key in convert:
            value = convert[key](value)
            kwargs[key] = value
        else:
            LOG.error('Unknown match field: %s', key)

    return dp.ofproto_parser.OFPMatch(**kwargs)


def to_match_eth(value):
    if '/' in value:
        value = value.split('/')
        return value[0], value[1]
    else:
        return value


def to_match_ip(value):
    if '/' in value:
        (ip_addr, ip_mask) = value.split('/')
        if ip_mask.isdigit():
            ip = netaddr.ip.IPNetwork(value)
            ip_addr = str(ip.ip)
            ip_mask = str(ip.netmask)
        return ip_addr, ip_mask
    else:
        return value


def to_match_vid(value):
    # NOTE: If "vlan_id" field is described as decimal int value
    #       (and decimal string value), it is treated as values of
    #       VLAN tag, and OFPVID_PRESENT(0x1000) bit is automatically
    #       applied. OTOH, If it is described as hexadecimal string,
    #       treated as values of oxm_value (including OFPVID_PRESENT
    #       bit), and OFPVID_PRESENT bit is NOT automatically applied.
    if isinstance(value, six.integer_types):
        # described as decimal int value
        return value | ofproto_v1_4.OFPVID_PRESENT
    else:
        if '/' in value:
            val = value.split('/')
            return int(val[0], 0), int(val[1], 0)
        else:
            if value.isdigit():
                # described as decimal string value
                return int(value, 10) | ofproto_v1_4.OFPVID_PRESENT
            else:
                return int(value, 0)


def to_match_masked_int(value):
    if isinstance(value, str) and '/' in value:
        value = value.split('/')
        return (ofctl_utils.str_to_int(value[0]),
                ofctl_utils.str_to_int(value[1]))
    else:
        return ofctl_utils.str_to_int(value)


def match_to_str(ofmatch):
    match = {}

    ofmatch = ofmatch.to_jsondict()['OFPMatch']
    ofmatch = ofmatch['oxm_fields']

    for match_field in ofmatch:
        key = match_field['OXMTlv']['field']
        mask = match_field['OXMTlv']['mask']
        value = match_field['OXMTlv']['value']
        if key == 'vlan_vid':
            value = match_vid_to_str(value, mask)
        elif key == 'in_port':
            value = UTIL.ofp_port_to_user(value)
        else:
            if mask is not None:
                value = str(value) + '/' + str(mask)
        match.setdefault(key, value)

    return match


def match_vid_to_str(value, mask):
    if mask is not None:
        value = '0x%04x/0x%04x' % (value, mask)
    else:
        if value & ofproto_v1_4.OFPVID_PRESENT:
            value = str(value & ~ofproto_v1_4.OFPVID_PRESENT)
        else:
            value = '0x%04x' % value
    return value


def send_stats_request(dp, stats, waiters, msgs):
    dp.set_xid(stats)
    waiters_per_dp = waiters.setdefault(dp.id, {})
    lock = hub.Event()
    previous_msg_len = len(msgs)
    waiters_per_dp[stats.xid] = (lock, msgs)
    dp.send_msg(stats)

    lock.wait(timeout=DEFAULT_TIMEOUT)
    current_msg_len = len(msgs)

    while current_msg_len > previous_msg_len:
        previous_msg_len = current_msg_len
        lock.wait(timeout=DEFAULT_TIMEOUT)
        current_msg_len = len(msgs)

    if not lock.is_set():
        del waiters_per_dp[stats.xid]


def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)
    s = {}

    for msg in msgs:
        stats = msg.body
        s = stats.to_jsondict()[stats.__class__.__name__]
    desc = {str(dp.id): s}
    return desc


def get_queue_stats(dp, waiters):
    ofp = dp.ofproto
    stats = dp.ofproto_parser.OFPQueueStatsRequest(dp, 0, ofp.OFPP_ANY,
                                                   ofp.OFPQ_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    desc = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s = stat.to_jsondict()[stat.__class__.__name__]
            properties = []
            for prop in stat.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                t = UTIL.ofp_queue_stats_prop_type_to_user(prop.type)
                p['type'] = t if t != p['type'] else 'UNKNOWN'
                properties.append(p)
            s['properties'] = properties
            desc.append(s)
    desc = {str(dp.id): desc}
    return desc


def get_queue_desc_stats(dp, waiters, port_no=None, queue_id=None):
    ofp = dp.ofproto
    port_no = port_no if port_no else ofp.OFPP_ANY
    queue_id = queue_id if queue_id else ofp.OFPQ_ALL

    stats = dp.ofproto_parser.OFPQueueDescStatsRequest(
        dp, 0, port_no, queue_id)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    configs = []
    for config in msgs:
        queue_list = []
        for queue in config.body:
            q = queue.to_jsondict()[queue.__class__.__name__]
            prop_list = []
            for prop in queue.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                t = UTIL.ofp_queue_desc_prop_type_to_user(prop.type)
                p['type'] = t if t != prop.type else 'UNKNOWN'
                prop_list.append(p)
            q['properties'] = prop_list
            queue_list.append(q)
        c = {'body': queue_list}
        configs.append(c)
    configs = {str(dp.id): configs}

    return configs


def get_flow_stats(dp, waiters, flow=None):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    flags = int(flow.get('flags', 0))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            s = stats.to_jsondict()[stats.__class__.__name__]
            s['instructions'] = instructions_to_str(stats.instructions)
            s['match'] = match_to_str(stats.match)
            flows.append(s)
    flows = {str(dp.id): flows}

    return flows


def get_aggregate_flow_stats(dp, waiters, flow=None):
    flow = flow if flow else {}
    table_id = UTIL.ofp_table_from_user(
        flow.get('table_id', dp.ofproto.OFPTT_ALL))
    flags = int(flow.get('flags', 0))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    match = to_match(dp, flow.get('match', {}))

    stats = dp.ofproto_parser.OFPAggregateStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    flows = []
    for msg in msgs:
        stats = msg.body
        s = stats.to_jsondict()[stats.__class__.__name__]
        flows.append(s)
    flows = {str(dp.id): flows}

    return flows


def get_table_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPTableStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    tables = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s = stat.to_jsondict()[stat.__class__.__name__]
            tables.append(s)
    desc = {str(dp.id): tables}

    return desc


def get_table_features(dp, waiters):
    stats = dp.ofproto_parser.OFPTableFeaturesStatsRequest(dp, 0, [])
    msgs = []
    ofproto = dp.ofproto
    send_stats_request(dp, stats, waiters, msgs)

    p_type_instructions = [ofproto.OFPTFPT_INSTRUCTIONS,
                           ofproto.OFPTFPT_INSTRUCTIONS_MISS]

    p_type_next_tables = [ofproto.OFPTFPT_NEXT_TABLES,
                          ofproto.OFPTFPT_NEXT_TABLES_MISS]

    p_type_actions = [ofproto.OFPTFPT_WRITE_ACTIONS,
                      ofproto.OFPTFPT_WRITE_ACTIONS_MISS,
                      ofproto.OFPTFPT_APPLY_ACTIONS,
                      ofproto.OFPTFPT_APPLY_ACTIONS_MISS]

    p_type_oxms = [ofproto.OFPTFPT_MATCH,
                   ofproto.OFPTFPT_WILDCARDS,
                   ofproto.OFPTFPT_WRITE_SETFIELD,
                   ofproto.OFPTFPT_WRITE_SETFIELD_MISS,
                   ofproto.OFPTFPT_APPLY_SETFIELD,
                   ofproto.OFPTFPT_APPLY_SETFIELD_MISS]

    p_type_experimenter = [ofproto.OFPTFPT_EXPERIMENTER,
                           ofproto.OFPTFPT_EXPERIMENTER_MISS]

    tables = []
    for msg in msgs:
        stats = msg.body
        for stat in stats:
            s = stat.to_jsondict()[stat.__class__.__name__]
            properties = []
            for prop in stat.properties:
                p = {}
                t = UTIL.ofp_table_feature_prop_type_to_user(prop.type)
                p['type'] = t if t != prop.type else 'UNKNOWN'
                if prop.type in p_type_instructions:
                    instruction_ids = []
                    for id in prop.instruction_ids:
                        i = {'len': id.len,
                             'type': id.type}
                        instruction_ids.append(i)
                    p['instruction_ids'] = instruction_ids
                elif prop.type in p_type_next_tables:
                    table_ids = []
                    for id in prop.table_ids:
                        table_ids.append(id)
                    p['table_ids'] = table_ids
                elif prop.type in p_type_actions:
                    action_ids = []
                    for id in prop.action_ids:
                        i = id.to_jsondict()[id.__class__.__name__]
                        action_ids.append(i)
                    p['action_ids'] = action_ids
                elif prop.type in p_type_oxms:
                    oxm_ids = []
                    for id in prop.oxm_ids:
                        i = id.to_jsondict()[id.__class__.__name__]
                        oxm_ids.append(i)
                    p['oxm_ids'] = oxm_ids
                elif prop.type in p_type_experimenter:
                    pass
                properties.append(p)
            s['name'] = stat.name.decode('utf-8')
            s['properties'] = properties
            tables.append(s)
    desc = {str(dp.id): tables}

    return desc


def get_port_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, 0, dp.ofproto.OFPP_ANY)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = stats.to_jsondict()[stats.__class__.__name__]
            properties = []
            for prop in stats.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                t = UTIL.ofp_port_stats_prop_type_to_user(prop.type)
                p['type'] = t if t != prop.type else 'UNKNOWN'
                properties.append(p)
            s['properties'] = properties
            ports.append(s)
    ports = {str(dp.id): ports}
    return ports


def get_meter_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPMeterStatsRequest(
        dp, 0, dp.ofproto.OFPM_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    meters = []
    for msg in msgs:
        for stats in msg.body:
            s = stats.to_jsondict()[stats.__class__.__name__]
            bands = []
            for band in stats.band_stats:
                b = band.to_jsondict()[band.__class__.__name__]
                bands.append(b)
            s['band_stats'] = bands
            meters.append(s)
    meters = {str(dp.id): meters}
    return meters


def get_meter_features(dp, waiters):
    ofp = dp.ofproto
    type_convert = {ofp.OFPMBT_DROP: 'DROP',
                    ofp.OFPMBT_DSCP_REMARK: 'DSCP_REMARK'}

    capa_convert = {ofp.OFPMF_KBPS: 'KBPS',
                    ofp.OFPMF_PKTPS: 'PKTPS',
                    ofp.OFPMF_BURST: 'BURST',
                    ofp.OFPMF_STATS: 'STATS'}

    stats = dp.ofproto_parser.OFPMeterFeaturesStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    features = []
    for msg in msgs:
        for feature in msg.body:
            band_types = []
            for k, v in type_convert.items():
                if (1 << k) & feature.band_types:
                    band_types.append(v)
            capabilities = []
            for k, v in sorted(capa_convert.items()):
                if k & feature.capabilities:
                    capabilities.append(v)
            f = {'max_meter': feature.max_meter,
                 'band_types': band_types,
                 'capabilities': capabilities,
                 'max_bands': feature.max_bands,
                 'max_color': feature.max_color}
            features.append(f)
    features = {str(dp.id): features}
    return features


def get_meter_config(dp, waiters):
    flags = {dp.ofproto.OFPMF_KBPS: 'KBPS',
             dp.ofproto.OFPMF_PKTPS: 'PKTPS',
             dp.ofproto.OFPMF_BURST: 'BURST',
             dp.ofproto.OFPMF_STATS: 'STATS'}

    stats = dp.ofproto_parser.OFPMeterConfigStatsRequest(
        dp, 0, dp.ofproto.OFPM_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    configs = []
    for msg in msgs:
        for config in msg.body:
            c = config.to_jsondict()[config.__class__.__name__]
            bands = []
            for band in config.bands:
                b = band.to_jsondict()[band.__class__.__name__]
                t = UTIL.ofp_meter_band_type_to_user(band.type)
                b['type'] = t if t != band.type else 'UNKNOWN'
                bands.append(b)
            c_flags = []
            for k, v in sorted(flags.items()):
                if k & config.flags:
                    c_flags.append(v)
            c['flags'] = c_flags
            c['bands'] = bands
            configs.append(c)
    configs = {str(dp.id): configs}
    return configs


def get_group_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPGroupStatsRequest(
        dp, 0, dp.ofproto.OFPG_ALL)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    groups = []
    for msg in msgs:
        for stats in msg.body:
            g = stats.to_jsondict()[stats.__class__.__name__]
            bucket_stats = []
            for bucket_stat in stats.bucket_stats:
                c = bucket_stat.to_jsondict()[bucket_stat.__class__.__name__]
                bucket_stats.append(c)
            g['bucket_stats'] = bucket_stats
            groups.append(g)
    groups = {str(dp.id): groups}
    return groups


def get_group_features(dp, waiters):

    ofp = dp.ofproto
    type_convert = {ofp.OFPGT_ALL: 'ALL',
                    ofp.OFPGT_SELECT: 'SELECT',
                    ofp.OFPGT_INDIRECT: 'INDIRECT',
                    ofp.OFPGT_FF: 'FF'}
    cap_convert = {ofp.OFPGFC_SELECT_WEIGHT: 'SELECT_WEIGHT',
                   ofp.OFPGFC_SELECT_LIVENESS: 'SELECT_LIVENESS',
                   ofp.OFPGFC_CHAINING: 'CHAINING',
                   ofp.OFPGFC_CHAINING_CHECKS: 'CHAINING_CHECKS'}
    act_convert = {ofp.OFPAT_OUTPUT: 'OUTPUT',
                   ofp.OFPAT_COPY_TTL_OUT: 'COPY_TTL_OUT',
                   ofp.OFPAT_COPY_TTL_IN: 'COPY_TTL_IN',
                   ofp.OFPAT_SET_MPLS_TTL: 'SET_MPLS_TTL',
                   ofp.OFPAT_DEC_MPLS_TTL: 'DEC_MPLS_TTL',
                   ofp.OFPAT_PUSH_VLAN: 'PUSH_VLAN',
                   ofp.OFPAT_POP_VLAN: 'POP_VLAN',
                   ofp.OFPAT_PUSH_MPLS: 'PUSH_MPLS',
                   ofp.OFPAT_POP_MPLS: 'POP_MPLS',
                   ofp.OFPAT_SET_QUEUE: 'SET_QUEUE',
                   ofp.OFPAT_GROUP: 'GROUP',
                   ofp.OFPAT_SET_NW_TTL: 'SET_NW_TTL',
                   ofp.OFPAT_DEC_NW_TTL: 'DEC_NW_TTL',
                   ofp.OFPAT_SET_FIELD: 'SET_FIELD',
                   ofp.OFPAT_PUSH_PBB: 'PUSH_PBB',
                   ofp.OFPAT_POP_PBB: 'POP_PBB',
                   ofp.OFPAT_EXPERIMENTER: 'EXPERIMENTER',
                   }

    stats = dp.ofproto_parser.OFPGroupFeaturesStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    features = []
    for msg in msgs:
        feature = msg.body
        types = []
        for k, v in type_convert.items():
            if (1 << k) & feature.types:
                types.append(v)
        capabilities = []
        for k, v in cap_convert.items():
            if k & feature.capabilities:
                capabilities.append(v)
        max_groups = []
        for k, v in type_convert.items():
            max_groups.append({v: feature.max_groups[k]})
        actions = []
        for k1, v1 in type_convert.items():
            acts = []
            for k2, v2 in act_convert.items():
                if (1 << k2) & feature.actions[k1]:
                    acts.append(v2)
            actions.append({v1: acts})
        f = {'types': types,
             'capabilities': capabilities,
             'max_groups': max_groups,
             'actions': actions}
        features.append(f)
    features = {str(dp.id): features}
    return features


def get_group_desc(dp, waiters):
    stats = dp.ofproto_parser.OFPGroupDescStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    descs = []
    for msg in msgs:
        for stats in msg.body:
            d = stats.to_jsondict()[stats.__class__.__name__]
            buckets = []
            for bucket in stats.buckets:
                b = bucket.to_jsondict()[bucket.__class__.__name__]
                actions = []
                for action in bucket.actions:
                    actions.append(action_to_str(action))
                b['actions'] = actions
                buckets.append(b)
            t = UTIL.ofp_group_type_to_user(stats.type)
            d['type'] = t if t != stats.type else 'UNKNOWN'
            d['buckets'] = buckets
            descs.append(d)
    descs = {str(dp.id): descs}
    return descs


def get_port_desc(dp, waiters):
    stats = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    descs = []

    for msg in msgs:
        stats = msg.body
        for stat in stats:
            d = stat.to_jsondict()[stat.__class__.__name__]
            properties = []
            for prop in stat.properties:
                p = prop.to_jsondict()[prop.__class__.__name__]
                t = UTIL.ofp_port_desc_prop_type_to_user(prop.type)
                p['type'] = t if t != prop.type else 'UNKNOWN'
                properties.append(p)
            d['name'] = stat.name.decode('utf-8')
            d['properties'] = properties
            descs.append(d)
    descs = {str(dp.id): descs}
    return descs


def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    table_id = UTIL.ofp_table_from_user(flow.get('table_id', 0))
    idle_timeout = int(flow.get('idle_timeout', 0))
    hard_timeout = int(flow.get('hard_timeout', 0))
    priority = int(flow.get('priority', 0))
    buffer_id = UTIL.ofp_buffer_from_user(
        flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = UTIL.ofp_port_from_user(
        flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = UTIL.ofp_group_from_user(
        flow.get('out_group', dp.ofproto.OFPG_ANY))
    importance = int(flow.get('importance', 0))
    flags = int(flow.get('flags', 0))
    match = to_match(dp, flow.get('match', {}))
    inst = to_instructions(dp, flow.get('instructions', []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        importance, flags, match, inst)

    dp.send_msg(flow_mod)


def mod_meter_entry(dp, meter, cmd):
    flags = 0
    if 'flags' in meter:
        meter_flags = meter['flags']
        if not isinstance(meter_flags, list):
            meter_flags = [meter_flags]
        for flag in meter_flags:
            t = UTIL.ofp_meter_flags_from_user(flag)
            f = t if t != flag else None
            if f is None:
                LOG.error('Unknown meter flag: %s', flag)
                continue
            flags |= f

    meter_id = UTIL.ofp_meter_from_user(meter.get('meter_id', 0))

    bands = []
    for band in meter.get('bands', []):
        band_type = band.get('type')
        rate = int(band.get('rate', 0))
        burst_size = int(band.get('burst_size', 0))
        if band_type == 'DROP':
            b = dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size)
        elif band_type == 'DSCP_REMARK':
            prec_level = int(band.get('prec_level', 0))
            b = dp.ofproto_parser.OFPMeterBandDscpRemark(
                rate, burst_size, prec_level)
        elif band_type == 'EXPERIMENTER':
            experimenter = int(band.get('experimenter', 0))
            b = dp.ofproto_parser.OFPMeterBandExperimenter(
                rate, burst_size, experimenter)
        else:
            LOG.error('Unknown band type: %s', band_type)
            continue
        bands.append(b)

    meter_mod = dp.ofproto_parser.OFPMeterMod(
        dp, cmd, flags, meter_id, bands)

    dp.send_msg(meter_mod)


def mod_group_entry(dp, group, cmd):
    group_type = str(group.get('type'))
    t = UTIL.ofp_group_type_from_user(group_type)
    group_type = t if t != group_type else None
    if group_type is None:
        LOG.error('Unknown group type: %s', group.get('type'))

    group_id = UTIL.ofp_group_from_user(group.get('group_id', 0))

    buckets = []
    for bucket in group.get('buckets', []):
        weight = int(bucket.get('weight', 0))
        watch_port = int(bucket.get('watch_port', dp.ofproto.OFPP_ANY))
        watch_group = int(bucket.get('watch_group', dp.ofproto.OFPG_ANY))
        actions = []
        for dic in bucket.get('actions', []):
            action = to_action(dp, dic)
            if action is not None:
                actions.append(action)
        b = dp.ofproto_parser.OFPBucket(
            weight, watch_port, watch_group, actions)
        buckets.append(b)

    group_mod = dp.ofproto_parser.OFPGroupMod(
        dp, cmd, group_type, group_id, buckets)

    dp.send_msg(group_mod)


def mod_port_behavior(dp, port_config):
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    port_no = UTIL.ofp_port_from_user(port_config.get('port_no', 0))
    hw_addr = str(port_config.get('hw_addr'))
    config = int(port_config.get('config', 0))
    mask = int(port_config.get('mask', 0))
    properties = port_config.get('properties')

    prop = []
    for p in properties:
        type_ = UTIL.ofp_port_mod_prop_type_from_user(p['type'])
        length = None
        if type_ == ofp.OFPPDPT_ETHERNET:
            advertise = UTIL.ofp_port_features_from_user(p['advertise'])
            m = parser.OFPPortModPropEthernet(type_, length,
                                              advertise)
        elif type_ == ofp.OFPPDPT_OPTICAL:
            m = parser.OFPPortModPropOptical(type_, length,
                                             p['configure'],
                                             p['freq_lmda'],
                                             p['fl_offset'],
                                             p['grid_span'],
                                             p['tx_pwr'])
        elif type_ == ofp.OFPPDPT_EXPERIMENTER:
            m = parser.OFPPortModPropExperimenter(type_, length,
                                                  p['experimenter'],
                                                  p['exp_type'],
                                                  p['data'])
        else:
            LOG.error('Unknown port desc prop type: %s', type_)
            continue
        prop.append(m)

    port_mod = dp.ofproto_parser.OFPPortMod(
        dp, port_no, hw_addr, config, mask, prop)

    dp.send_msg(port_mod)


def send_experimenter(dp, exp):
    experimenter = exp.get('experimenter', 0)
    exp_type = exp.get('exp_type', 0)
    data_type = exp.get('data_type', 'ascii')
    if data_type != 'ascii' and data_type != 'base64':
        LOG.error('Unknown data type: %s', data_type)
    data = exp.get('data', '')
    if data_type == 'base64':
        data = base64.b64decode(data)

    expmsg = dp.ofproto_parser.OFPExperimenter(
        dp, experimenter, exp_type, data)

    dp.send_msg(expmsg)
