# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
# Copyright (C) 2012 Simon Horman <horms ad verge net au>
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

import struct

from ryu import exception
from ryu.lib import mac
from . import ofproto_parser
from . import ofproto_v1_0
from . import ofproto

import logging
LOG = logging.getLogger('ryu.ofproto.nx_match')


UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
UINT16_MAX = (1 << 16) - 1

FWW_IN_PORT = 1 << 0
FWW_DL_TYPE = 1 << 4
FWW_NW_PROTO = 1 << 5
# No corresponding OFPFW_* bits
FWW_NW_DSCP = 1 << 1
FWW_NW_ECN = 1 << 2
FWW_ARP_SHA = 1 << 3
FWW_ARP_THA = 1 << 6
FWW_NW_TTL = 1 << 8
FWW_ALL = (1 << 13) - 1

# Ethernet types, for set_dl_type()
ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_LACP = 0x8809

IPPROTO_ICMP = 1

IP_ECN_MASK = 0x03
IP_DSCP_MASK = 0xfc

MF_PACK_STRING_BE64 = '!Q'
MF_PACK_STRING_BE32 = '!I'
MF_PACK_STRING_BE16 = '!H'
MF_PACK_STRING_8 = '!B'
MF_PACK_STRING_MAC = '!6s'

_MF_FIELDS = {}


class Flow(object):
    def __init__(self):
        self.in_port = 0
        self.dl_src = mac.DONTCARE
        self.dl_dst = mac.DONTCARE
        self.dl_type = 0
        self.tp_dst = 0
        self.tp_src = 0
        self.nw_tos = 0
        self.vlan_tci = 0
        self.nw_ttl = 0
        self.nw_proto = 0
        self.arp_sha = 0
        self.arp_tha = 0
        self.nw_src = 0
        self.nw_dst = 0
        self.tun_id = 0


class FlowWildcards(object):
    def __init__(self):
        self.dl_src_mask = 0
        self.dl_dst_mask = 0
        self.tp_src_mask = 0
        self.tp_dst_mask = 0
        self.nw_src_mask = 0
        self.nw_dst_mask = 0
        self.tun_id_mask = 0
        self.vlan_tci_mask = 0
        self.wildcards = FWW_ALL


class ClsRule(object):
    def __init__(self):
        self.wc = FlowWildcards()
        self.flow = Flow()

    def set_in_port(self, port):
        self.wc.wildcards &= ~FWW_IN_PORT
        self.flow.in_port = port

    def set_dl_dst(self, dl_dst):
        self.flow.dl_dst = dl_dst

    def set_dl_dst_masked(self, dl_dst, mask):
        self.wc.dl_dst_mask = mask
        # bit-wise and of the corresponding elements of dl_dst and mask
        self.flow.dl_dst = mac.haddr_bitand(dl_dst, mask)

    def set_dl_src(self, dl_src):
        self.flow.dl_src = dl_src

    def set_dl_src_masked(self, dl_src, mask):
        self.wc.dl_src_mask = mask
        self.flow.dl_src = mac.haddr_bitand(dl_src, mask)

    def set_dl_type(self, dl_type):
        self.wc.wildcards &= ~FWW_DL_TYPE
        self.flow.dl_type = dl_type

    def set_dl_tci(self, tci):
        self.set_dl_tci_masked(tci, UINT16_MAX)

    def set_dl_tci_masked(self, tci, mask):
        self.wc.vlan_tci_mask = mask
        self.flow.vlan_tci = tci

    def set_tp_src(self, tp_src):
        self.set_tp_src_masked(tp_src, UINT16_MAX)

    def set_tp_src_masked(self, tp_src, mask):
        self.wc.tp_src_mask = mask
        self.flow.tp_src = tp_src & mask

    def set_tp_dst(self, tp_dst):
        self.set_tp_dst_masked(tp_dst, UINT16_MAX)

    def set_tp_dst_masked(self, tp_dst, mask):
        self.wc.tp_dst_mask = mask
        self.flow.tp_dst = tp_dst & mask

    def set_nw_proto(self, nw_proto):
        self.wc.wildcards &= ~FWW_NW_PROTO
        self.flow.nw_proto = nw_proto

    def set_nw_src(self, nw_src):
        self.set_nw_src_masked(nw_src, UINT32_MAX)

    def set_nw_src_masked(self, nw_src, mask):
        self.flow.nw_src = nw_src
        self.wc.nw_src_mask = mask

    def set_nw_dst(self, nw_dst):
        self.set_nw_dst_masked(nw_dst, UINT32_MAX)

    def set_nw_dst_masked(self, nw_dst, mask):
        self.flow.nw_dst = nw_dst
        self.wc.nw_dst_mask = mask

    def set_nw_dscp(self, nw_dscp):
        self.wc.wildcards &= ~FWW_NW_DSCP
        self.flow.nw_tos &= ~IP_DSCP_MASK
        self.flow.nw_tos |= nw_dscp & IP_DSCP_MASK

    def set_icmp_type(self, icmp_type):
        self.set_tp_src(icmp_type)

    def set_icmp_code(self, icmp_code):
        self.set_tp_dst(icmp_code)

    def set_tun_id(self, tun_id):
        self.set_tun_id_masked(tun_id, UINT64_MAX)

    def set_tun_id_masked(self, tun_id, mask):
        self.wc.tun_id_mask = mask
        self.flow.tun_id = tun_id & mask

    def set_nw_ecn(self, nw_ecn):
        self.wc.wildcards &= ~FWW_NW_ECN
        self.flow.nw_tos &= ~IP_ECN_MASK
        self.flow.nw_tos |= nw_ecn & IP_ECN_MASK

    def set_nw_ttl(self, nw_ttl):
        self.wc.wildcards &= ~FWW_NW_TTL
        self.flow.nw_ttl = nw_ttl

    def set_arp_sha(self, sha):
        self.wc.wildcards &= ~FWW_ARP_SHA
        self.flow.arp_sha = sha

    def set_arp_tha(self, tha):
        self.wc.wildcards &= ~FWW_ARP_THA
        self.flow.arp_tha = tha

    def flow_format(self):
        # Tunnel ID is only supported by NXM
        if self.wc.tun_id_mask != 0:
            return ofproto_v1_0.NXFF_NXM

        # Masking DL_DST is only supported by NXM
        if self.wc.dl_dst_mask:
            return ofproto_v1_0.NXFF_NXM

        # ECN is only supported by NXM
        if not self.wc.wildcards & FWW_NW_ECN:
            return ofproto_v1_0.NXFF_NXM

        return ofproto_v1_0.NXFF_OPENFLOW10

    def match_tuple(self):
        assert self.flow_format() == ofproto_v1_0.NXFF_OPENFLOW10
        wildcards = ofproto.OFPFW_ALL

        if not self.wc.wildcards & FWW_IN_PORT:
            wildcards &= ~ofproto.OFPFW_IN_PORT

        if self.flow.dl_src != mac.DONTCARE:
            wildcards &= ~ofproto.OFPFW_DL_SRC

        if self.wc.dl_dst_mask:
            wildcards &= ~ofproto.OFPFW_DL_DST

        if not self.wc.wildcards & FWW_DL_TYPE:
            wildcards &= ~ofproto.OFPFW_DL_TYPE

        # FIXME: Add support for dl_vlan, fl_vlan_pcp, nw_tos, nw_proto,
        # nw_src, nw_dst, tp_src and dp_dst to self
        return (wildcards, self.flow.in_port, self.flow.dl_src,
                self.flow.dl_dst, 0, 0, self.flow.dl_type,
                self.flow.nw_tos & IP_DSCP_MASK, 0, 0, 0, 0, 0)


def _set_nxm_headers(nxm_headers):
    '''Annotate corresponding NXM header'''
    def _set_nxm_headers_dec(self):
        self.nxm_headers = nxm_headers
        return self
    return _set_nxm_headers_dec


def _register_make(cls):
    '''class decorator to Register mf make'''
    assert cls.nxm_headers is not None
    assert cls.nxm_headers is not []
    for nxm_header in cls.nxm_headers:
        assert nxm_header not in _MF_FIELDS
        _MF_FIELDS[nxm_header] = cls.make
    return cls


def mf_from_nxm_header(nxm_header):
    if nxm_header not in _MF_FIELDS:
        return None
    make = _MF_FIELDS.get(nxm_header)
    assert make is not None
    return make()


class MFField(object):
    def __init__(self, pack_str):
        self.pack_str = pack_str
        self.n_bytes = struct.calcsize(pack_str)
        self.n_bits = self.n_bytes * 8

    def _put(self, buf, offset, value):
        ofproto_parser.msg_pack_into(self.pack_str, buf, offset, value)
        return self.n_bytes

    def putw(self, buf, offset, value, mask):
        len_ = self._put(buf, offset, value)
        return len + self._put(buf, offset + len_, mask)

    def _is_all_ones(self, value):
        return value == (1 << self.n_bits) - 1

    def putm(self, buf, offset, value, mask):
        if mask == 0:
            return 0
        elif self._is_all_ones(mask):
            return self._put(buf, offset, value)
        else:
            return self.putw(buf, offset, value, mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IN_PORT])
class MFInPort(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.in_port)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_DST, ofproto_v1_0.NXM_OF_ETH_DST_W])
class MFEthDst(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        if rule.wc.dl_dst_mask:
            return self.putw(buf, offset, rule.flow.dl_dst,
                             rule.wc.dl_dst_mask)
        else:
            return self._put(buf, offset, rule.flow.dl_dst)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_SRC, ofproto_v1_0.NXM_OF_ETH_SRC_W])
class MFEthSrc(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        if rule.wc.dl_src_mask:
            return self.putw(buf, offset, rule.flow.dl_src,
                             rule.wc.dl_src_mask)
        else:
            return self._put(buf, offset, rule.flow.dl_src)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ETH_TYPE])
class MFEthType(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.dl_type)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_VLAN_TCI,
                   ofproto_v1_0.NXM_OF_VLAN_TCI_W])
class MFVlan(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.vlan_tci,
                         rule.wc.vlan_tci_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_TOS])
class MFIPDSCP(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset,
                         rule.flow.nw_tos & IP_DSCP_MASK)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_TUN_ID, ofproto_v1_0.NXM_NX_TUN_ID_W])
class MFTunId(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE64)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tun_id, rule.wc.tun_id_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_SRC, ofproto_v1_0.NXM_OF_IP_SRC_W])
class MFIPSrc(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.nw_src, rule.wc.nw_src_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_DST, ofproto_v1_0.NXM_OF_IP_DST_W])
class MFIPDst(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE32)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.nw_dst, rule.wc.nw_dst_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IP_ECN])
class MFIPECN(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset,
                         rule.flow.nw_tos & IP_ECN_MASK)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_IP_TTL])
class MFIPTTL(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.nw_ttl)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_IP_PROTO])
class MFIPProto(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.nw_proto)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_TCP_SRC, ofproto_v1_0.NXM_OF_TCP_SRC_W,
                   ofproto_v1_0.NXM_OF_UDP_SRC, ofproto_v1_0.NXM_OF_UDP_SRC_W])
class MFTPSRC(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_BE16)

    def put(self, buf, offset, rule):
        return self.putm(buf, offset, rule.flow.tp_src, rule.wc.tp_src_mask)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ARP_SHA])
class MFArpSha(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.arp_sha)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_NX_ARP_THA])
class MFArpTha(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_MAC)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.arp_tha)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ICMP_TYPE])
class MFICMPType(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.nw_src)


@_register_make
@_set_nxm_headers([ofproto_v1_0.NXM_OF_ICMP_CODE])
class MFICMPCode(MFField):
    @classmethod
    def make(cls):
        return cls(MF_PACK_STRING_8)

    def put(self, buf, offset, rule):
        return self._put(buf, offset, rule.flow.nw_dst)


def serialize_nxm_match(rule, buf, offset):
    old_offset = offset

    if not rule.wc.wildcards & FWW_IN_PORT:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IN_PORT, rule)

    # Ethernet.
    if rule.flow.dl_dst != mac.DONTCARE:
        if rule.wc.dl_dst_mask:
            header = ofproto_v1_0.NXM_OF_ETH_DST_W
        else:
            header = ofproto_v1_0.NXM_OF_ETH_DST
        offset += nxm_put(buf, offset, header, rule)

    if rule.flow.dl_src != mac.DONTCARE:
        if rule.wc.dl_src_mask:
            header = ofproto_v1_0.NXM_OF_ETH_SRC_W
        else:
            header = ofproto_v1_0.NXM_OF_ETH_SRC
        offset += nxm_put(buf, offset, header, rule)

    if not rule.wc.wildcards & FWW_DL_TYPE:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ETH_TYPE, rule)

    # 802.1Q
    if rule.wc.vlan_tci_mask != 0:
        if rule.wc.vlan_tci_mask == UINT16_MAX:
            header = ofproto_v1_0.NXM_OF_VLAN_TCI
        else:
            header = ofproto_v1_0.NXM_OF_VLAN_TCI_W
        offset += nxm_put(buf, offset, header, rule)

    # L3
    if not rule.wc.wildcards & FWW_NW_DSCP:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IP_TOS, rule)
    if not rule.wc.wildcards & FWW_NW_ECN:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_IP_ECN, rule)
    if not rule.wc.wildcards & FWW_NW_TTL:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_IP_TTL, rule)
    if not rule.wc.wildcards & FWW_NW_PROTO:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_IP_PROTO, rule)

    if not rule.wc.wildcards & FWW_NW_PROTO and (rule.flow.nw_proto
                                                 == IPPROTO_ICMP):
        if rule.wc.tp_src_mask != 0:
            offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ICMP_TYPE, rule)
        elif rule.wc.tp_dst_mask != 0:
            offset += nxm_put(buf, offset, ofproto_v1_0.NXM_OF_ICMP_CODE, rule)
        else:
            pass

    if rule.flow.tp_src != 0:
        if rule.flow.nw_proto == 6:
            if rule.wc.tp_src_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_TCP_SRC
            else:
                header = ofproto_v1_0.NXM_OF_TCP_SRC_W
        elif rule.flow.nw_proto == 17:
            if rule.wc.tp_src_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_UDP_SRC
            else:
                header = ofproto_v1_0.NXM_OF_UDP_SRC_W
        else:
            header = 0
        if header != 0:
            offset += nxm_put(buf, offset, header, rule)

    if rule.flow.tp_dst != 0:
        if rule.flow.nw_proto == 6:
            if rule.wc.tp_dst_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_TCP_DST
            else:
                header = ofproto_v1_0.NXM_OF_TCP_DST_W
        elif rule.flow.nw_proto == 17:
            if rule.wc.tp_dst_mask == UINT16_MAX:
                header = ofproto_v1_0.NXM_OF_UDP_DST
            else:
                header = ofproto_v1_0.NXM_OF_UDP_DST_W
        else:
            header = 0
        if header != 0:
            offset += nxm_put(buf, offset, header, rule)

    # IP Source and Destination
    if rule.flow.nw_src != 0:
        if rule.wc.nw_src_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_OF_IP_SRC
        else:
            header = ofproto_v1_0.NXM_OF_IP_SRC_W
        offset += nxm_put(buf, offset, header, rule)

    if rule.flow.nw_dst != 0:
        if rule.wc.nw_dst_mask == UINT32_MAX:
            header = ofproto_v1_0.NXM_OF_IP_DST
        else:
            header = ofproto_v1_0.NXM_OF_IP_DST_W
        offset += nxm_put(buf, offset, header, rule)

    # XXX: IPv6
    # ARP
    if not rule.wc.wildcards & FWW_ARP_SHA:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_ARP_SHA, rule)
    if not rule.wc.wildcards & FWW_ARP_THA:
        offset += nxm_put(buf, offset, ofproto_v1_0.NXM_NX_ARP_THA, rule)

    # Tunnel Id
    if rule.wc.tun_id_mask != 0:
        if rule.wc.tun_id_mask == UINT64_MAX:
            header = ofproto_v1_0.NXM_NX_TUN_ID
        else:
            header = ofproto_v1_0.NXM_NX_TUN_ID_W
        offset += nxm_put(buf, offset, header, rule)

    # XXX: Cookie

    # Pad
    pad_len = round_up(offset) - offset
    ofproto_parser.msg_pack_into("%dx" % pad_len, buf, offset)

    # The returned length, the match_len, does not include the pad
    return offset - old_offset


def nxm_put(buf, offset, header, rule):
    nxm = NXMatch(header)
    len_ = nxm.put_header(buf, offset)
    mf = mf_from_nxm_header(nxm.header)
    return len_ + mf.put(buf, offset + len, rule)


def round_up(length):
    return (length + 7) / 8 * 8  # Round up to a multiple of 8


class NXMatch(object):
    def __init__(self, header):
        self.header = header

    @classmethod
    def parser(cls, buf, offset, match_len):
        if match_len < 4:
            raise exception.OFPMalformedMessage
        (header,) = struct.unpack_from(ofproto_v1_0.NXM_HEADER_PACK_STRING,
                                       buf, offset)
        instance = cls(header)
        payload_len = instance.length()
        if payload_len == 0 or match_len < payload_len + 4:
            raise exception.OFPMalformedMessage
        return instance

    def vendor(self):
        return self.header >> 16

    def field(self):
        return (self.header >> 9) % 0x7f

    def type(self):
        return (self.header >> 9) % 0x7fffff

    def hasmask(self):
        return (self.header >> 8) & 1

    def length(self):
        return self.header & 0xff

    def show(self):
        return ('%08x (vendor=%x, field=%x, hasmask=%x len=%x)' %
                (self.header, self.vendor(), self.field(),
                 self.hasmask(), self.length()))

    def put_header(self, buf, offset):
        ofproto_parser.msg_pack_into(ofproto_v1_0.NXM_HEADER_PACK_STRING,
                                     buf, offset, self.header)
        return struct.calcsize(ofproto_v1_0.NXM_HEADER_PACK_STRING)
