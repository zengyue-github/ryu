# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

from . import packet_base
from . import packet_utils
from . import icmp
from . import udp
from . import tcp
from ryu.ofproto import inet


IPV4_ADDRESS_PACK_STR = '!I'
IPV4_ADDRESS_LEN = struct.calcsize(IPV4_ADDRESS_PACK_STR)
IPV4_PSEUDO_HEADER_PACK_STR = '!II2xHH'


class ipv4(packet_base.PacketBase):
    """IPv4 (RFC 791) header encoder/decoder class.

    NOTE: When decoding, this implementation tries to decode the upper
    layer protocol even for a fragmented datagram.  It isn't likely
    what a user would want.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    version        Version
    header_length  IHL
    tos            Type of Service
    total_length   Total Length \
                   (0 means automatically-calculate when encoding)
    identification Identification
    flags          Flags
    offset         Fragment Offset
    ttl            Time to Live
    proto          Protocol
    csum           Header Checksum \
                   (Ignored and automatically-calculated when encoding)
    src            Source Address
    dst            Destination Address
    option         A bytearray which contains the entire Options, or None for \
                   no Options
    ============== ====================
    """

    _PACK_STR = '!BBHHHBBHII'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, version, header_length, tos, total_length,
                 identification, flags, offset, ttl, proto, csum,
                 src, dst, option=None):
        super(ipv4, self).__init__()
        self.version = version
        self.header_length = header_length
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.proto = proto
        self.csum = csum
        self.src = src
        self.dst = dst
        self.length = header_length * 4
        self.option = option

    @classmethod
    def parser(cls, buf):
        (version, tos, total_length, identification, flags, ttl, proto, csum,
         src, dst) = struct.unpack_from(cls._PACK_STR, buf)
        header_length = version & 0xf
        version = version >> 4
        offset = flags & ((1 << 13) - 1)
        flags = flags >> 13
        msg = cls(version, header_length, tos, total_length, identification,
                  flags, offset, ttl, proto, csum, src, dst)

        if msg.length > ipv4._MIN_LEN:
            msg.option = buf[ipv4._MIN_LEN:msg.length]

        return msg, ipv4.get_packet_type(proto)

    def serialize(self, payload, prev):
        hdr = bytearray(self.header_length * 4)
        version = self.version << 4 | self.header_length
        flags = self.flags << 13 | self.offset
        if self.total_length == 0:
            self.total_length = self.header_length * 4 + len(payload)
        struct.pack_into(ipv4._PACK_STR, hdr, 0, version, self.tos,
                         self.total_length, self.identification, flags,
                         self.ttl, self.proto, 0, self.src, self.dst)

        if self.option:
            assert (self.length - ipv4._MIN_LEN) >= len(self.option)
            hdr[ipv4._MIN_LEN:ipv4._MIN_LEN + len(self.option)] = self.option

        self.csum = packet_utils.checksum(hdr)
        struct.pack_into('!H', hdr, 10, self.csum)
        return hdr

ipv4.register_packet_type(icmp.icmp, inet.IPPROTO_ICMP)
ipv4.register_packet_type(tcp.tcp, inet.IPPROTO_TCP)
ipv4.register_packet_type(udp.udp, inet.IPPROTO_UDP)
