# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import unittest
from nose.tools import eq_
from nose.tools import ok_

from ryu.lib.packet import bgp


class Test_bgp(unittest.TestCase):
    """ Test case for ryu.lib.packet.bgp
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_open1(self):
        msg = bgp.BGPOpen(my_as=30000, bgp_identifier='192.0.2.1')
        binmsg = msg.serialize()
        msg2, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 29)
        eq_(rest, '')

    def test_open2(self):
        opt_param = [bgp.BGPOptParamCapability(cap_code=200, cap_value='hoge'),
                     bgp.BGPOptParamUnknown(type_=99, value='fuga')]
        msg = bgp.BGPOpen(my_as=30000, bgp_identifier='192.0.2.2',
                          opt_param=opt_param)
        binmsg = msg.serialize()
        msg2, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        ok_(len(msg) > 29)
        eq_(rest, '')

    def test_update1(self):
        msg = bgp.BGPUpdate()
        binmsg = msg.serialize()
        msg2, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 23)
        eq_(rest, '')

    def test_update2(self):
        withdrawn_routes = [bgp.BGPWithdrawnRoute(length=0,
                                                  ip_addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=1,
                                                  ip_addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=3,
                                                  ip_addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=7,
                                                  ip_addr='192.0.2.13'),
                            bgp.BGPWithdrawnRoute(length=32,
                                                  ip_addr='192.0.2.13')]
        path_attributes = [
            bgp.BGPPathAttributeOrigin(value=1),
            bgp.BGPPathAttributeAsPath(value=[[1000], set([1001, 1002]),
                                              [1003, 1004]]),
            bgp.BGPPathAttributeNextHop(value='192.0.2.199'),
            bgp.BGPPathAttributeMultiExitDisc(value=2000000000),
            bgp.BGPPathAttributeLocalPref(value=1000000000),
            bgp.BGPPathAttributeAtomicAggregate(),
            bgp.BGPPathAttributeAggregator(as_number=40000,
                                           ip_addr='192.0.2.99'),
            bgp.BGPPathAttributeAs4Path(value=[[1000000], set([1000001, 1002]),
                                               [1003, 1000004]]),
            bgp.BGPPathAttributeAs4Aggregator(as_number=100040000,
                                              ip_addr='192.0.2.99'),
            bgp.BGPPathAttributeUnknown(flags=0, type_=100, value=300*'bar')
        ]
        nlri = [
            bgp.BGPNLRI(length=24, ip_addr='203.0.113.1'),
            bgp.BGPNLRI(length=16, ip_addr='203.0.113.0')
        ]
        msg = bgp.BGPUpdate(withdrawn_routes=withdrawn_routes,
                            path_attributes=path_attributes,
                            nlri=nlri)
        binmsg = msg.serialize()
        msg2, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        ok_(len(msg) > 23)
        eq_(rest, '')

    def test_keepalive(self):
        msg = bgp.BGPKeepAlive()
        binmsg = msg.serialize()
        msg2, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 19)
        eq_(rest, '')

    def test_notification(self):
        data = "hoge"
        msg = bgp.BGPNotification(error_code=1, error_subcode=2, data=data)
        binmsg = msg.serialize()
        msg2, rest = bgp.BGPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(len(msg), 21 + len(data))
        eq_(rest, '')

    def test_stream_parser(self):
        msgs = [
            bgp.BGPNotification(error_code=1, error_subcode=2, data="foo"),
            bgp.BGPNotification(error_code=3, error_subcode=4, data="bar"),
            bgp.BGPNotification(error_code=5, error_subcode=6, data="baz"),
        ]
        binmsgs = ''.join([bytes(msg.serialize()) for msg in msgs])
        sp = bgp.StreamParser()
        results = []
        for b in binmsgs:
            for m in sp.parse(b):
                results.append(m)
        eq_(str(results), str(msgs))

    def test_parser(self):
        files = [
            'bgp4-open',
            # commented out because
            # 1. we don't support 32 bit AS numbers in AS_PATH
            # 2. quagga always uses EXTENDED for AS_PATH
            # 'bgp4-update',
            'bgp4-keepalive',
        ]
        dir = '../packet_data/bgp4/'

        for f in files:
            print 'testing', f
            binmsg = open(dir + f).read()
            msg, rest = bgp.BGPMessage.parser(binmsg)
            binmsg2 = msg.serialize()
            eq_(binmsg, binmsg2)
            eq_(rest, '')
