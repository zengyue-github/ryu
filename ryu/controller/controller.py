# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

import contextlib
import gflags
import logging
import gevent
import traceback
import random
import greenlet
from gevent.server import StreamServer
from gevent.queue import Queue

from ryu.ofproto import ofproto
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_0_parser
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import nx_match

from ryu.controller import dispatcher
from ryu.controller import handler
from ryu.controller import ofp_event

LOG = logging.getLogger('ryu.controller.controller')

FLAGS = gflags.FLAGS
gflags.DEFINE_string('ofp_listen_host', '', 'openflow listen host')
gflags.DEFINE_integer('ofp_tcp_listen_port', ofproto.OFP_TCP_PORT,
                      'openflow tcp listen port')


class OpenFlowController(object):
    def __init__(self):
        super(OpenFlowController, self).__init__()

    # entry point
    def __call__(self):
        #LOG.debug('call')
        self.server_loop()

    def server_loop(self):
        server = StreamServer((FLAGS.ofp_listen_host,
                               FLAGS.ofp_tcp_listen_port),
                              datapath_connection_factory)
        #LOG.debug('loop')
        server.serve_forever()


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        except greenlet.GreenletExit:
            pass
        except:
            traceback.print_stack()
            raise
        finally:
            self.is_active = False
    return deactivate


class Datapath(object):
    supported_ofp_version = {
        ofproto_v1_0.OFP_VERSION: (ofproto_v1_0,
                                   ofproto_v1_0_parser),
        ofproto_v1_2.OFP_VERSION: (ofproto_v1_2,
                                   ofproto_v1_2_parser),
        }

    def __init__(self, socket, address):
        super(Datapath, self).__init__()

        self.socket = socket
        self.address = address
        self.is_active = True

        # The limit is arbitrary. We need to limit queue size to
        # prevent it from eating memory up
        self.send_q = Queue(16)

        # circular reference self.ev_q.aux == self
        self.ev_q = dispatcher.EventQueue(handler.QUEUE_NAME_OFP_MSG,
                                          handler.HANDSHAKE_DISPATCHER,
                                          self)

        self.set_version(max(self.supported_ofp_version))
        self.xid = random.randint(0, self.ofproto.MAX_XID)
        self.id = None  # datapath_id is unknown yet
        self.ports = None
        self.flow_format = ofproto_v1_0.NXFF_OPENFLOW10

    def close(self):
        """
        Call this before discarding this datapath object
        The circular refernce as self.ev_q.aux == self must be broken.
        """
        # tell this datapath is dead
        self.ev_q.set_dispatcher(handler.DEAD_DISPATCHER)
        self.ev_q.close()

    def set_version(self, version):
        assert version in self.supported_ofp_version
        self.ofproto, self.ofproto_parser = self.supported_ofp_version[version]

    # Low level socket handling layer
    @_deactivate
    def _recv_loop(self):
        buf = bytearray()
        required_len = ofproto.OFP_HEADER_SIZE

        count = 0
        while self.is_active:
            ret = self.socket.recv(required_len)
            if len(ret) == 0:
                self.is_active = False
                break
            buf += ret
            while len(buf) >= required_len:
                (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
                required_len = msg_len
                if len(buf) < required_len:
                    break

                msg = ofproto_parser.msg(self,
                                         version, msg_type, msg_len, xid, buf)
                #LOG.debug('queue msg %s cls %s', msg, msg.__class__)
                self.ev_q.queue(ofp_event.ofp_msg_to_ev(msg))

                buf = buf[required_len:]
                required_len = ofproto.OFP_HEADER_SIZE

                # We need to schedule other greenlets. Otherwise, ryu
                # can't accept new switches or handle the existing
                # switches. The limit is arbitrary. We need the better
                # approach in the future.
                count += 1
                if count > 2048:
                    count = 0
                    gevent.sleep(0)

    @_deactivate
    def _send_loop(self):
        while self.is_active:
            buf = self.send_q.get()
            self.socket.sendall(buf)

    def send(self, buf):
        self.send_q.put(buf)

    def set_xid(self, msg):
        self.xid += 1
        self.xid &= self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg):
        assert isinstance(msg, self.ofproto_parser.MsgBase)
        if msg.xid is None:
            self.set_xid(msg)
        msg.serialize()
        # LOG.debug('send_msg %s', msg)
        self.send(msg.buf)

    def serve(self):
        send_thr = gevent.spawn(self._send_loop)

        # send hello message immediately
        hello = self.ofproto_parser.OFPHello(self)
        self.send_msg(hello)

        try:
            self._recv_loop()
        finally:
            gevent.kill(send_thr)
            gevent.joinall([send_thr])

    def send_ev(self, ev):
        #LOG.debug('send_ev %s', ev)
        self.ev_q.queue(ev)

    #
    # Utility methods for convenience
    #
    def send_packet_out(self, buffer_id=0xffffffff, in_port=None,
                        actions=None, data=None):
        if in_port is None:
            in_port = self.ofproto.OFPP_NONE
        packet_out = self.ofproto_parser.OFPPacketOut(
            self, buffer_id, in_port, actions, data)
        self.send_msg(packet_out)

    def send_flow_mod(self, rule, cookie, command, idle_timeout, hard_timeout,
                      priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):
        if priority is None:
            priority = self.ofproto.OFP_DEFAULT_PRIORITY
        if out_port is None:
            out_port = self.ofproto.OFPP_NONE
        flow_format = rule.flow_format()
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format < flow_format:
            self.send_nxt_set_flow_format(flow_format)
        if flow_format == ofproto_v1_0.NXFF_OPENFLOW10:
            match_tuple = rule.match_tuple()
            match = self.ofproto_parser.OFPMatch(*match_tuple)
            flow_mod = self.ofproto_parser.OFPFlowMod(
                self, match, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, actions)
        else:
            flow_mod = self.ofproto_parser.NXTFlowMod(
                self, cookie, command, idle_timeout, hard_timeout,
                priority, buffer_id, out_port, flags, rule, actions)
        self.send_msg(flow_mod)

    def send_flow_del(self, rule, cookie, out_port=None):
        self.send_flow_mod(rule=rule, cookie=cookie,
                           command=self.ofproto.OFPFC_DELETE,
                           idle_timeout=0, hard_timeout=0, priority=0,
                           out_port=out_port)

    def send_delete_all_flows(self):
        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=self.ofproto.OFPFC_DELETE,
            idle_timeout=0, hard_timeout=0, priority=0, buffer_id=0,
            out_port=self.ofproto.OFPP_NONE, flags=0, actions=None)

    def send_barrier(self):
        barrier_request = self.ofproto_parser.OFPBarrierRequest(self)
        self.send_msg(barrier_request)

    def send_nxt_set_flow_format(self, flow_format):
        assert (flow_format == ofproto_v1_0.NXFF_OPENFLOW10 or
                flow_format == ofproto_v1_0.NXFF_NXM)
        if self.flow_format == flow_format:
            # Nothing to do
            return
        self.flow_format = flow_format
        set_format = self.ofproto_parser.NXTSetFlowFormat(self, flow_format)
        # FIXME: If NXT_SET_FLOW_FORMAT or NXFF_NXM is not supported by
        # the switch then an error message will be received. It may be
        # handled by setting self.flow_format to
        # ofproto_v1_0.NXFF_OPENFLOW10 but currently isn't.
        self.send_msg(set_format)
        self.send_barrier()


def datapath_connection_factory(socket, address):
    LOG.debug('connected socket:%s address:%s', socket, address)
    with contextlib.closing(Datapath(socket, address)) as datapath:
        try:
            datapath.serve()
        except:
            # Something went wrong.
            # Especially malicious switch can send malformed packet,
            # the parser raise exception.
            # Can we do anything more graceful?
            LOG.error("Error in the datapath %s from %s",
                      datapath.id, address)
            raise
