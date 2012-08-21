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

from . import ethernet


class Packet(object):
    def __init__(self, data=None):
        super(Packet, self).__init__()
        self.data = data
        self.protocols = []
        self.parsed_bytes = 0
        if self.data:
            # Do we need to handle non ethernet?
            self.parser(ethernet.ethernet)

    def parser(self, cls):
        while cls:
            proto, cls = cls.parser(self.data[self.parsed_bytes:])
            if proto:
                self.parsed_bytes += proto.length
                self.protocols.append(proto)

    def serialize(self):
        offset = 0
        self.data = bytearray()
        for p in self.protocols:
            p.serialize(self.data, offset)
            offset += p.length

    def add_protocol(self, proto):
        self.protocols.append(proto)

    def find_protocol(self, name):
        for p in self.protocols:
            if p.__class__.__name__ == name:
                return p
