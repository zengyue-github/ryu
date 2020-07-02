# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# client for ryu.app.ofctl.service

from ryu.base import app_manager
import event


def get_datapath(app, dpid):
    """
    Get datapath object by dpid.
    Returns None on error.
    """
    assert isinstance(dpid, (int, long))
    return app.send_request(event.GetDatapathRequest(dpid=dpid))()


def send_msg(app, msg):
    """
    Send an openflow message.
    """
    return app.send_request(event.SendMsgRequest(msg=msg))()


app_manager.require_app('ryu.app.ofctl.service')
