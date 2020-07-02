# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

"""
 Running or runtime configuration related to bgp peers/neighbors.
"""
from abc import abstractmethod
import logging

from ryu.services.protocols.bgp.base import OrderedDict
from ryu.services.protocols.bgp.rtconf.base import ADVERTISE_PEER_AS
from ryu.services.protocols.bgp.rtconf.base import BaseConf
from ryu.services.protocols.bgp.rtconf.base import BaseConfListener
from ryu.services.protocols.bgp.rtconf.base import CAP_ENHANCED_REFRESH
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_IPV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV4
from ryu.services.protocols.bgp.rtconf.base import CAP_MBGP_VPNV6
from ryu.services.protocols.bgp.rtconf.base import CAP_REFRESH
from ryu.services.protocols.bgp.rtconf.base import CAP_RTC
from ryu.services.protocols.bgp.rtconf.base import compute_optional_conf
from ryu.services.protocols.bgp.rtconf.base import ConfigTypeError
from ryu.services.protocols.bgp.rtconf.base import ConfigValueError
from ryu.services.protocols.bgp.rtconf.base import ConfWithId
from ryu.services.protocols.bgp.rtconf.base import ConfWithIdListener
from ryu.services.protocols.bgp.rtconf.base import ConfWithStats
from ryu.services.protocols.bgp.rtconf.base import ConfWithStatsListener
from ryu.services.protocols.bgp.rtconf.base import HOLD_TIME
from ryu.services.protocols.bgp.rtconf.base import MAX_PREFIXES
from ryu.services.protocols.bgp.rtconf.base import MULTI_EXIT_DISC
from ryu.services.protocols.bgp.rtconf.base import RTC_AS
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.bgp.rtconf.base import SITE_OF_ORIGINS
from ryu.services.protocols.bgp.rtconf.base import validate
from ryu.services.protocols.bgp.rtconf.base import validate_med
from ryu.services.protocols.bgp.rtconf.base import validate_soo_list

from ryu.services.protocols.bgp.protocols.bgp.capabilities import \
    EnhancedRouteRefreshCap
from ryu.services.protocols.bgp.protocols.bgp.capabilities import \
    MultiprotocolExtentionCap
from ryu.services.protocols.bgp.protocols.bgp.capabilities import \
    RouteRefreshCap
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_IPv4_UC
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_IPv4_VPN
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_IPv6_VPN
from ryu.services.protocols.bgp.protocols.bgp.nlri import RF_RTC_UC
from ryu.services.protocols.bgp.utils.validation import is_valid_ipv4
from ryu.services.protocols.bgp.utils.validation import is_valid_old_asn

LOG = logging.getLogger('bgpspeaker.rtconf.neighbor')

# Various neighbor settings.
REMOTE_AS = 'remote_as'
IP_ADDRESS = 'ip_address'
ENABLED = 'enabled'
CHANGES = 'changes'
LOCAL_ADDRESS = 'local_address'
LOCAL_PORT = 'local_port'

# Default value constants.
DEFAULT_CAP_GR_NULL = True
DEFAULT_CAP_REFRESH = True
DEFAULT_CAP_ENHANCED_REFRESH = False
DEFAULT_CAP_MBGP_IPV4 = True
DEFAULT_CAP_MBGP_VPNV4 = False
DEFAULT_CAP_MBGP_VPNV6 = False
DEFAULT_HOLD_TIME = 40
DEFAULT_ENABLED = True
DEFAULT_CAP_RTC = False

# Default value for *MAX_PREFIXES* setting is set to 0.
DEFAULT_MAX_PREFIXES = 0
DEFAULT_ADVERTISE_PEER_AS = False


@validate(name=ENABLED)
def validate_enabled(enabled):
    if not isinstance(enabled, bool):
        raise ConfigValueError(desc='Enable property is not an instance of '
                               'boolean')
    return enabled


@validate(name=CHANGES)
def validate_changes(changes):
    for k, v in changes.iteritems():
        if k not in (MULTI_EXIT_DISC, ENABLED):
            raise ConfigValueError(desc="Unknown field to change: %s" % k)

        if k == MULTI_EXIT_DISC:
            validate_med(v)
        elif k == ENABLED:
            validate_enabled(v)
    return changes


@validate(name=IP_ADDRESS)
def validate_ip_address(ip_address):
    if not is_valid_ipv4(ip_address):
        raise ConfigValueError(desc='Invalid neighbor ip_address: %s' %
                               ip_address)
    return ip_address


@validate(name=LOCAL_ADDRESS)
def validate_local_address(ip_address):
    if not is_valid_ipv4(ip_address):
        raise ConfigValueError(desc='Invalid local ip_address: %s' %
                               ip_address)
    return ip_address


@validate(name=LOCAL_PORT)
def validate_local_port(port):
    if not isinstance(port, (int, long)):
        raise ConfigTypeError(desc='Invalid local port: %s' % port)
    if port < 1025 or port > 65535:
        raise ConfigValueError(desc='Invalid local port value: %s, has to be'
                               ' between 1025 and 65535' % port)
    return port


@validate(name=REMOTE_AS)
def validate_remote_as(asn):
    if not is_valid_old_asn(asn):
        raise ConfigValueError(desc='Invalid remote as value %s' % asn)
    return asn


class NeighborConf(ConfWithId, ConfWithStats):
    """Class that encapsulates one neighbors' configuration."""

    UPDATE_ENABLED_EVT = 'update_enabled_evt'
    UPDATE_MED_EVT = 'update_med_evt'

    VALID_EVT = frozenset([UPDATE_ENABLED_EVT, UPDATE_MED_EVT])
    REQUIRED_SETTINGS = frozenset([REMOTE_AS, IP_ADDRESS, LOCAL_ADDRESS,
                                   LOCAL_PORT])
    OPTIONAL_SETTINGS = frozenset([CAP_REFRESH,
                                   CAP_ENHANCED_REFRESH, CAP_MBGP_VPNV4,
                                   CAP_MBGP_IPV4, CAP_MBGP_VPNV6,
                                   CAP_RTC, RTC_AS, HOLD_TIME,
                                   ENABLED, MULTI_EXIT_DISC, MAX_PREFIXES,
                                   ADVERTISE_PEER_AS, SITE_OF_ORIGINS])

    def __init__(self, **kwargs):
        super(NeighborConf, self).__init__(**kwargs)

    def _init_opt_settings(self, **kwargs):
        self._settings[CAP_REFRESH] = compute_optional_conf(
            CAP_REFRESH, DEFAULT_CAP_REFRESH, **kwargs)
        self._settings[CAP_ENHANCED_REFRESH] = compute_optional_conf(
            CAP_ENHANCED_REFRESH, DEFAULT_CAP_ENHANCED_REFRESH, **kwargs)
        self._settings[CAP_MBGP_IPV4] = compute_optional_conf(
            CAP_MBGP_IPV4, DEFAULT_CAP_MBGP_IPV4, **kwargs)
        self._settings[CAP_MBGP_VPNV4] = compute_optional_conf(
            CAP_MBGP_VPNV4, DEFAULT_CAP_MBGP_VPNV4, **kwargs)
        self._settings[CAP_MBGP_VPNV6] = compute_optional_conf(
            CAP_MBGP_VPNV6, DEFAULT_CAP_MBGP_VPNV6, **kwargs)
        self._settings[HOLD_TIME] = compute_optional_conf(
            HOLD_TIME, DEFAULT_HOLD_TIME, **kwargs)
        self._settings[ENABLED] = compute_optional_conf(
            ENABLED, DEFAULT_ENABLED, **kwargs)
        self._settings[MAX_PREFIXES] = compute_optional_conf(
            MAX_PREFIXES, DEFAULT_MAX_PREFIXES, **kwargs)
        self._settings[ADVERTISE_PEER_AS] = compute_optional_conf(
            ADVERTISE_PEER_AS, DEFAULT_ADVERTISE_PEER_AS, **kwargs)

        # We do not have valid default MED value.
        # If no MED attribute is provided then we do not have to use MED.
        # If MED attribute is provided we have to validate it and use it.
        med = kwargs.pop(MULTI_EXIT_DISC, None)
        if med and validate_med(med):
            self._settings[MULTI_EXIT_DISC] = med

        # We do not have valid default SOO value.
        # If no SOO attribute is provided then we do not have to use SOO.
        # If SOO attribute is provided we have to validate it and use it.
        soos = kwargs.pop(SITE_OF_ORIGINS, None)
        if soos and validate_soo_list(soos):
            self._settings[SITE_OF_ORIGINS] = soos

        # RTC configurations.
        self._settings[CAP_RTC] = \
            compute_optional_conf(CAP_RTC, DEFAULT_CAP_RTC, **kwargs)
        # Default RTC_AS is local (router) AS.
        from ryu.services.protocols.bgp.core_manager import \
            CORE_MANAGER
        default_rt_as = CORE_MANAGER.common_conf.local_as
        self._settings[RTC_AS] = \
            compute_optional_conf(RTC_AS, default_rt_as, **kwargs)

        # Since ConfWithId' default values use str(self) and repr(self), we
        # call super method after we have initialized other settings.
        super(NeighborConf, self)._init_opt_settings(**kwargs)

    @classmethod
    def get_opt_settings(cls):
        self_confs = super(NeighborConf, cls).get_opt_settings()
        self_confs.update(NeighborConf.OPTIONAL_SETTINGS)
        return self_confs

    @classmethod
    def get_req_settings(cls):
        self_confs = super(NeighborConf, cls).get_req_settings()
        self_confs.update(NeighborConf.REQUIRED_SETTINGS)
        return self_confs

    @classmethod
    def get_valid_evts(cls):
        self_valid_evts = super(NeighborConf, cls).get_valid_evts()
        self_valid_evts.update(NeighborConf.VALID_EVT)
        return self_valid_evts

    #==========================================================================
    # Required attributes
    #==========================================================================

    @property
    def remote_as(self):
        return self._settings[REMOTE_AS]

    @property
    def ip_address(self):
        return self._settings[IP_ADDRESS]

    @property
    def host_bind_ip(self):
        return self._settings[LOCAL_ADDRESS]

    @property
    def host_bind_port(self):
        return self._settings[LOCAL_PORT]

    #==========================================================================
    # Optional attributes with valid defaults.
    #==========================================================================

    @property
    def hold_time(self):
        return self._settings[HOLD_TIME]

    @property
    def cap_refresh(self):
        return self._settings[CAP_REFRESH]

    @property
    def cap_enhanced_refresh(self):
        return self._settings[CAP_ENHANCED_REFRESH]

    @property
    def cap_mbgp_ipv4(self):
        return self._settings[CAP_MBGP_IPV4]

    @property
    def cap_mbgp_vpnv4(self):
        return self._settings[CAP_MBGP_VPNV4]

    @property
    def cap_mbgp_vpnv6(self):
        return self._settings[CAP_MBGP_VPNV6]

    @property
    def cap_rtc(self):
        return self._settings[CAP_RTC]

    @property
    def enabled(self):
        return self._settings[ENABLED]

    @enabled.setter
    def enabled(self, enable):
        # Update enabled flag and notify listeners.
        if self._settings[ENABLED] != enable:
            self._settings[ENABLED] = enable
            self._notify_listeners(NeighborConf.UPDATE_ENABLED_EVT,
                                   enable)

    #==========================================================================
    # Optional attributes with no valid defaults.
    #==========================================================================

    @property
    def multi_exit_disc(self):
        # This property does not have any valid default. Hence if not set we
        # return None.
        return self._settings.get(MULTI_EXIT_DISC)

    @multi_exit_disc.setter
    def multi_exit_disc(self, value):
        if self._settings.get(MULTI_EXIT_DISC) != value:
            self._settings[MULTI_EXIT_DISC] = value
            self._notify_listeners(NeighborConf.UPDATE_MED_EVT, value)

    @property
    def soo_list(self):
        soos = self._settings.get(SITE_OF_ORIGINS)
        if soos:
            soos = list(soos)
        else:
            soos = []
        return soos

    @property
    def rtc_as(self):
        return self._settings[RTC_AS]

    def exceeds_max_prefix_allowed(self, prefix_count):
        allowed_max = self._settings[MAX_PREFIXES]
        does_exceed = False
        # Check if allowed max. is unlimited.
        if allowed_max != 0:
            # If max. prefix is limited, check if given exceeds this limit.
            if prefix_count > allowed_max:
                does_exceed = True

        return does_exceed

    def get_configured_capabilites(self):
        """Returns configured capabilities."""

        capabilities = OrderedDict()
        mbgp_caps = []
        if self.cap_mbgp_ipv4:
            mbgp_caps.append(MultiprotocolExtentionCap(RF_IPv4_UC))

        if self.cap_mbgp_vpnv4:
            mbgp_caps.append(MultiprotocolExtentionCap(RF_IPv4_VPN))

        if self.cap_mbgp_vpnv6:
            mbgp_caps.append(MultiprotocolExtentionCap(RF_IPv6_VPN))

        if self.cap_rtc:
            mbgp_caps.append(MultiprotocolExtentionCap(RF_RTC_UC))

        if mbgp_caps:
            capabilities[MultiprotocolExtentionCap.CODE] = mbgp_caps

        if self.cap_refresh:
            capabilities[RouteRefreshCap.CODE] = [
                RouteRefreshCap.get_singleton()]

        if self.cap_enhanced_refresh:
            capabilities[EnhancedRouteRefreshCap.CODE] = [
                EnhancedRouteRefreshCap.get_singleton()]

        return capabilities

    def __repr__(self):
        return '<%s(%r, %r, %r)>' % (self.__class__.__name__,
                                     self.remote_as,
                                     self.ip_address,
                                     self.enabled)

    def __str__(self):
        return 'Neighbor: %s' % (self.ip_address)


class NeighborsConf(BaseConf):
    """Container of all neighbor configurations."""

    ADD_NEIGH_CONF_EVT = 'add_neigh_conf_evt'
    REMOVE_NEIGH_CONF_EVT = 'remove_neigh_conf_evt'

    VALID_EVT = frozenset([ADD_NEIGH_CONF_EVT, REMOVE_NEIGH_CONF_EVT])

    def __init__(self):
        super(NeighborsConf, self).__init__()
        self._neighbors = {}

    def _init_opt_settings(self, **kwargs):
        pass

    def update(self, **kwargs):
        raise NotImplementedError('Use either add/remove_neighbor_conf'
                                  ' methods instead.')

    @property
    def rtc_as_set(self):
        """Returns current RTC AS configured for current neighbors.
        """
        rtc_as_set = set()
        for neigh in self._neighbors.itervalues():
            rtc_as_set.add(neigh.rtc_as)
        return rtc_as_set

    @classmethod
    def get_valid_evts(cls):
        self_valid_evts = super(NeighborsConf, cls).get_valid_evts()
        self_valid_evts.update(NeighborsConf.VALID_EVT)
        return self_valid_evts

    def add_neighbor_conf(self, neigh_conf):
        # Check if we already know this neighbor
        if neigh_conf.ip_address in self._neighbors.keys():
            message = 'Neighbor with given ip address already exists'
            raise RuntimeConfigError(desc=message)

        # Check if this neighbor's host address overlaps with other neighbors
        for nconf in self._neighbors.itervalues():
            if ((neigh_conf.host_bind_ip, neigh_conf.host_bind_port) ==
                    (nconf.host_bind_ip, nconf.host_bind_port)):
                raise RuntimeConfigError(desc='Given host_bind_ip and '
                                         'host_bind_port already taken')

        # Add this neighbor to known configured neighbors and generate update
        # event
        self._neighbors[neigh_conf.ip_address] = neigh_conf
        self._notify_listeners(NeighborsConf.ADD_NEIGH_CONF_EVT, neigh_conf)

    def remove_neighbor_conf(self, neigh_ip_address):
        neigh_conf = self._neighbors.pop(neigh_ip_address, None)
        if not neigh_conf:
            raise RuntimeConfigError(desc='Tried to remove a neighbor that '
                                     'does not exists')
        else:
            self._notify_listeners(NeighborsConf.REMOVE_NEIGH_CONF_EVT,
                                   neigh_conf)
        return neigh_conf

    def get_neighbor_conf(self, neigh_ip_address):
        return self._neighbors.get(neigh_ip_address, None)

    def __repr__(self):
        return '<%s(%r)>' % (self.__class__.__name__, self._neighbors)

    def __str__(self):
        return '\'Neighbors\': %s' % self._neighbors

    @property
    def settings(self):
        return [neighbor.settings for _, neighbor in
                self._neighbors.iteritems()]


class NeighborConfListener(ConfWithIdListener, ConfWithStatsListener):
    """Base listener for change events to a specific neighbors' configurations.
    """
    def __init__(self, neigh_conf):
        super(NeighborConfListener, self).__init__(neigh_conf)
        neigh_conf.add_listener(NeighborConf.UPDATE_ENABLED_EVT,
                                self.on_update_enabled)
        neigh_conf.add_listener(NeighborConf.UPDATE_MED_EVT,
                                self.on_update_med)

    @abstractmethod
    def on_update_enabled(self, evt):
        raise NotImplementedError('This method should be overridden.')

    def on_update_med(self, evt):
        raise NotImplementedError('This method should be overridden.')


class NeighborsConfListener(BaseConfListener):
    """Base listener for change events to neighbor configuration container."""

    def __init__(self, neighbors_conf):
        super(NeighborsConfListener, self).__init__(neighbors_conf)
        neighbors_conf.add_listener(NeighborsConf.ADD_NEIGH_CONF_EVT,
                                    self.on_add_neighbor_conf)
        neighbors_conf.add_listener(NeighborsConf.REMOVE_NEIGH_CONF_EVT,
                                    self.on_remove_neighbor_conf)

    @abstractmethod
    def on_add_neighbor_conf(self, evt):
        raise NotImplementedError('This method should be overridden.')

    @abstractmethod
    def on_remove_neighbor_conf(self, evt):
        raise NotImplementedError('This method should be overridden.')
