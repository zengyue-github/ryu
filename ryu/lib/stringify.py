#!/usr/bin/env python
#
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

import base64
import collections
import inspect


# Some arguments to __init__ is mungled in order to avoid name conflicts
# with builtin names.
# The standard mangling is to append '_' in order to avoid name clashes
# with reserved keywords.
#
# PEP8:
# Function and method arguments
#   If a function argument's name clashes with a reserved keyword,
#   it is generally better to append a single trailing underscore
#   rather than use an abbreviation or spelling corruption. Thus
#   class_ is better than clss. (Perhaps better is to avoid such
#   clashes by using a synonym.)
#
# grep __init__ *.py | grep '[^_]_\>' showed that
# 'len', 'property', 'set', 'type'
# A bit more generic way is adopted
import __builtin__
_RESERVED_KEYWORD = dir(__builtin__)


_mapdict = lambda f, d: dict([(k, f(v)) for k, v in d.items()])
_mapdict_key = lambda f, d: dict([(f(k), v) for k, v in d.items()])


class StringifyMixin(object):
    _class_prefixes = []

    def stringify_attrs(self):
        """an override point for sub classes"""
        return obj_python_attrs(self)

    def __str__(self):
        # repr() to escape binaries
        return self.__class__.__name__ + '(' + \
            ','.join("%s=%s" % (k, repr(v)) for k, v in
                     self.stringify_attrs()) + ')'
    __repr__ = __str__  # note: str(list) uses __repr__ for elements

    @classmethod
    def _is_class(cls, dict_):
        # we distinguish a dict like OFPSwitchFeatures.ports
        # from OFPxxx classes using heuristics.
        # exmples of OFP classes:
        #   {"OFPMatch": { ... }}
        #   {"MTIPv6SRC": { ... }}
        assert isinstance(dict_, dict)
        if len(dict_) != 1:
            return False
        k = dict_.keys()[0]
        if not isinstance(k, (bytes, unicode)):
            return False
        for p in cls._class_prefixes:
            if k.startswith(p):
                return True
        return False

    @classmethod
    def _encode_value(cls, v, encode_string=base64.b64encode):
        encode = lambda x: cls._encode_value(x, encode_string)
        if isinstance(v, (bytes, unicode)):
            json_value = encode_string(v)
        elif isinstance(v, list):
            json_value = map(encode, v)
        elif isinstance(v, dict):
            json_value = _mapdict(encode, v)
            # while a python dict key can be any hashable object,
            # a JSON object key should be a string.
            json_value = _mapdict_key(str, json_value)
            assert not cls._is_class(json_value)
        else:
            try:
                json_value = v.to_jsondict()
            except:
                json_value = v
        return json_value

    def to_jsondict(self, encode_string=base64.b64encode):
        """returns an object to feed json.dumps()
        """
        dict_ = {}
        encode = lambda x: self._encode_value(x, encode_string)
        for k, v in obj_attrs(self):
            dict_[k] = encode(v)
        return {self.__class__.__name__: dict_}

    @classmethod
    def cls_from_jsondict_key(cls, k):
        # find a class with the given name from our class' module.
        import sys
        mod = sys.modules[cls.__module__]
        return getattr(mod, k)

    @classmethod
    def obj_from_jsondict(cls, jsondict):
        assert len(jsondict) == 1
        for k, v in jsondict.iteritems():
            obj_cls = cls.cls_from_jsondict_key(k)
            return obj_cls.from_jsondict(v)

    @classmethod
    def _decode_value(cls, json_value, decode_string=base64.b64decode):
        decode = lambda x: cls._decode_value(x, decode_string)
        if isinstance(json_value, (bytes, unicode)):
            v = decode_string(json_value)
        elif isinstance(json_value, list):
            v = map(decode, json_value)
        elif isinstance(json_value, dict):
            if cls._is_class(json_value):
                v = cls.obj_from_jsondict(json_value)
            else:
                v = _mapdict(decode, json_value)
                # XXXhack
                # try to restore integer keys used by OFPSwitchFeatures.ports.
                try:
                    v = _mapdict_key(int, v)
                except ValueError:
                    pass
        else:
            v = json_value
        return v

    @staticmethod
    def _restore_args(dict_):
        def restore(k):
            if k in _RESERVED_KEYWORD:
                return k + '_'
            return k
        return _mapdict_key(restore, dict_)

    @classmethod
    def from_jsondict(cls, dict_, decode_string=base64.b64decode,
                      **additional_args):
        """create an instance from a result of json.loads()
        """
        decode = lambda x: cls._decode_value(x, decode_string)
        kwargs = cls._restore_args(_mapdict(decode, dict_))
        try:
            return cls(**dict(kwargs, **additional_args))
        except TypeError:
            #debug
            print "CLS", cls
            print "ARG", dict_
            print "KWARG", kwargs
            raise


def obj_python_attrs(msg_):
    """iterate object attributes for stringify purposes
    """

    # a special case for namedtuple which seems widely used in
    # ofp parser implementations.
    if hasattr(msg_, '_fields'):
        for k in msg_._fields:
            yield(k, getattr(msg_, k))
        return
    base = getattr(msg_, '_base_attributes', [])
    for k, v in inspect.getmembers(msg_):
        if k.startswith('_'):
            continue
        if callable(v):
            continue
        if k in base:
            continue
        if hasattr(msg_.__class__, k):
            continue
        yield (k, v)


def obj_attrs(msg_):
    """similar to obj_python_attrs() but deals with python reserved keywords
    """

    if isinstance(msg_, StringifyMixin):
        iter = msg_.stringify_attrs()
    else:
        # probably called by msg_str_attr
        iter = obj_python_attrs(msg_)
    for k, v in iter:
        if k.endswith('_') and k[:-1] in _RESERVED_KEYWORD:
            # XXX currently only StringifyMixin has restoring logic
            assert isinstance(msg_, StringifyMixin)
            k = k[:-1]
        yield (k, v)
