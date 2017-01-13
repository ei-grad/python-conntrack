#!/usr/bin/env python
#
# Copyright (c) 2009-2011,2015 Andrew Grigorev <andrew@ei-grad.ru>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

"""
Conntrack - A simple python interface to libnetfilter_conntrack using ctypes.
"""

import sys
import logging
import ctypes as c
from ctypes.util import find_library
from threading import Thread
from socket import AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IP, IPPROTO_ICMP, AF_UNSPEC
from collections import namedtuple

from Conntrack.constants import *


nfct = c.CDLL(find_library('netfilter_conntrack'))
libc = c.CDLL(find_library('c'))


NFCT_CALLBACK = c.CFUNCTYPE(c.c_int, c.c_int, c.c_void_p, c.c_void_p)


libc.__errno_location.restype = c.POINTER(c.c_int)
libc.strerror.restype = c.c_char_p

u32_mask = namedtuple("u32_mask", "value, mask")
tmpl = namedtuple("tmpl", "ct, exp, exptuple, mask, mark, filter_mark_kernel")

def alloc_tmpl_objects():
    tmpl(ct=nfct.nfct_new(), exptuple=nfct.nfct_new(), exp=nfct.nfct_new(), mask=nfct.nfct_new())
    return not tmpl.ct and not tmpl.exptuple and not tmpl.mask and not tmpl.exp

def free_tmpl_objects():
    if (tmpl.ct):
        nfct.nfct_destroy(tmpl.ct)
    if (tmpl.exptuple):
        nfct.nfct_destroy(tmpl.exptuple)
    if (tmpl.mask):
        nfct.nfct_destroy(tmpl.mask)
    if (tmpl.exp):
        nfct.nfct_destroy(tmpl.exp)

def nfct_catch_errcheck(ret, func, args):
    if ret == -1:
        e = libc.__errno_location()[0]
        raise OSError(libc.strerror(e))

def mark_cmp(m, ct):
    return nfct.nfct_attri_is_set(ct, ATTR_MARK) and (
        nfct.nfct_get_attr_u32(ct, ATTR_MARK) & m.mask) == m.value

def filter_mark(options, ct, obj):
    if ((options & CT_OPT_MARK) and not mark_cmp(obj, ct)):
        return 1
    else:
        return 0

def filter_nat(obj, ct):
    check_srcnat = 1 if options & CT_OPT_SRC_NAT else 0
    check_dstnat = 1 if options & CT_OPT_DST_NAT else 0
    has_srcnat = 0
    has_dstnat = 0

    if (options & CT_OPT_ANY_NAT):
        check_dstnat = 1
        check_srcnat = 1

    if check_srcnat:
        check_address = check_port =0
        if nfct.nfct_attr_is_set(obj, ATTR_SNAT_IPV4):
            check_address = 1
            ip = nfct.nfct_get_attr_u32(obj, ATTR_SNAT_IPV4)
            if nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) and (ip == nfct.nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST)):
                has_srcnat = 1
        if nfct.nfct_attr_is_set(obj, ATTR_SNAT_PORT):
            ret = 0
            check_port = 1
            port = nfct.nfct_get_attr_u16(obj, ATTR_SNAT_PORT)
            if nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT) and (port == nfct.nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST)):
                ret = 1
            if check_address and has_srcnat and not ret:
                has_srcnat = 0
            if not check_address and ret:
                has_srcnat = 1
        if not check_address and not check_port and (nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) or nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)):
            has_srcnat = 1

    if check_dstnat:
        check_address = check_port =0
        if nfct.nfct_attr_is_set(obj, ATTR_DNAT_IPV4):
            check_address = 1
            ip = nfct.nfct_get_attr_u32(obj, ATTR_DNAT_IPV4)
            if nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT) and (ip == nfct.nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC)):
                has_srcnat = 1
        if nfct.nfct_attr_is_set(obj, ATTR_DNAT_PORT):
            ret = 0
            check_port = 1
            port = nfct.nfct_get_attr_u16(obj, ATTR_DNAT_PORT)
            if nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT) and (port == nfct.nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC)):
                ret = 1
            if check_address and has_dstnat and not ret:
                has_dstnat = 0
            if not check_address and ret:
                has_dstnat = 1
        if not check_address and not check_port and (nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT) or nfct.nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT)):
            has_srcnat = 1

    if (options & CT_OPT_ANY_NAT):
        return not(has_srcnat or has_dstnat)
    elif ((options & CT_OPT_SRC_NAT)) and (options & CT_OPT_DST_NAT):
        return not (has_srcnat and has_dstnat)
    elif (options & CT_OPT_SRC_NAT):
        return not has_srcnat
    elif (options & CT_OPT_DST_NAT):
        return not has_dstnat
    return 0

def parse_plaintext_event(event):
    '''
    Convert conntrack event from NFCT_O_PLAIN format to dict.

    @return: tuple(proto, dict(in), dict(out))
    '''

    if sys.version_info[0] == 3:
        e = str(event, 'utf-8').split()
    else:
        e = str(event).decode('utf-8').split()
    proto = e[1]
    pairs = [i.split('=') for i in e if '=' in i]
    n = len(pairs) >> 1
    d_in = dict(pairs[:n])
    d_out = dict(pairs[n:])
    return proto, d_in, d_out


class EventListener(Thread):

    '''
    Calling a specified callback function to notify about conntrack events.
    '''

    def __init__(self, callback,
                 msg_types=NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY,
                 output_format=NFCT_O_PLAIN):
        Thread.__init__(self)

        self.msg_types = msg_types
        self.output_format = output_format

        self._running = False

        buf = c.create_string_buffer(1024)

        @NFCT_CALLBACK
        def cb(msg_type, ct, data):
            nfct.nfct_snprintf(buf, 1024, ct, msg_type, self.output_format,
                               NFCT_OF_TIME)
            callback(buf.value)
            return NFCT_CB_CONTINUE

        self.cb = cb

        self.h = self.get_handle()

    def get_handle(self):

        handle = nfct.nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS)

        if handle == 0:
            libc.perror("nfct_open")
            raise Exception("nfct_open failed!")

        nfct.nfct_callback_register(handle, self.msg_types, self.cb, 0)

        return handle

    def run(self):
        self._running = True
        nfct.nfct_catch.errcheck = nfct_catch_errcheck
        while self._running:
            try:
                nfct.nfct_catch(self.h)
            except OSError:
                if self._running:
                    logging.error('nfct_catch failed, may lose some connections')
                    nfct.nfct_close(self.h)
                    self.h = self.get_handle()

    def stop(self):
        self._running = False
        nfct.nfct_close(self.h)
        self.join()


class ConnectionManager(object):

    '''
    Could list all connections, get information about single connection.
    Has ability to destroy connections.
    '''

    def __init__(self, fmt=NFCT_O_DEFAULT, family=AF_INET):
        '''
        Create new ConnectionManager object

        @param fmt: format of returned messages
            - NFCT_O_XML
            - NFCT_O_PLAIN

        @param family: protocol family to work with
            - AF_INET
            - AF_INET6
        '''

        self.__format = fmt
        self.__family = family

    def list(self):
        '''Get list of active connections from conntrack.'''

        l = []

        buf = c.create_string_buffer(1024)

        @NFCT_CALLBACK
        def cb(type, ct, data):
            nfct.nfct_snprintf(buf, 1024, ct, type, self.__format, NFCT_OF_TIME)
            l.append(buf.value)
            return NFCT_CB_CONTINUE

        h = nfct.nfct_open(CONNTRACK, 0)

        if not h:
            libc.perror("nfct_open")
            raise Exception("nfct_open failed!")

        nfct.nfct_callback_register(h, NFCT_T_ALL, cb, 0)
        ret = nfct.nfct_query(h, NFCT_Q_DUMP, c.byref(c.c_int(self.__family)))
        if ret == -1:
            libc.perror("nfct_query")
            nfct.nfct_close(h)
            raise Exception("nfct_query failed!")
        nfct.nfct_close(h)
        return l

    def get(self, proto, src, dst, sport, dport):
        '''
        Get information about specified connection.

        proto: IPPROTO_UDP or IPPROTO_TCP
        src: source ip address
        dst: destination ip address
        sport: source port
        dport: destination port
        '''

        l = []

        ct = nfct.nfct_new()
        if not ct:
            libc.perror("nfct_new")
            raise Exception("nfct_new failed!")

        nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, self.__family)

        if self.__family == AF_INET:
            nfct.nfct_set_attr_u32(ct, ATTR_IPV4_SRC,
                                   libc.inet_addr(src))
            nfct.nfct_set_attr_u32(ct, ATTR_IPV4_DST,
                                   libc.inet_addr(dst))
        elif self.__family == AF_INET6:
            nfct.nfct_set_attr_u128(ct, ATTR_IPV6_SRC,
                                    libc.inet_addr(src))
            nfct.nfct_set_attr_u128(ct, ATTR_IPV6_DST,
                                    libc.inet_addr(dst))
        else:
            raise Exception("Unsupported protocol family!")

        nfct.nfct_set_attr_u8(ct, ATTR_L4PROTO, proto)

        nfct.nfct_set_attr_u16(ct, ATTR_PORT_SRC, libc.htons(sport))
        nfct.nfct_set_attr_u16(ct, ATTR_PORT_DST, libc.htons(dport))

        h = nfct.nfct_open(CONNTRACK, 0)
        if not h:
            libc.perror("nfct_open")
            raise Exception("nfct_open failed!")

        buf = c.create_string_buffer(1024)

        @NFCT_CALLBACK
        def cb(type, ct, data):
            nfct.nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, self.__format,
                               NFCT_OF_SHOW_LAYER3)
            l.append(buf.value)
            return NFCT_CB_CONTINUE

        nfct.nfct_callback_register(h, NFCT_T_ALL, cb, 0)

        ret = nfct.nfct_query(h, NFCT_Q_GET, ct)

        if ret == -1:
            libc.perror("nfct_query")
            raise Exception("nfct_query failed!")

        nfct.nfct_close(h)

        return l[0]

    def dump(self, ipversion=None, proto=None, src=None, dst=None, sport=None, dport=None, nat=False):
        global options
        options = 0
        ct = nfct.nfct_new()
        mask=nfct.nfct_new()
        cth = nfct.nfct_open(CONNTRACK, 0)

        if not ct or not mask:
            libc.perror("nfct_new")
            raise Exception("nfct_new failed!")

        if ipversion == 6:
            nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6)
            if src:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV6_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV6_DST,
                                    libc.inet_addr(dst))
        elif ipversion == 4:
            nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET)
            if src:
                nfct.nfct_set_attr_u32(ct, ATTR_IPV4_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u32(ct, ATTR_IPV4_DST,
                                    libc.inet_addr(dst))
        else:
            raise Exception("Unsupported protocol family!")
        if proto:
            nfct.nfct_set_attr_u8(ct, ATTR_L4PROTO, proto)
            options |= CT_OPT_PROTO
        if sport:
            nfct.nfct_set_attr_u16(ct, ATTR_PORT_SRC, libc.htons(sport))
        if dport:
            nfct.nfct_set_attr_u16(ct, ATTR_PORT_DST, libc.htons(dport))

        if nat:
            options |= CT_OPT_ANY_NAT

        buf = c.create_string_buffer(1024)
        @NFCT_CALLBACK
        def cb(type, ct, data):
            obj = data
            if (filter_nat(obj, ct)):
                return NFCT_CB_CONTINUE
            if filter_mark(options, ct, obj):
                return NFCT_CB_CONTINUE
            if (options & CT_COMPARISON) and not nfct.nfct_cmp(data, ct, NFCT_CMP_ALL | NFCT_CMP_MASK):
                return NFCT_CB_CONTINUE
            nfct.nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, self.__format,
                               NFCT_OF_SHOW_LAYER3)
            print(buf.value)
            return NFCT_CB_CONTINUE

        nfct.nfct_callback_register(cth, NFCT_T_ALL, cb, ct)
        filter_dump = nfct.nfct_filter_dump_create()
        if not filter_dump:
            libc.perror("nfct_filter_dump_create")
        ret = nfct.nfct_query(cth, NFCT_Q_DUMP_FILTER, filter_dump)
        if ret < 0:
            libc.perror("nfct_query")
            raise Exception("nfct_query failed!")
        nfct.nfct_filter_dump_destroy(filter_dump)
        nfct.nfct_destroy(mask)
        nfct.nfct_close(cth)



    def kill(self, proto, src, dst, sport, dport):
        '''
        Delete specified connection.

        proto: IPPROTO_UDP or IPPROTO_TCP
        src: source ip address
        dst: destination ip address
        sport: source port
        dport: destination port
        '''

        ct = nfct.nfct_new()
        if not ct:
            libc.perror("nfct_new")
            raise Exception("nfct_new failed!")

        nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, self.__family)

        if self.__family == AF_INET:
            nfct.nfct_set_attr_u32(ct, ATTR_IPV4_SRC,
                                   libc.inet_addr(src))
            nfct.nfct_set_attr_u32(ct, ATTR_IPV4_DST,
                                   libc.inet_addr(dst))
        elif self.__family == AF_INET6:
            nfct.nfct_set_attr_u128(ct, ATTR_IPV6_SRC,
                                    libc.inet_addr(src))
            nfct.nfct_set_attr_u128(ct, ATTR_IPV6_DST,
                                    libc.inet_addr(dst))
        else:
            raise Exception("Unsupported protocol family!")

        nfct.nfct_set_attr_u8(ct, ATTR_L4PROTO, proto)

        nfct.nfct_set_attr_u16(ct, ATTR_PORT_SRC, libc.htons(sport))
        nfct.nfct_set_attr_u16(ct, ATTR_PORT_DST, libc.htons(dport))

        h = nfct.nfct_open(CONNTRACK, 0)
        if not h:
            libc.perror("nfct_open")
            raise Exception("nfct_open failed!")

        ret = nfct.nfct_query(h, NFCT_Q_DESTROY, ct)

        if ret == -1:
            libc.perror("nfct_query")
            raise Exception("nfct_query failed!")

        nfct.nfct_close(h)

    def delete(self, ipversion=None, proto=None, src=None, dst=None, sport=None, dport=None, nat=False):
        global options
        options = 0
        ct = nfct.nfct_new()
        mask=nfct.nfct_new()
        cth = nfct.nfct_open(CONNTRACK, 0)
        ith = nfct.nfct_open(CONNTRACK, 0)
        
        if not ith or not cth:
            libc.perror("nfct_open")
        if ipversion == 6:
            nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6)
            if src:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV6_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV6_DST,
                                    libc.inet_addr(dst))
        elif ipversion == 4:
            nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET)
            if src:
                nfct.nfct_set_attr_u32(ct, ATTR_IPV4_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u32(ct, ATTR_IPV4_DST,
                                    libc.inet_addr(dst))
        else:
            raise Exception("Unsupported protocol family!")
        if proto:
            nfct.nfct_set_attr_u8(ct, ATTR_L4PROTO, proto)
            options |= CT_OPT_PROTO
        if sport:
            nfct.nfct_set_attr_u16(ct, ATTR_PORT_SRC, libc.htons(sport))
        if dport:
            nfct.nfct_set_attr_u16(ct, ATTR_PORT_DST, libc.htons(dport))

        if nat:
            options |= CT_OPT_ANY_NAT

        buf = c.create_string_buffer(1024)
        @NFCT_CALLBACK
        def cb(type, ct, data):
            obj = data
            if (filter_nat(obj, ct)):
                return NFCT_CB_CONTINUE
            if filter_mark(options, ct, obj):
                return NFCT_CB_CONTINUE
            if (options & CT_COMPARISON) and not nfct.nfct_cmp(data, ct, NFCT_CMP_ALL | NFCT_CMP_MASK):
                return NFCT_CB_CONTINUE
            res = nfct.nfct_query(ith, NFCT_Q_DESTROY, ct)
            if res < 0:
                libc.perror("nfct_delete")
                raise Exception("nfct_query failed!")
            nfct.nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, self.__format,
                               NFCT_OF_SHOW_LAYER3)
            print(buf.value)
            return NFCT_CB_CONTINUE
        nfct.nfct_callback_register(cth, NFCT_T_ALL, cb, ct)
        filter_dump = nfct.nfct_filter_dump_create()
        if not filter_dump:
            libc.perror("nfct_filter_dump_create")
        ret = nfct.nfct_query(cth, NFCT_Q_DUMP_FILTER, filter_dump)
        nfct.nfct_filter_dump_set_attr_u8(filter_dump, NFCT_FILTER_DUMP_L3NUM, AF_INET) if ipversion == 4 else nfct.nfct_filter_dump_set_attr_u8(filter_dump, NFCT_FILTER_DUMP_L3NUM, AF_INET6)
        if ret < 0:
            libc.perror("nfct_query")
            raise Exception("nfct_query failed!")
        nfct.nfct_filter_dump_destroy(filter_dump)
        nfct.nfct_destroy(mask)
        nfct.nfct_close(ith)
        nfct.nfct_close(cth)

    def flush(self):
        ct = nfct.nfct_new()
        if not ct:
            libc.perror("nfct_new")
            raise Exception("nfct_new failed!")

        nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, self.__family)
        h = nfct.nfct_open(CONNTRACK, 0)
        if not h:
            libc.perror("nfct_open")
            raise Exception("nfct_open failed!")

        ret = nfct.nfct_query(h, NFCT_Q_FLUSH, ct)
        if ret == -1:
            libc.perror("nfct_query")
            raise Exception("nfct_query failed!")

        nfct.nfct_close(h)

    def update(self, ipversion=None, proto=None, src=None, dst=None, sport=None, dport=None, nat=False, m = None):
        global options
        options = 0
        cth = nfct.nfct_open(CONNTRACK, 0)
        ith = nfct.nfct_open(CONNTRACK, 0)
        if not ith or not cth:
            libc.perror("nfct_open")
        ct = nfct.nfct_new()
        mark=nfct.nfct_new()
        if not ith or not cth:
            libc.perror("nfct_open")
        if ipversion == 6:
            nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6)
            if src:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV6_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV6_DST,
                                    libc.inet_addr(dst))
        elif ipversion == 4:
            nfct.nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET)
            if src:
                nfct.nfct_set_attr_u32(ct, ATTR_IPV4_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u32(ct, ATTR_IPV4_DST,
                                    libc.inet_addr(dst))
        else:
            raise Exception("Unsupported protocol family!")
        if proto:
            nfct.nfct_set_attr_u8(ct, ATTR_L4PROTO, proto)
            options |= CT_OPT_PROTO
        if sport:
            nfct.nfct_set_attr_u16(ct, ATTR_PORT_SRC, libc.htons(sport))
        if dport:
            nfct.nfct_set_attr_u16(ct, ATTR_PORT_DST, libc.htons(dport))

        if nat:
            options |= CT_OPT_ANY_NAT
        if m:
            options |= CT_OPT_MARK

        buf = c.create_string_buffer(1024)
        @NFCT_CALLBACK
        def cb(type, ct, data):
            obj = data
            if (filter_nat(obj, ct)):
                return NFCT_CB_CONTINUE
            if (nfct.nfct_attr_is_set(obj, ATTR_ID) and nfct.nfct_attr_is_set(ct, ATTR_ID) and
                nfct.nfct_get_attr_u32(obj, ATTR_ID) != nfct.nfct_get_attr_u32(ct, ATTR_ID)):
                return NFCT_CB_CONTINUE
            if (options & CT_OPT_TUPLE_ORIG and not nfct.nfct_cmp(obj, ct, NFCT_CMP_ORIG)):
                return NFCT_CB_CONTINUE
            if (options & CT_OPT_TUPLE_REPL and not nfct.nfct_cmp(obj, ct, NFCT_CMP_REPL)):
                return NFCT_CB_CONTINUE
            tmp = nfct.nfct_new()
            if not tmp:
                raise Exception("Out of memory")
            nfct.nfct_copy(tmp, ct, NFCT_CP_ORIG)
            nfct.nfct_copy(tmp, obj, NFCT_CP_META)
            nfct.copy_mark(tmp, ct, mark)
            nfct.copy_status(tmp, ct)

            if (nfct.nfct_cmp(tmp, ct, NFCT_CMP_ALL | NFCT_CMP_MASK)):
                nfct.nfct_destroy(tmp)
                return NFCT_CB_CONTINUE
            res = nfct.nfct_query(ith, NFCT_Q_UPDATE, tmp)
            if res < 0:
                nfct.nfct_destroy(tmp)
                raise Exception('Failed to update')

            res = nfct.nfct_query(ith, NFCT_Q_GET, tmp)
            if res < 0:
                nfct.nfct_destroy(tmp)
                raise Exception('Failed to update')
            nfct.nfct_destroy(tmp)
            nfct.nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, self.__format,
                               NFCT_OF_SHOW_LAYER3)
            print(buf.value)
            return NFCT_CB_CONTINUE

        nfct.nfct_callback_register(cth, NFCT_T_ALL, cb, ct)
        nfct.nfct_destroy(mark)
        nfct.nfct_close(ith)
        nfct.nfct_close(cth)

__all__ = ["EventListener", "ConnectionManager",
           "parse_plaintext_event",
           "NFCT_O_XML", "NFCT_O_PLAIN", "NFCT_T_NEW",
           "NFCT_T_UPDATE", "NFCT_T_DESTROY", "NFCT_T_ALL",
           "IPPROTO_TCP", "IPPROTO_UDP",
           "AF_INET", "AF_INET6"]
