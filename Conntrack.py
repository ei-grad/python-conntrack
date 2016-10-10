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
from socket import AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IP, IPPROTO_ICMP
from collections import namedtuple

nfct = c.CDLL(find_library('netfilter_conntrack'))
libc = c.CDLL(find_library('c'))


NFCT_CALLBACK = c.CFUNCTYPE(c.c_int, c.c_int, c.c_void_p, c.c_void_p)

# conntrack
CONNTRACK = 1
EXPECT = 2

# netlink groups
NF_NETLINK_CONNTRACK_NEW = 0x00000001
NF_NETLINK_CONNTRACK_UPDATE = 0x00000002
NF_NETLINK_CONNTRACK_DESTROY = 0x00000004
NF_NETLINK_CONNTRACK_EXP_NEW = 0x00000008
NF_NETLINK_CONNTRACK_EXP_UPDATE = 0x00000010
NF_NETLINK_CONNTRACK_EXP_DESTROY = 0x00000020

NFCT_ALL_CT_GROUPS = (NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE
                      | NF_NETLINK_CONNTRACK_DESTROY)

# nfct_*printf output format
NFCT_O_PLAIN = 0
NFCT_O_DEFAULT = NFCT_O_PLAIN
NFCT_O_XML = 1
NFCT_O_MAX = 2

# output flags
NFCT_OF_SHOW_LAYER3_BIT = 0
NFCT_OF_SHOW_LAYER3 = (1 << NFCT_OF_SHOW_LAYER3_BIT)
NFCT_OF_TIME_BIT = 1
NFCT_OF_TIME = (1 << NFCT_OF_TIME_BIT)
NFCT_OF_ID_BIT = 2
NFCT_OF_ID = (1 << NFCT_OF_ID_BIT)

# query
NFCT_Q_CREATE = 0
NFCT_Q_UPDATE = 1
NFCT_Q_DESTROY = 2
NFCT_Q_GET = 3
NFCT_Q_FLUSH = 4
NFCT_Q_DUMP = 5
NFCT_Q_DUMP_RESET = 6
NFCT_Q_CREATE_UPDATE = 7
NFCT_Q_DUMP_FILTER = 8
NFCT_Q_DUMP_FILTER_RESET = 9

# callback return code
NFCT_CB_FAILURE = -1   # failure
NFCT_CB_STOP = 0    # stop the query
NFCT_CB_CONTINUE = 1    # keep iterating through data
NFCT_CB_STOLEN = 2    # like continue, but ct is not freed

NFCT_CMP_ALL = 0
NFCT_CMP_ORIG = (1 << 0)
NFCT_CMP_REPL = (1 << 1)
NFCT_CMP_TIMEOUT_EQ = (1 << 2)
NFCT_CMP_TIMEOUT_GT = (1 << 3)
NFCT_CMP_TIMEOUT_GE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_GT)
NFCT_CMP_TIMEOUT_LT = (1 << 4)
NFCT_CMP_TIMEOUT_LE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_LT)
NFCT_CMP_MASK = (1 << 5)
NFCT_CMP_STRICT = (1 << 6)

# get option
NFCT_GOPT_IS_SNAT = 0
NFCT_GOPT_IS_DNAT = 1
NFCT_GOPT_IS_SPAT = 2
NFCT_GOPT_IS_DPAT = 3
NFCT_GOPT_MAX = NFCT_GOPT_IS_DPAT

# set option
NFCT_SOPT_UNDO_SNAT = 0
NFCT_SOPT_UNDO_DNAT = 1
NFCT_SOPT_UNDO_SPAT = 2
NFCT_SOPT_UNDO_DPAT = 3
NFCT_SOPT_MAX = NFCT_SOPT_UNDO_DPAT

# attributes
ATTR_ORIG_IPV4_SRC = 0                    # u32 bits
ATTR_IPV4_SRC = ATTR_ORIG_IPV4_SRC        # alias
ATTR_ORIG_IPV4_DST = 1                    # u32 bits
ATTR_IPV4_DST = ATTR_ORIG_IPV4_DST        # alias
ATTR_REPL_IPV4_SRC = 2                    # u32 bits
ATTR_REPL_IPV4_DST = 3                    # u32 bits
ATTR_ORIG_IPV6_SRC = 4                    # u128 bits
ATTR_IPV6_SRC = ATTR_ORIG_IPV6_SRC        # alias
ATTR_ORIG_IPV6_DST = 5                    # u128 bits
ATTR_IPV6_DST = ATTR_ORIG_IPV6_DST        # alias
ATTR_REPL_IPV6_SRC = 6                    # u128 bits
ATTR_REPL_IPV6_DST = 7                    # u128 bits
ATTR_ORIG_PORT_SRC = 8                    # u16 bits
ATTR_PORT_SRC = ATTR_ORIG_PORT_SRC        # alias
ATTR_ORIG_PORT_DST = 9                    # u16 bits
ATTR_PORT_DST = ATTR_ORIG_PORT_DST        # alias
ATTR_REPL_PORT_SRC = 10                   # u16 bits
ATTR_REPL_PORT_DST = 11                   # u16 bits
ATTR_ICMP_TYPE = 12                       # u8 bits
ATTR_ICMP_CODE = 13                       # u8 bits
ATTR_ICMP_ID = 14                         # u16 bits
ATTR_ORIG_L3PROTO = 15                    # u8 bits
ATTR_L3PROTO = ATTR_ORIG_L3PROTO          # alias
ATTR_REPL_L3PROTO = 16                    # u8 bits
ATTR_ORIG_L4PROTO = 17                    # u8 bits
ATTR_L4PROTO = ATTR_ORIG_L4PROTO          # alias
ATTR_REPL_L4PROTO = 18                    # u8 bits
ATTR_TCP_STATE = 19                       # u8 bits
ATTR_SNAT_IPV4 = 20                       # u32 bits
ATTR_DNAT_IPV4 = 21                       # u32 bits
ATTR_SNAT_PORT = 22                       # u16 bits
ATTR_DNAT_PORT = 23                       # u16 bits
ATTR_TIMEOUT = 24                         # u32 bits
ATTR_MARK = 25                            # u32 bits
ATTR_ORIG_COUNTER_PACKETS = 26            # u32 bits
ATTR_REPL_COUNTER_PACKETS = 27            # u32 bits
ATTR_ORIG_COUNTER_BYTES = 28              # u32 bits
ATTR_REPL_COUNTER_BYTES = 29              # u32 bits
ATTR_USE = 30                             # u32 bits
ATTR_ID = 31                              # u32 bits
ATTR_STATUS = 32                          # u32 bits
ATTR_TCP_FLAGS_ORIG = 33                  # u8 bits
ATTR_TCP_FLAGS_REPL = 34                  # u8 bits
ATTR_TCP_MASK_ORIG = 35                   # u8 bits
ATTR_TCP_MASK_REPL = 36                   # u8 bits
ATTR_MASTER_IPV4_SRC = 37                 # u32 bits
ATTR_MASTER_IPV4_DST = 38                 # u32 bits
ATTR_MASTER_IPV6_SRC = 39                 # u128 bits
ATTR_MASTER_IPV6_DST = 40                 # u128 bits
ATTR_MASTER_PORT_SRC = 41                 # u16 bits
ATTR_MASTER_PORT_DST = 42                 # u16 bits
ATTR_MASTER_L3PROTO = 43                  # u8 bits
ATTR_MASTER_L4PROTO = 44                  # u8 bits
ATTR_SECMARK = 45                         # u32 bits
ATTR_ORIG_NAT_SEQ_CORRECTION_POS = 46     # u32 bits
ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE = 47      # u32 bits
ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = 48       # u32 bits
ATTR_REPL_NAT_SEQ_CORRECTION_POS = 49     # u32 bits
ATTR_REPL_NAT_SEQ_OFFSET_BEFORE = 50      # u32 bits
ATTR_REPL_NAT_SEQ_OFFSET_AFTER = 51       # u32 bits
ATTR_SCTP_STATE = 52                      # u8 bits
ATTR_SCTP_VTAG_ORIG = 53                  # u32 bits
ATTR_SCTP_VTAG_REPL = 54                  # u32 bits
ATTR_HELPER_NAME = 55                     # string (30 bytes max)
ATTR_DCCP_STATE = 56                      # u8 bits
ATTR_DCCP_ROLE = 57                       # u8 bits
ATTR_DCCP_HANDSHAKE_SEQ = 58              # u64 bits
ATTR_MAX = 59
ATTR_GRP_ORIG_IPV4 = 0                    # struct nfct_attr_grp_ipv4
ATTR_GRP_REPL_IPV4 = 1                    # struct nfct_attr_grp_ipv4
ATTR_GRP_ORIG_IPV6 = 2                    # struct nfct_attr_grp_ipv6
ATTR_GRP_REPL_IPV6 = 3                    # struct nfct_attr_grp_ipv6
ATTR_GRP_ORIG_PORT = 4                    # struct nfct_attr_grp_port
ATTR_GRP_REPL_PORT = 5                    # struct nfct_attr_grp_port
ATTR_GRP_ICMP = 6                         # struct nfct_attr_grp_icmp
ATTR_GRP_MASTER_IPV4 = 7                  # struct nfct_attr_grp_ipv4
ATTR_GRP_MASTER_IPV6 = 8                  # struct nfct_attr_grp_ipv6
ATTR_GRP_MASTER_PORT = 9                  # struct nfct_attr_grp_port
ATTR_GRP_ORIG_COUNTERS = 10               # struct nfct_attr_grp_ctrs
ATTR_GRP_REPL_COUNTERS = 11               # struct nfct_attr_grp_ctrs
ATTR_GRP_MAX = 12
ATTR_EXP_MASTER = 0                       # pointer to conntrack object
ATTR_EXP_EXPECTED = 1                     # pointer to conntrack object
ATTR_EXP_MASK = 2                         # pointer to conntrack object
ATTR_EXP_TIMEOUT = 3                      # u32 bits
ATTR_EXP_MAX = 4

#ct optionsCT_OPT_ORIG_SRC_BIT	= 0,
CT_OPT_ORIG_SRC_BIT = 0
CT_OPT_ORIG_SRC = (1 << CT_OPT_ORIG_SRC_BIT)

CT_OPT_ORIG_DST_BIT	= 1
CT_OPT_ORIG_DST		= (1 << CT_OPT_ORIG_DST_BIT)

CT_OPT_ORIG		= (CT_OPT_ORIG_SRC | CT_OPT_ORIG_DST)

CT_OPT_REPL_SRC_BIT	= 2
CT_OPT_REPL_SRC		= (1 << CT_OPT_REPL_SRC_BIT)

CT_OPT_REPL_DST_BIT	= 3
CT_OPT_REPL_DST		= (1 << CT_OPT_REPL_DST_BIT)

CT_OPT_REPL		= (CT_OPT_REPL_SRC | CT_OPT_REPL_DST)

CT_OPT_PROTO_BIT	= 4
CT_OPT_PROTO		= (1 << CT_OPT_PROTO_BIT)

CT_OPT_TUPLE_ORIG	= (CT_OPT_ORIG | CT_OPT_PROTO)
CT_OPT_TUPLE_REPL	= (CT_OPT_REPL | CT_OPT_PROTO)

CT_OPT_TIMEOUT_BIT	= 5
CT_OPT_TIMEOUT		= (1 << CT_OPT_TIMEOUT_BIT)

CT_OPT_STATUS_BIT	= 6
CT_OPT_STATUS		= (1 << CT_OPT_STATUS_BIT)

CT_OPT_ZERO_BIT		= 7
CT_OPT_ZERO		= (1 << CT_OPT_ZERO_BIT)

CT_OPT_EVENT_MASK_BIT	= 8
CT_OPT_EVENT_MASK	= (1 << CT_OPT_EVENT_MASK_BIT)

CT_OPT_EXP_SRC_BIT	= 9
CT_OPT_EXP_SRC		= (1 << CT_OPT_EXP_SRC_BIT)

CT_OPT_EXP_DST_BIT	= 10
CT_OPT_EXP_DST		= (1 << CT_OPT_EXP_DST_BIT)

CT_OPT_MASK_SRC_BIT	= 11
CT_OPT_MASK_SRC		= (1 << CT_OPT_MASK_SRC_BIT)

CT_OPT_MASK_DST_BIT	= 12
CT_OPT_MASK_DST		= (1 << CT_OPT_MASK_DST_BIT)

CT_OPT_NATRANGE_BIT	= 13
CT_OPT_NATRANGE		= (1 << CT_OPT_NATRANGE_BIT)

CT_OPT_MARK_BIT		= 14
CT_OPT_MARK		= (1 << CT_OPT_MARK_BIT)

CT_OPT_ID_BIT		= 15
CT_OPT_ID		= (1 << CT_OPT_ID_BIT)

CT_OPT_FAMILY_BIT	= 16
CT_OPT_FAMILY		= (1 << CT_OPT_FAMILY_BIT)

CT_OPT_SRC_NAT_BIT	= 17
CT_OPT_SRC_NAT		= (1 << CT_OPT_SRC_NAT_BIT)

CT_OPT_DST_NAT_BIT	= 18
CT_OPT_DST_NAT		= (1 << CT_OPT_DST_NAT_BIT)

CT_OPT_OUTPUT_BIT	= 19
CT_OPT_OUTPUT		= (1 << CT_OPT_OUTPUT_BIT)

CT_OPT_SECMARK_BIT	= 20
CT_OPT_SECMARK		= (1 << CT_OPT_SECMARK_BIT)

CT_OPT_BUFFERSIZE_BIT	= 21
CT_OPT_BUFFERSIZE	= (1 << CT_OPT_BUFFERSIZE_BIT)

CT_OPT_ANY_NAT_BIT	= 22
CT_OPT_ANY_NAT		= (1 << CT_OPT_ANY_NAT_BIT)

CT_OPT_ZONE_BIT		= 23
CT_OPT_ZONE = (1 << CT_OPT_ZONE_BIT)

CT_COMPARISON = (CT_OPT_PROTO | CT_OPT_ORIG | CT_OPT_REPL | \
		       CT_OPT_MARK | CT_OPT_SECMARK |  CT_OPT_STATUS | \
CT_OPT_ID | CT_OPT_ZONE)

# message type
NFCT_T_UNKNOWN = 0
NFCT_T_NEW_BIT = 0
NFCT_T_NEW = (1 << NFCT_T_NEW_BIT)
NFCT_T_UPDATE_BIT = 1
NFCT_T_UPDATE = (1 << NFCT_T_UPDATE_BIT)
NFCT_T_DESTROY_BIT = 2
NFCT_T_DESTROY = (1 << NFCT_T_DESTROY_BIT)

NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY
NFCT_T_ERROR_BIT = 31
NFCT_T_ERROR = (1 << NFCT_T_ERROR_BIT)


libc.__errno_location.restype = c.POINTER(c.c_int)
libc.strerror.restype = c.c_char_p

u32_mask = namedtuple("u32_mask", "value, mask")
tmpl = namedtuple("tmpl", "ct, exp, exptuple, mask, mark, filter_mark_kernel")
options = 0

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

    def delete(self, ipversion=None, proto=None, src=None, dst=None, sport=None, dport=None):
        global options
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
                nfct.nfct_set_attr_u128(ct, ATTR_IPV4_SRC,
                                    libc.inet_addr(src))
            if dst:
                nfct.nfct_set_attr_u128(ct, ATTR_IPV4_DST,
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
            print buf.value
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


__all__ = ["EventListener", "ConnectionManager",
           "parse_plaintext_event",
           "NFCT_O_XML", "NFCT_O_PLAIN", "NFCT_T_NEW",
           "NFCT_T_UPDATE", "NFCT_T_DESTROY", "NFCT_T_ALL",
           "IPPROTO_TCP", "IPPROTO_UDP",
           "AF_INET", "AF_INET6"]
