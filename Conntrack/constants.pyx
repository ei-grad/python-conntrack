# conntrack
CONNTRACK = 1
EXPECT = 2

cdef extern from "<libnetfilter_conntrack/libnetfilter_conntrack.h>":

    # nfct_open
    cdef int _NFNL_SUBSYS_CTNETLINK "NFNL_SUBSYS_CTNETLINK"

    # netlink groups
    cdef int _NF_NETLINK_CONNTRACK_NEW "NF_NETLINK_CONNTRACK_NEW"
    cdef int _NF_NETLINK_CONNTRACK_UPDATE "NF_NETLINK_CONNTRACK_UPDATE"
    cdef int _NF_NETLINK_CONNTRACK_DESTROY "NF_NETLINK_CONNTRACK_DESTROY"
    cdef int _NF_NETLINK_CONNTRACK_EXP_NEW "NF_NETLINK_CONNTRACK_EXP_NEW"
    cdef int _NF_NETLINK_CONNTRACK_EXP_UPDATE "NF_NETLINK_CONNTRACK_EXP_UPDATE"
    cdef int _NF_NETLINK_CONNTRACK_EXP_DESTROY "NF_NETLINK_CONNTRACK_EXP_DESTROY"

    cdef int _NFCT_ALL_CT_GROUPS "NFCT_ALL_CT_GROUPS"

    # nfctcdef int __ "_"*printf output format
    cdef int _NFCT_O_PLAIN "NFCT_O_PLAIN"
    cdef int _NFCT_O_DEFAULT "NFCT_O_DEFAULT"
    cdef int _NFCT_O_XML "NFCT_O_XML"
    cdef int _NFCT_O_MAX "NFCT_O_MAX"

    # output flags
    cdef int _NFCT_OF_SHOW_LAYER3_BIT "NFCT_OF_SHOW_LAYER3_BIT"
    cdef int _NFCT_OF_SHOW_LAYER3 "NFCT_OF_SHOW_LAYER3"
    cdef int _NFCT_OF_TIME_BIT "NFCT_OF_TIME_BIT"
    cdef int _NFCT_OF_TIME "NFCT_OF_TIME"
    cdef int _NFCT_OF_ID_BIT "NFCT_OF_ID_BIT"
    cdef int _NFCT_OF_ID "NFCT_OF_ID"

    # query
    cdef int _NFCT_Q_CREATE "NFCT_Q_CREATE"
    cdef int _NFCT_Q_UPDATE "NFCT_Q_UPDATE"
    cdef int _NFCT_Q_DESTROY "NFCT_Q_DESTROY"
    cdef int _NFCT_Q_GET "NFCT_Q_GET"
    cdef int _NFCT_Q_FLUSH "NFCT_Q_FLUSH"
    cdef int _NFCT_Q_DUMP "NFCT_Q_DUMP"
    cdef int _NFCT_Q_DUMP_RESET "NFCT_Q_DUMP_RESET"
    cdef int _NFCT_Q_CREATE_UPDATE "NFCT_Q_CREATE_UPDATE"
    cdef int _NFCT_Q_DUMP_FILTER "NFCT_Q_DUMP_FILTER"
    cdef int _NFCT_Q_DUMP_FILTER_RESET "NFCT_Q_DUMP_FILTER_RESET"

    # callback return code
    cdef int _NFCT_CB_FAILURE "NFCT_CB_FAILURE" # failure
    cdef int _NFCT_CB_STOP "NFCT_CB_STOP" # stop the query
    cdef int _NFCT_CB_CONTINUE "NFCT_CB_CONTINUE" # keep iterating through data
    cdef int _NFCT_CB_STOLEN "NFCT_CB_STOLEN" # like continue, but ct is not freed

    cdef int _NFCT_CMP_ALL "NFCT_CMP_ALL"
    cdef int _NFCT_CMP_ORIG "NFCT_CMP_ORIG"
    cdef int _NFCT_CMP_REPL "NFCT_CMP_REPL"
    cdef int _NFCT_CMP_TIMEOUT_EQ "NFCT_CMP_TIMEOUT_EQ"
    cdef int _NFCT_CMP_TIMEOUT_GT "NFCT_CMP_TIMEOUT_GT"
    cdef int _NFCT_CMP_TIMEOUT_GE "NFCT_CMP_TIMEOUT_GE"
    cdef int _NFCT_CMP_TIMEOUT_LT "NFCT_CMP_TIMEOUT_LT"
    cdef int _NFCT_CMP_TIMEOUT_LE "NFCT_CMP_TIMEOUT_LE"
    cdef int _NFCT_CMP_MASK "NFCT_CMP_MASK"
    cdef int _NFCT_CMP_STRICT "NFCT_CMP_STRICT"

    # get option
    cdef int _NFCT_GOPT_IS_SNAT "NFCT_GOPT_IS_SNAT"
    cdef int _NFCT_GOPT_IS_DNAT "NFCT_GOPT_IS_DNAT"
    cdef int _NFCT_GOPT_IS_SPAT "NFCT_GOPT_IS_SPAT"
    cdef int _NFCT_GOPT_IS_DPAT "NFCT_GOPT_IS_DPAT"
    cdef int _NFCT_GOPT_MAX "NFCT_GOPT_MAX"

    # set option
    cdef int _NFCT_SOPT_UNDO_SNAT "NFCT_SOPT_UNDO_SNAT"
    cdef int _NFCT_SOPT_UNDO_DNAT "NFCT_SOPT_UNDO_DNAT"
    cdef int _NFCT_SOPT_UNDO_SPAT "NFCT_SOPT_UNDO_SPAT"
    cdef int _NFCT_SOPT_UNDO_DPAT "NFCT_SOPT_UNDO_DPAT"
    cdef int _NFCT_SOPT_MAX "NFCT_SOPT_MAX"

    # attributes
    cdef int _ATTR_ORIG_IPV4_SRC "ATTR_ORIG_IPV4_SRC" # ucdef int _32 "32" bits
    cdef int _ATTR_IPV4_SRC "ATTR_IPV4_SRC" # alias
    cdef int _ATTR_ORIG_IPV4_DST "ATTR_ORIG_IPV4_DST"  # ucdef int _32 "32" bits
    cdef int _ATTR_IPV4_DST "ATTR_IPV4_DST"  # alias
    cdef int _ATTR_REPL_IPV4_SRC "ATTR_REPL_IPV4_SRC"  # ucdef int _32 "32" bits
    cdef int _ATTR_REPL_IPV4_DST "ATTR_REPL_IPV4_DST"  # ucdef int _32 "32" bits
    cdef int _ATTR_ORIG_IPV6_SRC "ATTR_ORIG_IPV6_SRC"  # ucdef int _128 "128" bits
    cdef int _ATTR_IPV6_SRC "ATTR_IPV6_SRC"  # alias
    cdef int _ATTR_ORIG_IPV6_DST "ATTR_ORIG_IPV6_DST"  # ucdef int _128 "128" bits
    cdef int _ATTR_IPV6_DST "ATTR_IPV6_DST"  # alias
    cdef int _ATTR_REPL_IPV6_SRC "ATTR_REPL_IPV6_SRC"  # ucdef int _128 "128" bits
    cdef int _ATTR_REPL_IPV6_DST "ATTR_REPL_IPV6_DST"  # ucdef int _128 "128" bits
    cdef int _ATTR_ORIG_PORT_SRC "ATTR_ORIG_PORT_SRC"  # ucdef int _16 "16" bits
    cdef int _ATTR_PORT_SRC "ATTR_PORT_SRC"  # alias
    cdef int _ATTR_ORIG_PORT_DST "ATTR_ORIG_PORT_DST"  # ucdef int _16 "16" bits
    cdef int _ATTR_PORT_DST "ATTR_PORT_DST"  # alias
    cdef int _ATTR_REPL_PORT_SRC "ATTR_REPL_PORT_SRC"  # ucdef int _16 "16" bits
    cdef int _ATTR_REPL_PORT_DST "ATTR_REPL_PORT_DST"  # ucdef int _16 "16" bits
    cdef int _ATTR_ICMP_TYPE "ATTR_ICMP_TYPE"  # ucdef int _8 "8" bits
    cdef int _ATTR_ICMP_CODE "ATTR_ICMP_CODE"  # ucdef int _8 "8" bits
    cdef int _ATTR_ICMP_ID "ATTR_ICMP_ID"  # ucdef int _16 "16" bits
    cdef int _ATTR_ORIG_L3PROTO "ATTR_ORIG_L3PROTO"  # ucdef int _8 "8" bits
    cdef int _ATTR_L3PROTO "ATTR_L3PROTO"  # alias
    cdef int _ATTR_REPL_L3PROTO "ATTR_REPL_L3PROTO"  # ucdef int _8 "8" bits
    cdef int _ATTR_ORIG_L4PROTO "ATTR_ORIG_L4PROTO"  # ucdef int _8 "8" bits
    cdef int _ATTR_L4PROTO "ATTR_L4PROTO"  # alias
    cdef int _ATTR_REPL_L4PROTO "ATTR_REPL_L4PROTO"  # ucdef int _8 "8" bits
    cdef int _ATTR_TCP_STATE "ATTR_TCP_STATE"  # ucdef int _8 "8" bits
    cdef int _ATTR_SNAT_IPV4 "ATTR_SNAT_IPV4"  # ucdef int _32 "32" bits
    cdef int _ATTR_DNAT_IPV4 "ATTR_DNAT_IPV4"  # ucdef int _32 "32" bits
    cdef int _ATTR_SNAT_PORT "ATTR_SNAT_PORT"  # ucdef int _16 "16" bits
    cdef int _ATTR_DNAT_PORT "ATTR_DNAT_PORT"  # ucdef int _16 "16" bits
    cdef int _ATTR_TIMEOUT "ATTR_TIMEOUT"  # ucdef int _32 "32" bits
    cdef int _ATTR_MARK "ATTR_MARK"  # ucdef int _32 "32" bits
    cdef int _ATTR_ORIG_COUNTER_PACKETS "ATTR_ORIG_COUNTER_PACKETS"  # ucdef int _32 "32" bits
    cdef int _ATTR_REPL_COUNTER_PACKETS "ATTR_REPL_COUNTER_PACKETS"  # ucdef int _32 "32" bits
    cdef int _ATTR_ORIG_COUNTER_BYTES "ATTR_ORIG_COUNTER_BYTES"  # ucdef int _32 "32" bits
    cdef int _ATTR_REPL_COUNTER_BYTES "ATTR_REPL_COUNTER_BYTES"  # ucdef int _32 "32" bits
    cdef int _ATTR_USE "ATTR_USE"  # ucdef int _32 "32" bits
    cdef int _ATTR_ID "ATTR_ID"  # ucdef int _32 "32" bits
    cdef int _ATTR_STATUS "ATTR_STATUS"  # ucdef int _32 "32" bits
    cdef int _ATTR_TCP_FLAGS_ORIG "ATTR_TCP_FLAGS_ORIG"  # ucdef int _8 "8" bits
    cdef int _ATTR_TCP_FLAGS_REPL "ATTR_TCP_FLAGS_REPL"  # ucdef int _8 "8" bits
    cdef int _ATTR_TCP_MASK_ORIG "ATTR_TCP_MASK_ORIG"  # ucdef int _8 "8" bits
    cdef int _ATTR_TCP_MASK_REPL "ATTR_TCP_MASK_REPL"  # ucdef int _8 "8" bits
    cdef int _ATTR_MASTER_IPV4_SRC "ATTR_MASTER_IPV4_SRC"  # ucdef int _32 "32" bits
    cdef int _ATTR_MASTER_IPV4_DST "ATTR_MASTER_IPV4_DST"  # ucdef int _32 "32" bits
    cdef int _ATTR_MASTER_IPV6_SRC "ATTR_MASTER_IPV6_SRC"  # ucdef int _128 "128" bits
    cdef int _ATTR_MASTER_IPV6_DST "ATTR_MASTER_IPV6_DST"  # ucdef int _128 "128" bits
    cdef int _ATTR_MASTER_PORT_SRC "ATTR_MASTER_PORT_SRC"  # ucdef int _16 "16" bits
    cdef int _ATTR_MASTER_PORT_DST "ATTR_MASTER_PORT_DST"  # ucdef int _16 "16" bits
    cdef int _ATTR_MASTER_L3PROTO "ATTR_MASTER_L3PROTO"  # ucdef int _8 "8" bits
    cdef int _ATTR_MASTER_L4PROTO "ATTR_MASTER_L4PROTO"  # ucdef int _8 "8" bits
    cdef int _ATTR_SECMARK "ATTR_SECMARK"  # ucdef int _32 "32" bits
    cdef int _ATTR_ORIG_NAT_SEQ_CORRECTION_POS "ATTR_ORIG_NAT_SEQ_CORRECTION_POS"  # ucdef int _32 "32" bits
    cdef int _ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE "ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE"  # ucdef int _32 "32" bits
    cdef int _ATTR_ORIG_NAT_SEQ_OFFSET_AFTER "ATTR_ORIG_NAT_SEQ_OFFSET_AFTER"  # ucdef int _32 "32" bits
    cdef int _ATTR_REPL_NAT_SEQ_CORRECTION_POS "ATTR_REPL_NAT_SEQ_CORRECTION_POS"  # ucdef int _32 "32" bits
    cdef int _ATTR_REPL_NAT_SEQ_OFFSET_BEFORE "ATTR_REPL_NAT_SEQ_OFFSET_BEFORE"  # ucdef int _32 "32" bits
    cdef int _ATTR_REPL_NAT_SEQ_OFFSET_AFTER "ATTR_REPL_NAT_SEQ_OFFSET_AFTER"  # ucdef int _32 "32" bits
    cdef int _ATTR_SCTP_STATE "ATTR_SCTP_STATE"  # ucdef int _8 "8" bits
    cdef int _ATTR_SCTP_VTAG_ORIG "ATTR_SCTP_VTAG_ORIG"  # ucdef int _32 "32" bits
    cdef int _ATTR_SCTP_VTAG_REPL "ATTR_SCTP_VTAG_REPL"  # ucdef int _32 "32" bits
    cdef int _ATTR_HELPER_NAME "ATTR_HELPER_NAME"  # string (cdef int _30 "30" bytes max)
    cdef int _ATTR_DCCP_STATE "ATTR_DCCP_STATE"  # ucdef int _8 "8" bits
    cdef int _ATTR_DCCP_ROLE "ATTR_DCCP_ROLE"  # ucdef int _8 "8" bits
    cdef int _ATTR_DCCP_HANDSHAKE_SEQ "ATTR_DCCP_HANDSHAKE_SEQ"  # ucdef int _64 "64" bits
    cdef int _ATTR_MAX "ATTR_MAX"
    cdef int _ATTR_GRP_ORIG_IPV4 "ATTR_GRP_ORIG_IPV4"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ipvcdef int _4 "4"
    cdef int _ATTR_GRP_REPL_IPV4 "ATTR_GRP_REPL_IPV4"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ipvcdef int _4 "4"
    cdef int _ATTR_GRP_ORIG_IPV6 "ATTR_GRP_ORIG_IPV6"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ipvcdef int _6 "6"
    cdef int _ATTR_GRP_REPL_IPV6 "ATTR_GRP_REPL_IPV6"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ipvcdef int _6 "6"
    cdef int _ATTR_GRP_ORIG_PORT "ATTR_GRP_ORIG_PORT"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"port
    cdef int _ATTR_GRP_REPL_PORT "ATTR_GRP_REPL_PORT"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"port
    cdef int _ATTR_GRP_ICMP "ATTR_GRP_ICMP"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"icmp
    cdef int _ATTR_GRP_MASTER_IPV4 "ATTR_GRP_MASTER_IPV4"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ipvcdef int _4 "4"
    cdef int _ATTR_GRP_MASTER_IPV6 "ATTR_GRP_MASTER_IPV6"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ipvcdef int _6 "6"
    cdef int _ATTR_GRP_MASTER_PORT "ATTR_GRP_MASTER_PORT"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"port
    cdef int _ATTR_GRP_ORIG_COUNTERS "ATTR_GRP_ORIG_COUNTERS"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ctrs
    cdef int _ATTR_GRP_REPL_COUNTERS "ATTR_GRP_REPL_COUNTERS"  # struct nfctcdef int __ "_"attrcdef int __ "_"grpcdef int __ "_"ctrs
    cdef int _ATTR_GRP_MAX "ATTR_GRP_MAX"
    cdef int _ATTR_EXP_MASTER "ATTR_EXP_MASTER"  # pointer to conntrack object
    cdef int _ATTR_EXP_EXPECTED "ATTR_EXP_EXPECTED"  # pointer to conntrack object
    cdef int _ATTR_EXP_MASK "ATTR_EXP_MASK"  # pointer to conntrack object
    cdef int _ATTR_EXP_TIMEOUT "ATTR_EXP_TIMEOUT"  # ucdef int _32 "32" bits
    cdef int _ATTR_EXP_MAX "ATTR_EXP_MAX"

    # message type
    cdef int _NFCT_T_UNKNOWN "NFCT_T_UNKNOWN"
    cdef int _NFCT_T_NEW_BIT "NFCT_T_NEW_BIT"
    cdef int _NFCT_T_NEW "NFCT_T_NEW"
    cdef int _NFCT_T_UPDATE_BIT "NFCT_T_UPDATE_BIT"
    cdef int _NFCT_T_UPDATE "NFCT_T_UPDATE"
    cdef int _NFCT_T_DESTROY_BIT "NFCT_T_DESTROY_BIT"
    cdef int _NFCT_T_DESTROY "NFCT_T_DESTROY"

    cdef int _NFCT_T_ALL "NFCT_T_ALL"
    cdef int _NFCT_T_ERROR_BIT "NFCT_T_ERROR_BIT"
    cdef int _NFCT_T_ERROR "NFCT_T_ERROR"

    cdef int _NFCT_FILTER_DUMP_MARK "NFCT_FILTER_DUMP_MARK"
    cdef int _NFCT_FILTER_DUMP_L3NUM "NFCT_FILTER_DUMP_L3NUM"
    cdef int _NFCT_FILTER_DUMP_MAX "NFCT_FILTER_DUMP_MAX"

    cdef int _NFCT_CP_ALL "NFCT_CP_ALL"
    cdef int _NFCT_CP_ORIG "NFCT_CP_ORIG"
    cdef int _NFCT_CP_REPL "NFCT_CP_REPL"
    cdef int _NFCT_CP_META "NFCT_CP_META"

# nfct_open
NFNL_SUBSYS_CTNETLINK = _NFNL_SUBSYS_CTNETLINK

# netlink groups
NF_NETLINK_CONNTRACK_NEW = _NF_NETLINK_CONNTRACK_NEW
NF_NETLINK_CONNTRACK_UPDATE = _NF_NETLINK_CONNTRACK_UPDATE
NF_NETLINK_CONNTRACK_DESTROY = _NF_NETLINK_CONNTRACK_DESTROY
NF_NETLINK_CONNTRACK_EXP_NEW = _NF_NETLINK_CONNTRACK_EXP_NEW
NF_NETLINK_CONNTRACK_EXP_UPDATE = _NF_NETLINK_CONNTRACK_EXP_UPDATE
NF_NETLINK_CONNTRACK_EXP_DESTROY = _NF_NETLINK_CONNTRACK_EXP_DESTROY

NFCT_ALL_CT_GROUPS = _NFCT_ALL_CT_GROUPS

# nfct_ = __*printf output format
NFCT_O_PLAIN = _NFCT_O_PLAIN
NFCT_O_DEFAULT = _NFCT_O_DEFAULT
NFCT_O_XML = _NFCT_O_XML
NFCT_O_MAX = _NFCT_O_MAX

# output flags
NFCT_OF_SHOW_LAYER3_BIT = _NFCT_OF_SHOW_LAYER3_BIT
NFCT_OF_SHOW_LAYER3 = _NFCT_OF_SHOW_LAYER3
NFCT_OF_TIME_BIT = _NFCT_OF_TIME_BIT
NFCT_OF_TIME = _NFCT_OF_TIME
NFCT_OF_ID_BIT = _NFCT_OF_ID_BIT
NFCT_OF_ID = _NFCT_OF_ID

# query
NFCT_Q_CREATE = _NFCT_Q_CREATE
NFCT_Q_UPDATE = _NFCT_Q_UPDATE
NFCT_Q_DESTROY = _NFCT_Q_DESTROY
NFCT_Q_GET = _NFCT_Q_GET
NFCT_Q_FLUSH = _NFCT_Q_FLUSH
NFCT_Q_DUMP = _NFCT_Q_DUMP
NFCT_Q_DUMP_RESET = _NFCT_Q_DUMP_RESET
NFCT_Q_CREATE_UPDATE = _NFCT_Q_CREATE_UPDATE
NFCT_Q_DUMP_FILTER = _NFCT_Q_DUMP_FILTER
NFCT_Q_DUMP_FILTER_RESET = _NFCT_Q_DUMP_FILTER_RESET

# callback return code
NFCT_CB_FAILURE = _NFCT_CB_FAILURE # failure
NFCT_CB_STOP = _NFCT_CB_STOP # stop the query
NFCT_CB_CONTINUE = _NFCT_CB_CONTINUE # keep iterating through data
NFCT_CB_STOLEN = _NFCT_CB_STOLEN # like continue, but ct is not freed

NFCT_CMP_ALL = _NFCT_CMP_ALL
NFCT_CMP_ORIG = _NFCT_CMP_ORIG
NFCT_CMP_REPL = _NFCT_CMP_REPL
NFCT_CMP_TIMEOUT_EQ = _NFCT_CMP_TIMEOUT_EQ
NFCT_CMP_TIMEOUT_GT = _NFCT_CMP_TIMEOUT_GT
NFCT_CMP_TIMEOUT_GE = _NFCT_CMP_TIMEOUT_GE
NFCT_CMP_TIMEOUT_LT = _NFCT_CMP_TIMEOUT_LT
NFCT_CMP_TIMEOUT_LE = _NFCT_CMP_TIMEOUT_LE
NFCT_CMP_MASK = _NFCT_CMP_MASK
NFCT_CMP_STRICT = _NFCT_CMP_STRICT

# get option
NFCT_GOPT_IS_SNAT = _NFCT_GOPT_IS_SNAT
NFCT_GOPT_IS_DNAT = _NFCT_GOPT_IS_DNAT
NFCT_GOPT_IS_SPAT = _NFCT_GOPT_IS_SPAT
NFCT_GOPT_IS_DPAT = _NFCT_GOPT_IS_DPAT
NFCT_GOPT_MAX = _NFCT_GOPT_MAX

# set option
NFCT_SOPT_UNDO_SNAT = _NFCT_SOPT_UNDO_SNAT
NFCT_SOPT_UNDO_DNAT = _NFCT_SOPT_UNDO_DNAT
NFCT_SOPT_UNDO_SPAT = _NFCT_SOPT_UNDO_SPAT
NFCT_SOPT_UNDO_DPAT = _NFCT_SOPT_UNDO_DPAT
NFCT_SOPT_MAX = _NFCT_SOPT_MAX

# attributes
ATTR_ORIG_IPV4_SRC = _ATTR_ORIG_IPV4_SRC # u32 = _32 bits
ATTR_IPV4_SRC = _ATTR_IPV4_SRC # alias
ATTR_ORIG_IPV4_DST = _ATTR_ORIG_IPV4_DST  # u32 = _32 bits
ATTR_IPV4_DST = _ATTR_IPV4_DST  # alias
ATTR_REPL_IPV4_SRC = _ATTR_REPL_IPV4_SRC  # u32 = _32 bits
ATTR_REPL_IPV4_DST = _ATTR_REPL_IPV4_DST  # u32 = _32 bits
ATTR_ORIG_IPV6_SRC = _ATTR_ORIG_IPV6_SRC  # u128 = _128 bits
ATTR_IPV6_SRC = _ATTR_IPV6_SRC  # alias
ATTR_ORIG_IPV6_DST = _ATTR_ORIG_IPV6_DST  # u128 = _128 bits
ATTR_IPV6_DST = _ATTR_IPV6_DST  # alias
ATTR_REPL_IPV6_SRC = _ATTR_REPL_IPV6_SRC  # u128 = _128 bits
ATTR_REPL_IPV6_DST = _ATTR_REPL_IPV6_DST  # u128 = _128 bits
ATTR_ORIG_PORT_SRC = _ATTR_ORIG_PORT_SRC  # u16 = _16 bits
ATTR_PORT_SRC = _ATTR_PORT_SRC  # alias
ATTR_ORIG_PORT_DST = _ATTR_ORIG_PORT_DST  # u16 = _16 bits
ATTR_PORT_DST = _ATTR_PORT_DST  # alias
ATTR_REPL_PORT_SRC = _ATTR_REPL_PORT_SRC  # u16 = _16 bits
ATTR_REPL_PORT_DST = _ATTR_REPL_PORT_DST  # u16 = _16 bits
ATTR_ICMP_TYPE = _ATTR_ICMP_TYPE  # u8 = _8 bits
ATTR_ICMP_CODE = _ATTR_ICMP_CODE  # u8 = _8 bits
ATTR_ICMP_ID = _ATTR_ICMP_ID  # u16 = _16 bits
ATTR_ORIG_L3PROTO = _ATTR_ORIG_L3PROTO  # u8 = _8 bits
ATTR_L3PROTO = _ATTR_L3PROTO  # alias
ATTR_REPL_L3PROTO = _ATTR_REPL_L3PROTO  # u8 = _8 bits
ATTR_ORIG_L4PROTO = _ATTR_ORIG_L4PROTO  # u8 = _8 bits
ATTR_L4PROTO = _ATTR_L4PROTO  # alias
ATTR_REPL_L4PROTO = _ATTR_REPL_L4PROTO  # u8 = _8 bits
ATTR_TCP_STATE = _ATTR_TCP_STATE  # u8 = _8 bits
ATTR_SNAT_IPV4 = _ATTR_SNAT_IPV4  # u32 = _32 bits
ATTR_DNAT_IPV4 = _ATTR_DNAT_IPV4  # u32 = _32 bits
ATTR_SNAT_PORT = _ATTR_SNAT_PORT  # u16 = _16 bits
ATTR_DNAT_PORT = _ATTR_DNAT_PORT  # u16 = _16 bits
ATTR_TIMEOUT = _ATTR_TIMEOUT  # u32 = _32 bits
ATTR_MARK = _ATTR_MARK  # u32 = _32 bits
ATTR_ORIG_COUNTER_PACKETS = _ATTR_ORIG_COUNTER_PACKETS  # u32 = _32 bits
ATTR_REPL_COUNTER_PACKETS = _ATTR_REPL_COUNTER_PACKETS  # u32 = _32 bits
ATTR_ORIG_COUNTER_BYTES = _ATTR_ORIG_COUNTER_BYTES  # u32 = _32 bits
ATTR_REPL_COUNTER_BYTES = _ATTR_REPL_COUNTER_BYTES  # u32 = _32 bits
ATTR_USE = _ATTR_USE  # u32 = _32 bits
ATTR_ID = _ATTR_ID  # u32 = _32 bits
ATTR_STATUS = _ATTR_STATUS  # u32 = _32 bits
ATTR_TCP_FLAGS_ORIG = _ATTR_TCP_FLAGS_ORIG  # u8 = _8 bits
ATTR_TCP_FLAGS_REPL = _ATTR_TCP_FLAGS_REPL  # u8 = _8 bits
ATTR_TCP_MASK_ORIG = _ATTR_TCP_MASK_ORIG  # u8 = _8 bits
ATTR_TCP_MASK_REPL = _ATTR_TCP_MASK_REPL  # u8 = _8 bits
ATTR_MASTER_IPV4_SRC = _ATTR_MASTER_IPV4_SRC  # u32 = _32 bits
ATTR_MASTER_IPV4_DST = _ATTR_MASTER_IPV4_DST  # u32 = _32 bits
ATTR_MASTER_IPV6_SRC = _ATTR_MASTER_IPV6_SRC  # u128 = _128 bits
ATTR_MASTER_IPV6_DST = _ATTR_MASTER_IPV6_DST  # u128 = _128 bits
ATTR_MASTER_PORT_SRC = _ATTR_MASTER_PORT_SRC  # u16 = _16 bits
ATTR_MASTER_PORT_DST = _ATTR_MASTER_PORT_DST  # u16 = _16 bits
ATTR_MASTER_L3PROTO = _ATTR_MASTER_L3PROTO  # u8 = _8 bits
ATTR_MASTER_L4PROTO = _ATTR_MASTER_L4PROTO  # u8 = _8 bits
ATTR_SECMARK = _ATTR_SECMARK  # u32 = _32 bits
ATTR_ORIG_NAT_SEQ_CORRECTION_POS = _ATTR_ORIG_NAT_SEQ_CORRECTION_POS  # u32 = _32 bits
ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE = _ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE  # u32 = _32 bits
ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = _ATTR_ORIG_NAT_SEQ_OFFSET_AFTER  # u32 = _32 bits
ATTR_REPL_NAT_SEQ_CORRECTION_POS = _ATTR_REPL_NAT_SEQ_CORRECTION_POS  # u32 = _32 bits
ATTR_REPL_NAT_SEQ_OFFSET_BEFORE = _ATTR_REPL_NAT_SEQ_OFFSET_BEFORE  # u32 = _32 bits
ATTR_REPL_NAT_SEQ_OFFSET_AFTER = _ATTR_REPL_NAT_SEQ_OFFSET_AFTER  # u32 = _32 bits
ATTR_SCTP_STATE = _ATTR_SCTP_STATE  # u8 = _8 bits
ATTR_SCTP_VTAG_ORIG = _ATTR_SCTP_VTAG_ORIG  # u32 = _32 bits
ATTR_SCTP_VTAG_REPL = _ATTR_SCTP_VTAG_REPL  # u32 = _32 bits
ATTR_HELPER_NAME = _ATTR_HELPER_NAME  # string (30 = _30 bytes max)
ATTR_DCCP_STATE = _ATTR_DCCP_STATE  # u8 = _8 bits
ATTR_DCCP_ROLE = _ATTR_DCCP_ROLE  # u8 = _8 bits
ATTR_DCCP_HANDSHAKE_SEQ = _ATTR_DCCP_HANDSHAKE_SEQ  # u64 = _64 bits
ATTR_MAX = _ATTR_MAX
ATTR_GRP_ORIG_IPV4 = _ATTR_GRP_ORIG_IPV4  # struct nfct_ = __attr_ = __grp_ = __ipv4 = _4
ATTR_GRP_REPL_IPV4 = _ATTR_GRP_REPL_IPV4  # struct nfct_ = __attr_ = __grp_ = __ipv4 = _4
ATTR_GRP_ORIG_IPV6 = _ATTR_GRP_ORIG_IPV6  # struct nfct_ = __attr_ = __grp_ = __ipv6 = _6
ATTR_GRP_REPL_IPV6 = _ATTR_GRP_REPL_IPV6  # struct nfct_ = __attr_ = __grp_ = __ipv6 = _6
ATTR_GRP_ORIG_PORT = _ATTR_GRP_ORIG_PORT  # struct nfct_ = __attr_ = __grp_ = __port
ATTR_GRP_REPL_PORT = _ATTR_GRP_REPL_PORT  # struct nfct_ = __attr_ = __grp_ = __port
ATTR_GRP_ICMP = _ATTR_GRP_ICMP  # struct nfct_ = __attr_ = __grp_ = __icmp
ATTR_GRP_MASTER_IPV4 = _ATTR_GRP_MASTER_IPV4  # struct nfct_ = __attr_ = __grp_ = __ipv4 = _4
ATTR_GRP_MASTER_IPV6 = _ATTR_GRP_MASTER_IPV6  # struct nfct_ = __attr_ = __grp_ = __ipv6 = _6
ATTR_GRP_MASTER_PORT = _ATTR_GRP_MASTER_PORT  # struct nfct_ = __attr_ = __grp_ = __port
ATTR_GRP_ORIG_COUNTERS = _ATTR_GRP_ORIG_COUNTERS  # struct nfct_ = __attr_ = __grp_ = __ctrs
ATTR_GRP_REPL_COUNTERS = _ATTR_GRP_REPL_COUNTERS  # struct nfct_ = __attr_ = __grp_ = __ctrs
ATTR_GRP_MAX = _ATTR_GRP_MAX
ATTR_EXP_MASTER = _ATTR_EXP_MASTER  # pointer to conntrack object
ATTR_EXP_EXPECTED = _ATTR_EXP_EXPECTED  # pointer to conntrack object
ATTR_EXP_MASK = _ATTR_EXP_MASK  # pointer to conntrack object
ATTR_EXP_TIMEOUT = _ATTR_EXP_TIMEOUT  # u32 = _32 bits
ATTR_EXP_MAX = _ATTR_EXP_MAX

# message type
NFCT_T_UNKNOWN = _NFCT_T_UNKNOWN
NFCT_T_NEW_BIT = _NFCT_T_NEW_BIT
NFCT_T_NEW = _NFCT_T_NEW
NFCT_T_UPDATE_BIT = _NFCT_T_UPDATE_BIT
NFCT_T_UPDATE = _NFCT_T_UPDATE
NFCT_T_DESTROY_BIT = _NFCT_T_DESTROY_BIT
NFCT_T_DESTROY = _NFCT_T_DESTROY

NFCT_T_ALL = _NFCT_T_ALL
NFCT_T_ERROR_BIT = _NFCT_T_ERROR_BIT
NFCT_T_ERROR = _NFCT_T_ERROR

NFCT_FILTER_DUMP_MARK = _NFCT_FILTER_DUMP_MARK
NFCT_FILTER_DUMP_L3NUM = _NFCT_FILTER_DUMP_L3NUM
NFCT_FILTER_DUMP_MAX = _NFCT_FILTER_DUMP_MAX

NFCT_CP_ALL = _NFCT_CP_ALL
NFCT_CP_ORIG = _NFCT_CP_ORIG
NFCT_CP_REPL = _NFCT_CP_REPL
NFCT_CP_META = _NFCT_CP_META

# conntrack options from conntrack-tools/src/conntrack.c
CT_OPT_ORIG_SRC_BIT = 0
CT_OPT_ORIG_SRC     = (1 << CT_OPT_ORIG_SRC_BIT)

CT_OPT_ORIG_DST_BIT = 1
CT_OPT_ORIG_DST     = (1 << CT_OPT_ORIG_DST_BIT)

CT_OPT_ORIG     = (CT_OPT_ORIG_SRC | CT_OPT_ORIG_DST)

CT_OPT_REPL_SRC_BIT = 2
CT_OPT_REPL_SRC     = (1 << CT_OPT_REPL_SRC_BIT)

CT_OPT_REPL_DST_BIT = 3
CT_OPT_REPL_DST     = (1 << CT_OPT_REPL_DST_BIT)

CT_OPT_REPL     = (CT_OPT_REPL_SRC | CT_OPT_REPL_DST)

CT_OPT_PROTO_BIT    = 4
CT_OPT_PROTO        = (1 << CT_OPT_PROTO_BIT)

CT_OPT_TUPLE_ORIG   = (CT_OPT_ORIG | CT_OPT_PROTO)
CT_OPT_TUPLE_REPL   = (CT_OPT_REPL | CT_OPT_PROTO)

CT_OPT_TIMEOUT_BIT  = 5
CT_OPT_TIMEOUT      = (1 << CT_OPT_TIMEOUT_BIT)

CT_OPT_STATUS_BIT   = 6
CT_OPT_STATUS       = (1 << CT_OPT_STATUS_BIT)

CT_OPT_ZERO_BIT     = 7
CT_OPT_ZERO     = (1 << CT_OPT_ZERO_BIT)

CT_OPT_EVENT_MASK_BIT   = 8
CT_OPT_EVENT_MASK   = (1 << CT_OPT_EVENT_MASK_BIT)

CT_OPT_EXP_SRC_BIT  = 9
CT_OPT_EXP_SRC      = (1 << CT_OPT_EXP_SRC_BIT)

CT_OPT_EXP_DST_BIT  = 10
CT_OPT_EXP_DST      = (1 << CT_OPT_EXP_DST_BIT)

CT_OPT_MASK_SRC_BIT = 11
CT_OPT_MASK_SRC     = (1 << CT_OPT_MASK_SRC_BIT)

CT_OPT_MASK_DST_BIT = 12
CT_OPT_MASK_DST     = (1 << CT_OPT_MASK_DST_BIT)

CT_OPT_NATRANGE_BIT = 13
CT_OPT_NATRANGE     = (1 << CT_OPT_NATRANGE_BIT)

CT_OPT_MARK_BIT     = 14
CT_OPT_MARK     = (1 << CT_OPT_MARK_BIT)

CT_OPT_ID_BIT       = 15
CT_OPT_ID       = (1 << CT_OPT_ID_BIT)

CT_OPT_FAMILY_BIT   = 16
CT_OPT_FAMILY       = (1 << CT_OPT_FAMILY_BIT)

CT_OPT_SRC_NAT_BIT  = 17
CT_OPT_SRC_NAT      = (1 << CT_OPT_SRC_NAT_BIT)

CT_OPT_DST_NAT_BIT  = 18
CT_OPT_DST_NAT      = (1 << CT_OPT_DST_NAT_BIT)

CT_OPT_OUTPUT_BIT   = 19
CT_OPT_OUTPUT       = (1 << CT_OPT_OUTPUT_BIT)

CT_OPT_SECMARK_BIT  = 20
CT_OPT_SECMARK      = (1 << CT_OPT_SECMARK_BIT)

CT_OPT_BUFFERSIZE_BIT   = 21
CT_OPT_BUFFERSIZE   = (1 << CT_OPT_BUFFERSIZE_BIT)
