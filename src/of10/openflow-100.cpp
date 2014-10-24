/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2013 LittleField
 *   -- add and complete it
 */

#define OPENFLOW_INTERNAL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <of10/openflow-100.hpp>
#include <openflow-common.hpp>
#include "openflow/of10.h"
#include "field_type.hpp"

#define PROTO_TAG_OPENFLOW_VER "OFP10"

namespace openflow_100
{

DissectorContext * DissectorContext::mSingle = NULL;
DissectorContext * Context;

DissectorContext *DissectorContext::getInstance(int proto_openflow)
{
    if (mSingle == NULL) {
        mSingle = new DissectorContext(proto_openflow);
    }

    return mSingle;
}

void DissectorContext::setHandles(dissector_handle_t data, dissector_handle_t openflow)
{
    this->mDataHandle = data;
    this->mOpenflowHandle = openflow;
}

void DissectorContext::prepDissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW_VER);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    Context->dispatchMessage(tvb, pinfo, tree);
}

void DissectorContext::dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, DissectorContext::getMessageLen,
        DissectorContext::prepDissect);
}

guint DissectorContext::getMessageLen(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    // 0-7    version
    // 8-15   type
    // 16-31  length
    return (guint)tvb_get_ntohs(tvb, offset + 2);
}

DissectorContext::DissectorContext(int proto_openflow)
    : mProtoOpenflow(proto_openflow), mFM(proto_openflow, "of10")
{
    Context = this;

    this->_ether_handle = find_dissector("eth_withoutfcs");
    this->setupCodes();
    this->setupFlags();
    this->setupFields();

    this->mFM.doRegister();
}

void init(int proto_openflow)
{
    DissectorContext::getInstance(proto_openflow);
}

void DissectorContext::dispatchMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    this->_offset = 0;
    this->_tvb = tvb;
    this->_pinfo = pinfo;
    this->_tree = tree;

    this->_rawLen = tvb_length_remaining(tvb, 0);

    guint8 type = tvb_get_guint8(this->_tvb, 1);
    this->_oflen = tvb_get_ntohs(this->_tvb, 2);

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
        val_to_str(type, (value_string*) this->ofp_type->data, "Unknown Type (0x%02x)"));

    if (this->_tree) {
        this->_curOFPSubtree = this->mFM.addSubtree(tree, "data", this->_tvb, 0, -1);
        proto_tree *hdr_tree = this->mFM.addSubtree(this->_curOFPSubtree, "header", this->_tvb, this->_offset, 8);

        ADD_CHILD(hdr_tree, "version", 1);
        ADD_CHILD(hdr_tree, "type", 1);
        ADD_CHILD(hdr_tree, "length", 2);
        ADD_CHILD(hdr_tree, "xid", 4);

        if (this->_oflen > this->_rawLen) {
            this->_oflen = this->_rawLen;
        }

        #define IGNORE this->_offset = this->_oflen
        if (this->_oflen > this->_offset) {
            switch (type) {
            case OFPT_HELLO:
                IGNORE; // Nothing to parse
                break;

            case OFPT_ERROR:
                this->dissect_ofp_error();
                break;

            case OFPT_VENDOR:
                this->dissect_ofp_vendor();
                break;
            case OFPT_ECHO_REQUEST:
            case OFPT_ECHO_REPLY:
                this->dissect_ofp_echo();
                break;

            case OFPT_FEATURES_REQUEST:
                this->dissect_ofp_features_request();
                break;

            case OFPT_FEATURES_REPLY:
                this->dissect_ofp_switch_features();
                break;

            case OFPT_GET_CONFIG_REQUEST:
                IGNORE; // Not yet implemented
                break;

            case OFPT_GET_CONFIG_REPLY:
            case OFPT_SET_CONFIG:
                this->dissect_ofp_set_config();
                break;

            case OFPT_PACKET_IN:
                this->dissect_ofp_packet_in();
                break;

            case OFPT_FLOW_REMOVED:
                this->dissect_ofp_flow_remove();
                break;

            case OFPT_PORT_STATUS:
                this->dissect_ofp_port_status();
                break;

            case OFPT_PACKET_OUT:
                this->dissect_ofp_packet_out();
                break;

            case OFPT_FLOW_MOD:
                this->dissect_ofp_flow_mod();
                break;

            case OFPT_PORT_MOD:
                this->dissect_ofp_port_mod();
                break;

            case OFPT_STATS_REQUEST:
                this->dissect_ofp_stats_request();
                break;

            case OFPT_STATS_REPLY:
                this->dissect_ofp_stats_reply();
                break;

            case OFPT_BARRIER_REQUEST:
            case OFPT_BARRIER_REPLY:
                IGNORE; // Nothing to parse
                break;

            case OFPT_QUEUE_GET_CONFIG_REQUEST:
                this->dissect_ofp_queue_get_config_request();
                break;
            case OFPT_QUEUE_GET_CONFIG_REPLY:
                this->dissect_ofp_queue_get_config_reply();
                break;

            default:
                IGNORE; // We don't know what to do
            }

        } /* end if if (this->_oflen > this->_offset) */
    } /* end of if (this->_tree) */
}

void DissectorContext::dissect_ofp_error()
{
    ADD_TREE(tree, "ofp_error");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_error.type", 2);

    #define STR(a) #a
    #define ERROR(value) \
    case value: \
        ADD_CHILD(tree, STR(ofp_error.code.value), 2); \
        break;

    // TODO: this can improve...
    switch (type) {
        ERROR(OFPET_HELLO_FAILED)
        ERROR(OFPET_BAD_REQUEST)
        ERROR(OFPET_BAD_ACTION)
        ERROR(OFPET_FLOW_MOD_FAILED)
        ERROR(OFPET_PORT_MOD_FAILED)
        ERROR(OFPET_QUEUE_OP_FAILED)
        default:
            break;
    }

    if (this->_oflen - this->_offset > 0) {
        ADD_OFDISSECTOR(tree, "ofp_error.data", this->_oflen - this->_offset);
    } else {
        ADD_CHILD(tree, "ofp_error.data", this->_oflen - this->_offset);
    }
}

void DissectorContext::dissect_ofp_echo()
{
    ADD_CHILD(this->_curOFPSubtree, "echo", this->_oflen - this->_offset);
    this->_offset = this->_oflen;
}

void DissectorContext::dissect_ofp_vendor()
{
    ADD_TREE(tree, "ofp_vendor_header");
    ADD_CHILD(tree, "ofp_vendor_header.vendor", 4);
    ADD_CHILD(tree, "ofp_vendor_header.body", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_features_request()
{
    ADD_CHILD(this->_curOFPSubtree, "ofp_feature_request", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_switch_features()
{
    ADD_TREE(tree, "ofp_switch_features");

    ADD_CHILD(tree, "ofp_switch_features.datapath_id", 8);
    ADD_CHILD(tree, "ofp_switch_features.n_buffers", 4);
    ADD_CHILD(tree, "ofp_switch_features.n_tables", 1);
    ADD_CHILD(tree, "padding", 3);

    READ_UINT32(capabilities);
    ADD_SUBTREE(capabilities_tree, tree, "ofp_switch_features.capabilities", 4);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_FLOW_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_TABLE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_PORT_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_STP", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_RESERVED", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_IP_REASM", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_QUEUE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_ARP_MATCH_IP", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.RESERVED", 4, capabilities);
    CONSUME_BYTES(4);

    READ_UINT32(actions);
    ADD_SUBTREE(actions_tree, tree, "ofp_switch_features.actions", 4);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_OUTPUT", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_VLAN_VID", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_VLAN_PCP", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_STRIP_VLAN", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_DL_SRC", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_DL_DST", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_NW_SRC", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_NW_DST", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_NW_TOS", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_TP_SRC", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_SET_TP_DST", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_ENQUEUE", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.OFPAT_VENDOR", 4, actions);
    ADD_BOOLEAN(actions_tree, "ofp_action_type_bmp.RESERVED", 4, actions);
    CONSUME_BYTES(4);

    // Ports
    // TODO: shouldn't we use a while like in other parts?
    guint32 portlen = this->_oflen - 32;

    if (portlen < 0 || portlen % 48 != 0) {
        // Packet alignment is off, we should probably complain
    } else {
        guint32 ports =  portlen / 48;
        ADD_SUBTREE(port_tree, tree, "ofp_switch_features.ports", portlen);
        ADD_UINT(port_tree, "ofp_switch_features.port_num", 4, ports);
        for (int port = 0; port < ports; ++port) {
            this->dissect_ofp_port(port_tree);
        }
    }
}

void DissectorContext::dissect_ofp_set_config(void)
{
    ADD_TREE(tree, "ofp_switch_config");

    //ADD_CHILD(tree, "ofp_switch_config.flags", 2);
    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_switch_config.flags", 2);
    if (flags == 0) {
        ADD_UINT(flags_tree, "ofp_config_flags.OFPC_FRAG_NORMAL", 2, flags);
    } else {
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.RESERVED", 2, flags);
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_FRAG_DROP", 2, flags);
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_FRAG_REASM", 2, flags);
    }
    CONSUME_BYTES(2);
    ADD_CHILD(tree, "ofp_switch_config.miss_send_len", 2);
}

void DissectorContext::dissect_ofp_packet_in()
{
    ADD_TREE(tree, "ofp_packet_in");

    ADD_CHILD(tree, "ofp_packet_in.buffer_id", 4);
    ADD_CHILD(tree, "ofp_packet_in.total_len", 2);
    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_packet_in.in_port", portid, 2);
    ADD_CHILD(tree, "ofp_packet_in.reason", 1);
    ADD_CHILD(tree, "padding", 1);

    if (this->_oflen - this->_offset > 0) {
        ADD_DISSECTOR(tree, "ofp_packet_in.data", this->_oflen - this->_offset);
    } else {
        ADD_CHILD(tree, "ofp_packet_in.data", this->_oflen - this->_offset);
    }
}

void DissectorContext::dissect_ofp_packet_out()
{
    ADD_TREE(tree, "ofp_packet_out");

    ADD_CHILD(tree, "ofp_packet_out.buffer_id", 4);
    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_packet_out.in_port", portid, 2);
    READ_UINT16(actions_len);
    ADD_CHILD(tree, "ofp_packet_out.actions_len", 2);

    int end = this->_offset + actions_len;
    while (this->_offset < end) {
        dissect_ofp_action(tree);
    }

    if (this->_oflen - this->_offset > 0) {
        ADD_DISSECTOR(tree, "ofp_packet_out.data", this->_oflen - this->_offset);
    } else {
        ADD_CHILD(tree, "ofp_packet_out.data", this->_oflen - this->_offset);
    }
}

void DissectorContext::dissect_ofp_wildcards(proto_tree *tree, guint32 wildcards)
{
#if 0
    guint32 sipmask, dipmask;

    sipmask = (wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT;
    dipmask = (wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT;

    //This creates the wildcards as the standard bit-tree view in the UI
    ADD_SUBTREE(wct, tree, "ofp_match.wildcards", 4);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_IN_PORT", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_SRC", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_DST", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_TYPE", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_NW_PROTO", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_TP_SRC", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_TP_DST", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_NW_SRC_MASK", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_NW_DST_MASK", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN_PCP", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_NW_TOS", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.RESERVED", 4, wildcards);
    ADD_UINT(wct, "ofp_flow_wildcards.src_ip_mask", 4, sipmask);
    ADD_UINT(wct, "ofp_flow_wildcards.dst_ip_mask", 4, dipmask);
#else
    //This creates the wildcards as the standard bit-tree view in the UI
    ADD_SUBTREE(wct, tree, "ofp_match.wildcards", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_IN_PORT", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_SRC", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_DST", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_TYPE", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_NW_PROTO", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_TP_SRC", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_TP_DST", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_NW_SRC_MASK", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_NW_DST_MASK", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN_PCP", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_NW_TOS", 4);
    //ADD_CHILD(wct, "ofp_flow_wildcards.RESERVED", 4);
#endif
}

void DissectorContext::dissect_ofp_match(proto_tree *tree)
{
    guint32 sipmask, dipmask;

    ADD_SUBTREE(t, tree, "ofp_match", sizeof(struct ofp_match));

#define CHECK_WILDCARD(m,t,f,l) \
    if (wildcards & (m)) { \
        CONSUME_BYTES(l); \
    } else  { \
        ADD_CHILD(t,f,l); \
    }

    /*FIXME: We should care if the type isn't STANDARD (0x00) */

    // We're going to grab the wildcards so we can selectively display info in the tree
    // CHECK_WILDCARD requires this local to exist
    //guint32 wildcards = tvb_get_ntohl(this->_tvb, this->_offset + 8);
    READ_UINT32(wildcards);
    this->dissect_ofp_wildcards(t, wildcards);
    /* Adding booleans doesn't consume the bits, so we need to move the offset
     * the length of the wildcard field
     */
    CONSUME_BYTES(4);


    if (wildcards & (OFPFW_IN_PORT)) {
        this->_offset += 2;
    } else  {
        READ_UINT16(portid);
        add_child_ofp_port_no(t, "ofp_match.in_port", portid, 2);
    }
    //CHECK_WILDCARD(OFPFW_IN_PORT, t, "ofp_match.in_port", 2);

    CHECK_WILDCARD(OFPFW_DL_SRC, t, "ofp_match.dl_src", 6);
    CHECK_WILDCARD(OFPFW_DL_DST, t, "ofp_match.dl_dst", 6);

    if (wildcards & (OFPFW_DL_VLAN)) {
        this->_offset += 2;
    } else  {
        READ_UINT16(vlanid);
        add_child_ofp_vlanid(t, "ofp_match.dl_vlan", vlanid, 2);
    }
    //CHECK_WILDCARD(OFPFW_DL_VLAN, t, "ofp_match.dl_vlan", 2);
    CHECK_WILDCARD(OFPFW_DL_VLAN_PCP, t, "ofp_match.dl_vlan_pcp", 1);
    ADD_CHILD(t, "padding", 1);
    CHECK_WILDCARD(OFPFW_DL_TYPE, t, "ofp_match.dl_type", 2);
    CHECK_WILDCARD(OFPFW_NW_TOS, t, "ofp_match.nw_tos", 1);
    CHECK_WILDCARD(OFPFW_NW_PROTO, t, "ofp_match.nw_proto", 1);

    ADD_CHILD(t, "padding", 2);

    sipmask = (wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT;
    if (sipmask >= 32) { /* 0 - /32, 8 - /24, 32 - /0 */
        CONSUME_BYTES(4);
    } else  {
        ADD_CHILD(t, "ofp_match.nw_src", 4);
    }

    dipmask = (wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT;
    if (dipmask >= 32) { /* 0 - /32, 8 - /24, 32 - /0 */
        CONSUME_BYTES(4);
    } else  {
        ADD_CHILD(t, "ofp_match.nw_dst", 4);
    }

    //CHECK_WILDCARD(OFPFW_NW_SRC_MASK, t, "ofp_match.nw_src", 4);
    //CHECK_WILDCARD(OFPFW_NW_DST_MASK, t, "ofp_match.nw_dst", 4);

    CHECK_WILDCARD(OFPFW_TP_SRC, t, "ofp_match.tp_src", 2);
    CHECK_WILDCARD(OFPFW_TP_DST, t, "ofp_match.tp_dst", 2);
}

void DissectorContext::dissect_ofp_action(proto_tree* parent)
{
    guint16 len;

    READ_UINT16(type);
    len = tvb_get_ntohs(this->_tvb, this->_offset + 2);

    if (len == 0) {
        throw ZeroLenAction();
    }

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_action", len);
    ADD_CHILD(tree, "ofp_action.type", 2);
    ADD_CHILD(tree, "ofp_action.len", 2);

    switch (type) {
        case OFPAT_OUTPUT: {
            READ_UINT16(portid);
            add_child_ofp_port_no(tree, "ofp_action_output.port", portid, 2);
            ADD_CHILD(tree, "ofp_action_output.max_len", 2);
            break;
        }
        case OFPAT_SET_VLAN_VID: {
            READ_UINT16(vlanid);
            add_child_ofp_vlanid(tree, "ofp_action_vlan_vid.vlan_vid", vlanid, 2);
            ADD_CHILD(tree, "padding", 2);
            break;
        }
        case OFPAT_SET_VLAN_PCP:
            ADD_CHILD(tree, "ofp_action_vlan_pcp.vlan_pcp", 1);
            ADD_CHILD(tree, "padding", 3);
            break;
        case OFPAT_STRIP_VLAN:
            /* nothing */
            ADD_CHILD(tree, "padding", 4);
            break;
        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST:
            ADD_CHILD(tree, "ofp_action_dl_addr.dl_addr", 6);
            ADD_CHILD(tree, "padding", 6);
            break;
        case OFPAT_SET_NW_DST:
        case OFPAT_SET_NW_SRC:
            ADD_CHILD(tree, "ofp_action_nw_addr.nw_addr", 4);
            break;
        case OFPAT_SET_NW_TOS:
            ADD_CHILD(tree, "ofp_action_nw_tos.nw_tos", 1);
            ADD_CHILD(tree, "padding", 3);
            break;
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST:
            ADD_CHILD(tree, "ofp_action_tp_port.tp_port", 2);
            ADD_CHILD(tree, "padding", 2);
            break;
        case OFPAT_ENQUEUE: {
            READ_UINT16(portid);
            add_child_ofp_port_no(tree, "ofp_action_enqueue.port", portid, 2);
            ADD_CHILD(tree, "padding", 6);
            READ_UINT32(queueid);
            add_child_ofp_queue_id(tree, "ofp_action_enqueue.queue_id", queueid, 4);
            break;
        }
         case OFPAT_VENDOR:
            ADD_CHILD(tree, "ofp_action_vendor_header.vender", 4);
            break;
        default:
            CONSUME_BYTES(message_end - this->_offset);
            break;
    }
}

void DissectorContext::dissect_ofp_port_status()
{
    ADD_TREE(tree, "ofp_port_status");

    ADD_CHILD(tree, "ofp_port_status.reason", 1);
    ADD_CHILD(tree, "padding", 7);

    ADD_SUBTREE(desc_tree, tree, "ofp_port_status.desc", this->_oflen - this->_offset);
    while ((this->_oflen - this->_offset) > 0) {
        this->dissect_ofp_port(desc_tree);
    }
}

void DissectorContext::dissect_ofp_port(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_port", sizeof(struct ofp_phy_port));

    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_port.num", portid, 2);
    ADD_CHILD(tree, "ofp_port.hwaddr", 6);
    ADD_CHILD(tree, "ofp_port.name", 16);

    ADD_SUBTREE(config_tree, tree, "ofp_port.config", 4);
    READ_UINT32(ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_STP", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV_STP", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FLOOD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.RESERVED", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(state_tree, tree, "ofp_port.state", 4);
    READ_UINT32(ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LINK_DOWN", 4, ofpps);
    ADD_CHILD(state_tree, "ofp_port.stp", 4);

    ADD_SUBTREE(curr_feats_tree, tree, "ofp_port.curr_feats", 4);
    dissect_ofppf(curr_feats_tree);

    ADD_SUBTREE(advertised_tree, tree, "ofp_port.advertised", 4);
    dissect_ofppf(advertised_tree);

    ADD_SUBTREE(supported_tree, tree, "ofp_port.supported", 4);
    dissect_ofppf(supported_tree);

    ADD_SUBTREE(peer_tree, tree, "ofp_port.peer", 4);
    dissect_ofppf(peer_tree);
}

void DissectorContext::dissect_ofppf(proto_tree *tree)
{
    READ_UINT32(ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10MB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10MB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100MB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100MB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1GB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_COPPER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_FIBER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_AUTONEG", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_PAUSE", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_PAUSE_ASYM", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.RESERVED", 4, ofppf);
    CONSUME_BYTES(4);
}

void DissectorContext::dissect_ofp_flow_mod()
{
    ADD_TREE(tree, "ofp_flow_mod");

    //ADD_SUBTREE(match_tree, tree, "ofp_flow_mod.match", this->_oflen - this->_offset);
    this->dissect_ofp_match(tree);

    ADD_CHILD(tree, "ofp_flow_mod.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_mod.command", 2);
    ADD_CHILD(tree, "ofp_flow_mod.idle_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_mod.hard_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_mod.priority", 2);
    ADD_CHILD(tree, "ofp_flow_mod.buffer_id", 4);
    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_flow_mod.out_port", portid, 2);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_flow_mod.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_EMERG", 2, flags);
    CONSUME_BYTES(2);

    try {
        while ((this->_oflen - this->_offset) > 0) {
            this->dissect_ofp_action(tree);
        }
    } catch (const ZeroLenAction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_flow_remove()
{
    ADD_TREE(tree, "ofp_flow_removed");

    this->dissect_ofp_match(tree);

    ADD_CHILD(tree, "ofp_flow_removed.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_removed.priority", 2);
    ADD_CHILD(tree, "ofp_flow_removed.reason", 1);
    ADD_CHILD(tree, "padding", 1);

    ADD_CHILD(tree, "ofp_flow_removed.duration_sec", 4);
    ADD_CHILD(tree, "ofp_flow_removed.duration_nsec", 4);

    ADD_CHILD(tree, "ofp_flow_removed.idle_timeout", 2);
    ADD_CHILD(tree, "padding", 2);

    ADD_CHILD(tree, "ofp_flow_removed.packet_count", 8);
    ADD_CHILD(tree, "ofp_flow_removed.byte_count", 8);
}

void DissectorContext::dissect_ofp_port_mod()
{
    ADD_TREE(tree, "ofp_port_mod");

    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_port_mod.port_no", portid, 2);
    ADD_CHILD(tree, "ofp_port_mod.hw_addr", 6);

    ADD_SUBTREE(config_tree, tree, "ofp_port_mod.config", 4);
    READ_UINT32(ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_STP", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV_STP", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FLOOD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.RESERVED", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(mask_tree, tree, "ofp_port_mod.mask", 4);
    READ_UINT32(mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_STP", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_RECV", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_RECV_STP", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_FLOOD", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_FWD", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.RESERVED", 4, mask);
    CONSUME_BYTES(4);

    ADD_SUBTREE(advertised_tree, tree, "ofp_port_mod.advertised", 4);
    dissect_ofppf(advertised_tree);

    ADD_CHILD(tree, "padding", 4);
}

void DissectorContext::dissect_ofp_flow_stats_request(proto_tree *tree)
{
    ADD_SUBTREE(flow_stat_tree, tree, "ofp_flow_stats_request",
        sizeof(struct ofp_flow_stats_request));
    this->dissect_ofp_match(flow_stat_tree);
    READ_UINT8(tableid);
    add_child_ofp_table(flow_stat_tree, "ofp_flow_stats_request.table_id", tableid, 1);
    ADD_CHILD(flow_stat_tree, "padding", 1);
    READ_UINT16(portid);
    add_child_ofp_port_no(flow_stat_tree, "ofp_flow_stats_request.out_port", portid, 2);
}

void DissectorContext::dissect_ofp_flow_stats(proto_tree *tree)
{
    guint32 start, end;

    while ((this->_oflen - this->_offset) > 0) {
        READ_UINT16(length);
        end = this->_offset + length;
        ADD_SUBTREE(flow_stat_tree, tree, "ofp_flow_stats", length);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.length", 2);
        READ_UINT8(tableid);
        add_child_ofp_table(flow_stat_tree, "ofp_flow_stats.table_id", tableid, 1);
        ADD_CHILD(flow_stat_tree, "padding", 1);
        this->dissect_ofp_match(flow_stat_tree);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.duration_sec", 4);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.duration_nsec", 4);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.priority", 2);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.idle_timeout", 2);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.hard_timeout", 2);
        ADD_CHILD(flow_stat_tree, "padding", 6);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.cookie", 8);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.packet_count", 8);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.byte_count", 8);

        try {
            while ((end - this->_offset) > 0) {
                this->dissect_ofp_action(flow_stat_tree);
            }
        } catch (const ZeroLenAction &e) {
            CONSUME_BYTES(this->_oflen - this->_offset);
            return;
        }
    }
}

void DissectorContext::dissect_ofp_aggregate_stats_request(proto_tree *tree)
{
    ADD_SUBTREE(flow_aggre_stat_tree, tree, "ofp_aggregate_stats_request",
        sizeof(struct ofp_aggregate_stats_request));
    this->dissect_ofp_match(flow_aggre_stat_tree);
    READ_UINT8(tableid);
    add_child_ofp_table(flow_aggre_stat_tree, "ofp_aggregate_stats_request.table_id", tableid, 1);
    ADD_CHILD(flow_aggre_stat_tree, "padding", 1);
    READ_UINT16(portid);
    add_child_ofp_port_no(flow_aggre_stat_tree, "ofp_aggregate_stats_request.out_port", portid, 2);
}

void DissectorContext::dissect_ofp_aggregate_stats(proto_tree *tree)
{
    ADD_SUBTREE(flow_aggre_stat_tree, tree, "ofp_aggregate_stats_reply",
        sizeof(struct ofp_aggregate_stats_reply));
    ADD_CHILD(flow_aggre_stat_tree, "ofp_aggregate_stats_reply.packet_count", 8);
    ADD_CHILD(flow_aggre_stat_tree, "ofp_aggregate_stats_reply.byte_count", 8);
    ADD_CHILD(flow_aggre_stat_tree, "ofp_aggregate_stats_reply.flow_count", 8);
    ADD_CHILD(flow_aggre_stat_tree, "padding", 6);
}

void DissectorContext::dissect_ofp_port_stats_request(proto_tree *tree)
{
    ADD_SUBTREE(port_stat_tree, tree, "ofp_port_stats_request",
        sizeof(struct ofp_port_stats_request));
    READ_UINT16(portid);
    add_child_ofp_port_no(port_stat_tree, "ofp_port_stats_request.port_no", portid, 2);
    ADD_CHILD(port_stat_tree, "padding", 6);
}

void DissectorContext::dissect_ofp_port_stats(proto_tree *tree)
{
    while ((this->_oflen - this->_offset) > 0) {
        ADD_SUBTREE(port_stat_tree, tree, "ofp_port_stats", sizeof(struct ofp_port_stats));
        READ_UINT16(portid);
        add_child_ofp_port_no(port_stat_tree, "ofp_port_stats.port_no", portid, 2);
        ADD_CHILD(port_stat_tree, "padding", 6);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_packets", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.tx_packets", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_bytes", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.tx_bytes", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_dropped", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.tx_dropped", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_errors", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.tx_errors", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_frame_err", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_over_err", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.rx_crc_err", 8);
        ADD_CHILD(port_stat_tree, "ofp_port_stats.collisions", 8);
    }
}

void DissectorContext::dissect_ofp_queue_stats_request(proto_tree *tree)
{
    ADD_SUBTREE(queue_stat_tree, tree, "ofp_queue_stats_request",
        sizeof(struct ofp_queue_stats_request));
    READ_UINT16(portid);
    add_child_ofp_port_no(queue_stat_tree, "ofp_queue_stats_request.port_no", portid, 2);
    ADD_CHILD(queue_stat_tree, "padding", 2);
    READ_UINT32(queueid);
    add_child_ofp_queue_id(queue_stat_tree, "ofp_queue_stats_request.queue_id", queueid, 4);
}

void DissectorContext::dissect_ofp_queue_stats(proto_tree *tree)
{
    while ((this->_oflen - this->_offset) > 0) {
        ADD_SUBTREE(queue_stat_tree, tree, "ofp_queue_stats", sizeof(struct ofp_queue_stats));
        READ_UINT16(portid);
        add_child_ofp_port_no(queue_stat_tree, "ofp_queue_stats.port_no", portid, 2);
        ADD_CHILD(queue_stat_tree, "padding", 2);
        READ_UINT32(queueid);
        add_child_ofp_queue_id(queue_stat_tree, "ofp_queue_stats.queue_id", queueid, 4);
        ADD_CHILD(queue_stat_tree, "ofp_queue_stats.tx_bytes", 8);
        ADD_CHILD(queue_stat_tree, "ofp_queue_stats.tx_packets", 8);
        ADD_CHILD(queue_stat_tree, "ofp_queue_stats.tx_errors", 8);
    }
}

void DissectorContext::dissect_ofp_vendor_stats_vendor(proto_tree *tree)
{
    ADD_SUBTREE(vendor_stat_tree, tree, "ofp_vendor_stats_vendor", this->_oflen - this->_offset);
    ADD_CHILD(vendor_stat_tree, "ofp_vendor_stats_vendor.vendor", 4);
    ADD_CHILD(vendor_stat_tree, "ofp_vendor_stats_vendor.body", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_desc_stats(proto_tree *tree)
{
    ADD_SUBTREE(desc_stat_tree, tree, "ofp_desc_stats", sizeof(struct ofp_desc_stats));
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.mfr_desc", DESC_STR_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.hw_desc", DESC_STR_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.sw_desc", DESC_STR_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.serial_num", SERIAL_NUM_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.dp_desc", DESC_STR_LEN);
}

void DissectorContext::dissect_ofp_table_stats(proto_tree *tree)
{
    while ((this->_oflen - this->_offset) > 0) {
        ADD_SUBTREE(table_stat_tree, tree, "ofp_table_stats", sizeof(struct ofp_table_stats));
        READ_UINT8(tableid);
        add_child_ofp_table(table_stat_tree, "ofp_table_stats.table_id", tableid, 1);
        ADD_CHILD(table_stat_tree, "padding", 3);
        ADD_CHILD(table_stat_tree, "ofp_table_stats.name", OFP_MAX_TABLE_NAME_LEN);
        READ_UINT32(wildcards);
        this->dissect_ofp_wildcards(table_stat_tree, wildcards);
        CONSUME_BYTES(4);
        ADD_CHILD(table_stat_tree, "ofp_table_stats.max_entries", 4);
        ADD_CHILD(table_stat_tree, "ofp_table_stats.active_count", 4);
        ADD_CHILD(table_stat_tree, "ofp_table_stats.lookup_count", 8);
        ADD_CHILD(table_stat_tree, "ofp_table_stats.matched_count", 8);
    }
}

void DissectorContext::dissect_ofp_stats_request()
{
    ADD_TREE(tree, "ofp_stats_request");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_stats_request.type", 2);
    ADD_CHILD(tree, "ofp_stats_request.flags", 2);

    switch (type) {
    case OFPST_DESC:
        this->_offset += this->_oflen - this->_offset;
        break;
    case OFPST_FLOW:
        this->dissect_ofp_flow_stats_request(tree);
        break;
    case OFPST_AGGREGATE:
        this->dissect_ofp_aggregate_stats_request(tree);
        break;
    case OFPST_TABLE:
        this->_offset += this->_oflen - this->_offset;
        break;
    case OFPST_PORT:
        this->dissect_ofp_port_stats_request(tree);
        break;
    case OFPST_QUEUE:
        this->dissect_ofp_queue_stats_request(tree);
        break;
    case OFPST_VENDOR:
        this->dissect_ofp_vendor_stats_vendor(tree);
        break;
    default:
        ADD_CHILD(tree, "ofp_stats_request.body", this->_oflen - this->_offset);
        break;
    }

}

void DissectorContext::dissect_ofp_stats_reply()
{
    ADD_TREE(tree, "ofp_stats_reply");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_stats_reply.type", 2);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_stats_reply.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_stats_reply_flags.OFPSF_REPLY_MORE", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_stats_reply_flags.RESERVED", 2, flags);
    CONSUME_BYTES(2);

    // TODO: include this check in every case we have a body?
    if (this->_oflen <= this->_offset) {
        return;
    }

    switch (type) {
    case OFPST_DESC:
        this->dissect_ofp_desc_stats(tree);
        break;
    case OFPST_FLOW:
        this->dissect_ofp_flow_stats(tree);
        break;
    case OFPST_AGGREGATE:
        this->dissect_ofp_aggregate_stats(tree);
        break;
    case OFPST_TABLE:
        this->dissect_ofp_table_stats(tree);
        break;
    case OFPST_PORT:
        this->dissect_ofp_port_stats(tree);
        break;
    case OFPST_QUEUE:
        this->dissect_ofp_queue_stats(tree);
        break;
    case OFPST_VENDOR:
        this->dissect_ofp_vendor_stats_vendor(tree);
        break;
    default:
        ADD_CHILD(tree, "ofp_stats_reply.body", this->_oflen - this->_offset);
        break;
    }
}

void DissectorContext::dissect_ofp_queue_prop(proto_tree *parent)
{
    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset + 2);

    ADD_SUBTREE(tree, parent, "ofp_queue_prop_header", len);

    READ_UINT16(property);
    ADD_CHILD(tree, "ofp_queue_prop_header.property", 2);
    ADD_CHILD(tree, "ofp_queue_prop_header.len", 2);
    ADD_CHILD(tree, "padding", 4);

    if (property == OFPQT_MIN_RATE) {
        ADD_CHILD(tree, "ofp_queue_prop_min_rate.rate", 2);
        ADD_CHILD(tree, "padding", 6);
    }
}

void DissectorContext::dissect_ofp_packet_queue(proto_tree *parent)
{
    guint32 msg_end;
    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset + 4);

    READ_UINT32(queueid);
    ADD_SUBTREE(tree, parent, "ofp_packet_queue", len);
    msg_end = this->_offset + len;
    add_child_ofp_queue_id(tree, "ofp_packet_queue.queue_id", queueid, 4);
    ADD_CHILD(tree, "ofp_packet_queue.len", 2);
    ADD_CHILD(tree, "padding", 2);

    while ((msg_end - this->_offset) > 0) {
        dissect_ofp_queue_prop(tree);
    }
}

void DissectorContext::dissect_ofp_queue_get_config_request(void)
{
    ADD_TREE(tree, "ofp_queue_get_config_request");
    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_queue_get_config_request.port", portid, 2);
    ADD_CHILD(tree, "padding", 2);  /* ·Ç64Î»¶ÔÆë */
}

void DissectorContext::dissect_ofp_queue_get_config_reply(void)
{
    ADD_TREE(tree, "ofp_queue_get_config_reply");

    READ_UINT16(portid);
    add_child_ofp_port_no(tree, "ofp_queue_get_config_reply.port", portid, 2);
    ADD_CHILD(tree, "padding", 6);

    while ((this->_oflen - this->_offset) > 0) {
        dissect_ofp_packet_queue(tree);
    }
}

void DissectorContext::add_child_ofp_table(proto_tree* tree, const char *field, guint8 tableid,
                        guint32 len)
{
    const char* str_table = NULL;
    char str_tblid[6];

    switch (tableid) {
    case 0xFF:
        str_table = "0xFF - ALL tables";
        break;
    case 0xFE:
        str_table = "0xFE - Emergency";
        break;
    default:
        str_table = str_tblid;
        snprintf(str_tblid, 6, "%u", tableid);
        str_tblid[5] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_table);
}

void DissectorContext::add_child_ofp_queue_id(proto_tree* tree, const char *field, guint32 queueid,
                        guint32 len)
{
    const char* str_queue = NULL;
    char str_qid[20];

    switch (queueid) {
    case OFPQ_ALL:
        str_queue = "OFPQ_ALL(0xFFFFFFFF) - All ones is used to indicate all queues in a port";
        break;
    default:
        str_queue = str_qid;
        snprintf(str_qid, 20, "%u", queueid);
        str_qid[19] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_queue);
}

void DissectorContext::add_child_ofp_vlanid(proto_tree* tree, const char *field, guint16 vlanid,
                        guint32 len)
{
    const char* str_vlan = NULL;
    char str_vid[10];

    switch (vlanid) {
    case OFP_VLAN_NONE:
        str_vlan = "OFP_VLAN_NONE(0xFFFF) - No VLAN id was set";
        break;
    default:
        str_vlan = str_vid;
        snprintf(str_vid, 10, "%u", vlanid);
        str_vid[9] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_vlan);
}

void DissectorContext::add_child_ofp_port_no(proto_tree* tree, const char *field, guint16 portid,
                        guint32 len)
{
    const char* str_port = NULL;
    char str_pid[10];

    switch (portid) {
    case OFPP_MAX:
        str_port = "OFPP_MAX(0xFF00) - Maximum number of physical and logical switch ports";
        break;
    case OFPP_IN_PORT:
        str_port = "OFPP_IN_PORT(0xFFF8) - Send the packet out the input port";
        break;
    case OFPP_TABLE:
        str_port = "OFPP_TABLE(0xFFF9) - Submit the packet to the first flow table";
        break;
    case OFPP_NORMAL:
        str_port = "OFPP_NORMAL(0xFFFA) - Process with normal L2/L3 switching";
        break;
    case OFPP_FLOOD:
        str_port = "OFPP_FLOOD(0xFFFB) - All physical ports in VLAN, except input port and those blocked or link down";
        break;
    case OFPP_ALL:
        str_port = "OFPP_AL(0xFFFC) - All physical ports except input port";
        break;
    case OFPP_CONTROLLER:
        str_port = "OFPP_CONTROLLER(0xFFFD) - Send to controller";
        break;
    case OFPP_LOCAL:
        str_port = "OFPP_LOCAL(0xFFFE) - Local openflow \"port\"";
        break;
    case OFPP_NONE:
        str_port = "OFPP_NONE(0xFFFF) - Any port. For flow mod (delete) and flow stats requests only";
        break;
    default:
        str_port = str_pid;
        snprintf(str_pid, 10, "%u", portid);
        str_pid[9] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_port);
}

// Boring part
void DissectorContext::setupFields(void)
{
    TREE_FIELD("data", "Openflow Protocol");
    FIELD("padding", "Padding", FT_NONE, BASE_NONE, NO_VALUES, NO_MASK);

    //Header
    TREE_FIELD("header", "Header");
    FIELD("version", "Version", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("type", "Type", FT_UINT8, BASE_DEC, VALUES(ofp_type), NO_MASK);
    FIELD("length", "Length", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("xid", "Transaction ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

    //Echo Request/Reply
    FIELD("echo", "Echo Data", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_error
    TREE_FIELD("ofp_error", "Error");
    FIELD("ofp_error.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_error_type), NO_MASK);
    FIELD("ofp_error.code.OFPET_HELLO_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_hello_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_REQUEST", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_request_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_ACTION", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_action_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_FLOW_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_flow_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_PORT_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_port_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_QUEUE_OP_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_queue_op_failed_code), NO_MASK);
    FIELD("ofp_error.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_error.err_data", "Error Data");

    //ofp_feature_request
    FIELD("ofp_feature_request", "Feature Request", FT_NONE, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_switch_features
    TREE_FIELD("ofp_switch_features", "Feature Reply");
    FIELD("ofp_switch_features.datapath_id", "Datapath ID", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.n_buffers", "Buffers", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.n_tables", "Tables", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_switch_features.capabilities", "Capabilities", FT_UINT32);
    BITMAP_FIELD("ofp_switch_features.actions", "Actions", FT_UINT32);
    TREE_FIELD("ofp_switch_features.ports", "Ports");
    FIELD("ofp_switch_features.port_num", "Number of ports", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_port
    TREE_FIELD("ofp_port", "Port Description");
    FIELD("ofp_port.num", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.hwaddr", "Hardware Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port.config", "Config", FT_UINT32);
    BITMAP_FIELD("ofp_port.state", "State", FT_UINT32);
    FIELD("ofp_port.stp", "STP", FT_UINT32, BASE_HEX, VALUES(port_state), NO_MASK);
    BITMAP_FIELD("ofp_port.curr_feats", "Current Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.advertised", "Advertised Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.supported", "Supported Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.peer", "Peer Features", FT_UINT32);

    //ofp_switch_config
    TREE_FIELD("ofp_switch_config", "Switch Configuration");
    //FIELD("ofp_switch_config.flags", "Flags", FT_UINT16, BASE_DEC, VALUES(ofp_config_flags), NO_MASK);
    BITMAP_FIELD("ofp_switch_config.flags", "Flags", FT_UINT16);
    FIELD("ofp_switch_config.miss_send_len", "Max new flow bytes to controller", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_flow_mod
    TREE_FIELD("ofp_flow_mod", "Flow Mod");
    FIELD("ofp_flow_mod.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.command", "Command", FT_UINT8, BASE_HEX, VALUES(ofp_flow_mod_command), NO_MASK);
    FIELD("ofp_flow_mod.idle_timeout", "Idle Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.hard_timeout", "Hard Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_port", "Output Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_flow_mod.flags", "Flags", FT_UINT16);

    //ofp_match
    TREE_FIELD("ofp_match", "Match");
    TREE_FIELD("ofp_match.wildcards", "Wildcards");
    BITMAP_FIELD("ofp_flow_wildcards", "Wildcards", FT_UINT32);
    FIELD("ofp_match.in_port", "In Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    /*FIXME: There's no BASE_BINARY, so FT_ETHER is how you're getting ethernet masks.  Have fun. */
    FIELD("ofp_match.dl_src", "Ethernet Source Addr", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_dst", "Ethernet Dest Addr", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_vlan", "VLAN ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_vlan_pcp", "VLAN PCP", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_type", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_tos", "IP DSCP", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_proto", "IP Protocol", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_src", "IP Source Addr", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_dst", "IP Dest Addr", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    /*FIXME: should really add individual entries for TCP/UDP/SCTP/whatever ports and switch on protocol */
    FIELD("ofp_match.tp_src", "TCP/UDP Source Port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.tp_dst", "TCP/UDP Dest Port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_action
    TREE_FIELD("ofp_action", "Action");
    FIELD("ofp_action.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_action_type), NO_MASK);
    FIELD("ofp_action.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.port", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.max_len", "Max Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_enqueue.port", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_enqueue.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_vlan_vid.vlan_vid", "Vlan ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_vlan_pcp.vlan_pcp", "Vlan Priority", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_dl_addr.dl_addr", "Ethernet address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_nw_addr.nw_addr", "IP address", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_nw_tos.nw_tos", "IP Tos/DSCP", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_tp_port.tp_port", "TCP/UDP port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_vendor_header.vendor", "Vendor ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_stats_request
    TREE_FIELD("ofp_stats_request", "Stats Request");
    FIELD("ofp_stats_request.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_stats_types), NO_MASK);
    BITMAP_FIELD("ofp_stats_request.flags", "Flags(none yet defined)", FT_UINT16);
    FIELD("ofp_stats_request.body", "Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_stats_reply
    TREE_FIELD("ofp_stats_reply", "Stats Reply");
    FIELD("ofp_stats_reply.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_stats_types), NO_MASK);
    BITMAP_FIELD("ofp_stats_reply.flags", "Flags", FT_UINT16);
    FIELD("ofp_stats_reply.body", "Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_desc_stats
    TREE_FIELD("ofp_desc_stats", "Desc Stats Reply");
    FIELD("ofp_desc_stats.mfr_desc", "Mfr Desc", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_desc_stats.hw_desc", "HW Desc", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_desc_stats.sw_desc", "SW Desc", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_desc_stats.serial_num", "Serial Num", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_desc_stats.dp_desc", "DP Desc", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    /* CSM: Stats: Flow: Request */
    TREE_FIELD("ofp_flow_stats_request", "Flow Stats Request");
    FIELD("ofp_flow_stats_request.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.out_port", "Out Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    /* CSM: Stats: Flow: Reply */
    TREE_FIELD("ofp_flow_stats", "Flow Stats Reply");
    FIELD("ofp_flow_stats.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.duration_sec", "Flow Duration (sec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.duration_nsec", "Flow Duration (nsec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.idle_timeout", "Number of seconds idle before expiration", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.hard_timeout", "Number of seconds before expiration", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.packet_count", "Packet Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.byte_count", "Byte Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    /* CSM: Stats: Aggregate: Request */
    TREE_FIELD("ofp_aggregate_stats_request", "Aggregate Stats Request");
    FIELD("ofp_aggregate_stats_request.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_request.out_port", "Out Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    /* CSM: Stats: Aggregate: Reply */
    TREE_FIELD("ofp_aggregate_stats_reply", "Aggregate Stats Reply");
    FIELD("ofp_aggregate_stats_reply.packet_count", "Packet Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_reply.byte_count", "Byte Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_reply.flow_count", "Flow Count", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    /* CSM: Stats: Port Request */
    TREE_FIELD("ofp_port_stats_request", "Port Stats Request");
    FIELD("ofp_port_stats_request.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    /* CSM: Stats: Port Reply */
    TREE_FIELD("ofp_port_stats", "Port Stats Reply");
    FIELD("ofp_port_stats.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_packets", "Received packets", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.tx_packets", "transmitted packets", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_bytes", "received bytes", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.tx_bytes", "Transmitted bytes", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_dropped", "RX dropped", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.tx_dropped", "TX dropped", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_errors", "RX errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.tx_errors", "TX errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_frame_err", "RX frame errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_over_err", "RX overrun errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.rx_crc_err", "RX CRC Errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_stats.collisions", "RX Collisions", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    /* CSM: Stats: Queue Request */
    TREE_FIELD("ofp_queue_stats_request", "Queue Stats Request");
    FIELD("ofp_queue_stats_request.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats_request.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    /* CSM: Stats: Queue Reply */
    TREE_FIELD("ofp_queue_stats", "Queue Stats Reply");
    FIELD("ofp_queue_stats.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.tx_bytes", "Transmitted bytes", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.tx_packets", "transmitted packets", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.tx_errors", "TX errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    /* CSM: Stats: Table */
    TREE_FIELD("ofp_table_stats", "Table Stats Reply");
    FIELD("ofp_table_stats.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_table_stats.wildcards", "Wildcards", FT_UINT32);
    FIELD("ofp_table_stats.max_entries", "Max Supported Entries", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.active_count", "Active Entry Count", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.lookup_count", "Lookup Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.matched_count", "Packet Match Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    /* CSM: Stats: Vendor */
    TREE_FIELD("ofp_vendor_stats_vendor", "Vendor Stats");
    FIELD("ofp_vendor_stats_vendor.vendor", "Vendor ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_vendor_stats_vendor.body", "Vendor Stats Message Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_port_status
    TREE_FIELD("ofp_port_status", "Port Status");
    FIELD("ofp_port_status.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_port_reason), NO_MASK);
    TREE_FIELD("ofp_port_status.desc", "Ports");

    //ofp_packet_in
    TREE_FIELD("ofp_packet_in", "Packet in");
    FIELD("ofp_packet_in.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.total_len", "Total length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.in_port", "Input Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_packet_in_reason), NO_MASK);
    FIELD("ofp_packet_in.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_packet_out
    TREE_FIELD("ofp_packet_out", "Packet out");
    FIELD("ofp_packet_out.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.in_port", "Input Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.actions_len", "Actions length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    /* ofp_packet_queue */
    TREE_FIELD("ofp_packet_queue", "List of configured queues");
    FIELD("ofp_packet_queue.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_queue.len", "Length of desc", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    /* ofp_queue_prop_header */
    TREE_FIELD("ofp_queue_prop_header", "List of properties");
    FIELD("ofp_queue_prop_header.property", "Queue property", FT_UINT16, BASE_DEC, VALUES(ofp_queue_properties), NO_MASK);
    FIELD("ofp_queue_prop_header.len", "Length of property", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_flow_removed
    TREE_FIELD("ofp_flow_removed", "Flow Removed");
    FIELD("ofp_flow_removed.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.reason", "Reason", FT_UINT8, BASE_DEC, VALUES(ofp_flow_removed_reason), NO_MASK);
    FIELD("ofp_flow_removed.duration_sec", "Flow Duration (sec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.duration_nsec", "Flow Duration (nsec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.idle_timeout", "Idle Time (sec) Before Discarding", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.packet_count", "Packet Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.byte_count", "Byte Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_port_mod
    TREE_FIELD("ofp_port_mod", "Port Mod");
    FIELD("ofp_port_mod.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port_mod.hw_addr", "MAC Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port_mod.config", "Port Config Flags", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.mask", "Port Mask Flags", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.advertised", "Port Advertise Flags", FT_UINT32);

    //ofp_vendor_header
    TREE_FIELD("ofp_vendor_header", "Vendor Header");
    FIELD("ofp_vendor_header.vendor", "Vendor ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_vendor_header.body", "Vendor Message Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_queue_get_config_request
    TREE_FIELD("ofp_queue_get_config_request", "Queue Configuration Request");
    FIELD("ofp_queue_get_config_request.port", "Port(< OFPP_MAX) ID",FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_queue_get_config_reply
    TREE_FIELD("ofp_queue_get_config_reply", "Queue Configuration Reply");
    FIELD("ofp_queue_get_config_reply.port", "Port(< OFPP_MAX) ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_queue_prop_min_rate
    FIELD("ofp_queue_prop_min_rate.rate", "Min rate In 1/10 of a percent", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
}

// Generated code
void DissectorContext::setupCodes(void)
{
    guint32 i;

    // ofp_type
    TYPE_ARRAY(ofp_type);
    TYPE_ARRAY_ADD(ofp_type, OFPT_HELLO, "Hello (SM) - OFPT_HELLO");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ERROR, "Error (SM) - OFPT_ERROR");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ECHO_REQUEST, "Echo request (SM) - OFPT_ECHO_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ECHO_REPLY, "Echo reply (SM) - OFPT_ECHO_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_VENDOR, "Vendor (SM) - OFPT_VENDOR");

    TYPE_ARRAY_ADD(ofp_type, OFPT_FEATURES_REQUEST, "Features request (CSM) - OFPT_FEATURES_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FEATURES_REPLY, "Features reply (CSM) - OFPT_FEATURES_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GET_CONFIG_REQUEST, "Get config request (CSM) - OFPT_GET_CONFIG_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GET_CONFIG_REPLY, "Get config reply (CSM) - OFPT_GET_CONFIG_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_SET_CONFIG, "Set config (CSM) - OFPT_SET_CONFIG");

    TYPE_ARRAY_ADD(ofp_type, OFPT_PACKET_IN, "Packet in (AM) - OFPT_PACKET_IN");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FLOW_REMOVED, "Flow removed (AM) - OFPT_FLOW_REMOVED");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PORT_STATUS, "Port status (AM) - OFPT_PORT_STATUS");

    TYPE_ARRAY_ADD(ofp_type, OFPT_PACKET_OUT, "Packet out (CSM) - OFPT_PACKET_OUT");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FLOW_MOD, "Flow mod (CSM) - OFPT_FLOW_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PORT_MOD, "Port mod (CSM) - OFPT_PORT_MOD");

    TYPE_ARRAY_ADD(ofp_type, OFPT_STATS_REQUEST, "Stats request (CSM) - OFPT_STATS_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_STATS_REPLY, "Stats reply (CSM) - OFPT_STATS_REPLY");

    TYPE_ARRAY_ADD(ofp_type, OFPT_BARRIER_REQUEST, "Barrier request (CSM) - OFPT_BARRIER_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_BARRIER_REPLY, "Barrier reply (CSM) - OFPT_BARRIER_REPLY");

    TYPE_ARRAY_ADD(ofp_type, OFPT_QUEUE_GET_CONFIG_REQUEST, "Queue get config request (CSM) - OFPT_QUEUE_GET_CONFIG_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_QUEUE_GET_CONFIG_REPLY, "Queue get config reply (CSM) - OFPT_QUEUE_GET_CONFIG_REPLY");

    // ofp_queue_properties
    TYPE_ARRAY(ofp_queue_properties);
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_NONE, "No property defined for queue (default) - OFPQT_MAX_RATE");
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_MIN_RATE, "Minimum datarate guaranteed - OFPQT_MIN_RATE");

    // ofp_flow_wildcards
    TYPE_ARRAY(ofp_flow_wildcards);
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_IN_PORT, "Switch input port - OFPFW_IN_PORT");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_DL_VLAN, "VLAN id - OFPFW_DL_VLAN");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_DL_SRC, "Ethernet source address - OFPFW_DL_SRC");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_DL_DST, "Ethernet destination address - OFPFW_DL_DST");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_DL_TYPE, "Ethernet frame type - OFPFW_DL_TYPE");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_NW_PROTO, "IP protocol - OFPFW_NW_PROTO");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_TP_SRC, "TCP source port - OFPFW_TP_SRC");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_TP_DST, "TCP destination port - OFPFW_TP_DST");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_NW_SRC_MASK, "IP source address wildcard mask - OFPFW_NW_SRC_MASK");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_NW_SRC_ALL, "IP source address wildcard bit count - OFPFW_NW_SRC_ALL");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_NW_DST_MASK, "IP destination address wildcard mask - OFPFW_NW_DST_MASK");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_NW_DST_ALL, "IP destination address wildcard bit count - OFPFW_NW_DST_ALL");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_DL_VLAN_PCP, "VLAN priority - OFPFW_DL_VLAN_PCP");
    TYPE_ARRAY_ADD(ofp_flow_wildcards, OFPFW_NW_TOS, "IP DSCP (6 bits in ToS field) - OFPFW_NW_TOS");

    // ofp_action_type
    TYPE_ARRAY(ofp_action_type);
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_OUTPUT, "Output to switch port - OFPAT_OUTPUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_VLAN_VID, "Set the 802.1q VLAN id - OFPAT_SET_VLAN_VID");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_VLAN_PCP, "Set the 802.1q priority - OFPAT_SET_VLAN_PCP");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_STRIP_VLAN, "Strip the 802.1q header - OFPAT_STRIP_VLAN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_DL_SRC, "Set Ethernet source address - OFPAT_SET_DL_SRC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_DL_DST, "Set Ethernet destination address - OFPAT_SET_DL_DST");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_SRC, "Set IP source address - OFPAT_SET_NW_SRC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_DST, "Set IP destination address - OFPAT_SET_NW_DST");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_TOS, "Set IP ToS (DSCP field, 6 bits) - OFPAT_SET_NW_TOS");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_TP_SRC, "Set TCP/UDP source port - OFPAT_SET_TP_SRC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_TP_DST, "Set TCP/UDP destination port - OFPAT_SET_TP_DST");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_ENQUEUE, "Output to queue - OFPAT_ENQUEUE");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_VENDOR, "Vendor action - OFPAT_VENDOR");

    // ofp_flow_mod_command
    TYPE_ARRAY(ofp_flow_mod_command);
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_ADD, "New flow - OFPFC_ADD");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY, "Modify all matching flows - OFPFC_MODIFY");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY_STRICT, "Modify entry strictly matching wildcards and priority - OFPFC_MODIFY_STRICT");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE, "Delete all matching flows - OFPFC_DELETE");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE_STRICT, "Delete entry strictly matching wildcards and priority - OFPFC_DELETE_STRICT");

    // ofp_stats_types
    TYPE_ARRAY(ofp_stats_types);
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_DESC, "Description of an OpenFlow switch - OFPST_DESC");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_FLOW, "Individual flow statistics - OFPST_FLOW");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_AGGREGATE, "Aggregate flow statistics - OFPST_AGGREGATE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_TABLE, "Flow table statistics - OFPST_TABLE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_PORT, "Port statistics - OFPST_PORT");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_QUEUE, "Queue statistics for a port - OFPST_QUEUE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_VENDOR, "Vendor extension - OFPST_VENDOR");

    // ofp_packet_in_reason
    TYPE_ARRAY(ofp_packet_in_reason);
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_NO_MATCH, "No matching flow - OFPR_NO_MATCH");
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_ACTION, "Action explicitly output to controller - OFPR_ACTION");

    // ofp_flow_removed_reason
    TYPE_ARRAY(ofp_flow_removed_reason);
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_IDLE_TIMEOUT, "Flow idle time exceeded idle_timeout - OFPRR_IDLE_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_HARD_TIMEOUT, "Time exceeded hard_timeout - OFPRR_HARD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_DELETE, "Evicted by a DELETE flow mod - OFPRR_DELETE");

    // ofp_port_reason
    TYPE_ARRAY(ofp_port_reason);
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_ADD, "The port was added - OFPPR_ADD");
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_DELETE, "The port was removed - OFPPR_DELETE");
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_MODIFY, "Some attribute of the port has changed - OFPPR_MODIFY");

    // ofp_error_type
    TYPE_ARRAY(ofp_error_type);
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_HELLO_FAILED, "Hello protocol failed - OFPET_HELLO_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_REQUEST, "Request was not understood - OFPET_BAD_REQUEST");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_ACTION, "Error in action description - OFPET_BAD_ACTION");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_FLOW_MOD_FAILED, "Problem modifying flow entry - OFPET_FLOW_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_PORT_MOD_FAILED, "Port mod request failed - OFPET_PORT_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_QUEUE_OP_FAILED, "Queue operation failed - OFPET_QUEUE_OP_FAILED");

    // ofp_hello_failed_code
    TYPE_ARRAY(ofp_hello_failed_code);
    TYPE_ARRAY_ADD(ofp_hello_failed_code, OFPHFC_INCOMPATIBLE, "No compatible version - OFPHFC_INCOMPATIBLE");
    TYPE_ARRAY_ADD(ofp_hello_failed_code, OFPHFC_EPERM, "Permissions error - OFPHFC_EPERM");

    // ofp_bad_request_code
    TYPE_ARRAY(ofp_bad_request_code);
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_VERSION, "ofp_header.version not supported - OFPBRC_BAD_VERSION");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_TYPE, "ofp_header.type not supported - OFPBRC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_STAT, "ofp_stats_request.type not supported - OFPBRC_BAD_STAT");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_VENDOR, "Vendor not supported - OFPBRC_BAD_VENDOR");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_SUBTYPE, "Vendor subtype not supported - OFPBRC_BAD_SUBTYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_EPERM, "Permissions error - OFPBRC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_LEN, "Wrong request length for type - OFPBRC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_EMPTY, "Specified buffer has already been used - OFPBRC_BUFFER_EMPTY");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_UNKNOWN, "Specified buffer does not exist - OFPBRC_BUFFER_UNKNOWN");

    // ofp_bad_action_code
    TYPE_ARRAY(ofp_bad_action_code);
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TYPE, "Unknown action type - OFPBAC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_LEN, "Length problem in actions - OFPBAC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_VENDOR, "Unknown vendor id specified - OFPBAC_BAD_VENDOR");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_VENDOR_TYPE, "Unknown action for vendor id - OFPBAC_BAD_VENDOR_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_PORT, "Problem validating output port - OFPBAC_BAD_OUT_PORT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_ARGUMENT, "Bad action argument - OFPBAC_BAD_ARGUMENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_EPERM, "Permissions error - OFPBAC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_TOO_MANY, "Can't handle this many actions - OFPBAC_TOO_MANY");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_QUEUE, "Problem validating output queue - OFPBAC_BAD_QUEUE");

    // ofp_flow_mod_failed_code
    TYPE_ARRAY(ofp_flow_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_ALL_TABLES_FULL, "Flow not added because table was full - OFPFMFC_ALL_TABLES_FULL");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_OVERLAP, "Attempted to add overlapping flow with CHECK_OVERLAP flag set - OFPFMFC_OVERLAP");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_EPERM, "Permissions error - OFPFMFC_EPERM");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_EMERG_TIMEOUT, "Flow not added because of unsupported idle/hard timeout - OFPFMFC_BAD_EMERG_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_COMMAND, "Unsupported or unknown command - OFPFMFC_BAD_COMMAND");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_UNSUPPORTED, "Unsupported action list - OFPFMFC_UNSUPPORTED");

    // ofp_port_mod_failed_code
    TYPE_ARRAY(ofp_port_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_PORT, "Specified port number does not exist - OFPPMFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_HW_ADDR, "Specified hardware address does not match the port number - OFPPMFC_BAD_HW_ADDR");

    // ofp_queue_op_failed_code
    TYPE_ARRAY(ofp_queue_op_failed_code);
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_PORT, "Invalid port (or port does not exist) - OFPQOFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_QUEUE, "Queue does not exist - OFPQOFC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_EPERM, "Permissions error - OFPQOFC_EPERM");

    // port_state
    TYPE_ARRAY(port_state);
    TYPE_ARRAY_ADD(port_state, OFPPS_STP_LISTEN, "Not learning or relaying frames");
    TYPE_ARRAY_ADD(port_state, OFPPS_STP_LEARN, "Learning but not relaying frames");
    TYPE_ARRAY_ADD(port_state, OFPPS_STP_FORWARD, "Learning and relaying frames");
    TYPE_ARRAY_ADD(port_state, OFPPS_STP_BLOCK, "Not part of spanning tree(Blocked)");
    TYPE_ARRAY_ADD(port_state, (OFPPS_STP_LISTEN | OFPPS_LINK_DOWN), "Not learning or relaying frames");
    TYPE_ARRAY_ADD(port_state, (OFPPS_STP_LEARN | OFPPS_LINK_DOWN), "Learning but not relaying frames");
    TYPE_ARRAY_ADD(port_state, (OFPPS_STP_FORWARD | OFPPS_LINK_DOWN), "Learning and relaying frames");
    TYPE_ARRAY_ADD(port_state, (OFPPS_STP_BLOCK | OFPPS_LINK_DOWN), "Not part of spanning tree(Blocked)");

//    TYPE_ARRAY(ofp_config_flags);
//    TYPE_ARRAY_ADD(ofp_config_flags, OFPC_FRAG_NORMAL & OFPC_FRAG_MASK, "No special handling for fragments");
//    TYPE_ARRAY_ADD(ofp_config_flags, OFPC_FRAG_DROP & OFPC_FRAG_MASK, "Drop fragments");
//    TYPE_ARRAY_ADD(ofp_config_flags, OFPC_FRAG_REASM & OFPC_FRAG_MASK, "Reassemble (only if OFPC_IP_REASM set)");

    // ofp_queue_property
    TYPE_ARRAY(ofp_queue_property);
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_NONE, "No property defined for queue (default) - OFPQT_NONE");
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_MIN_RATE, "Minimum datarate guaranteed - OFPQT_MIN_RATE");
}

void DissectorContext::setupFlags(void)
{
    // ofp_port_config
    BITMAP_PART("ofp_port_config.OFPPC_PORT_DOWN", "Port is administratively down", 32, OFPPC_PORT_DOWN);
    BITMAP_PART("ofp_port_config.OFPPC_NO_STP", "Disable 802.1D spanning tree on port", 32, OFPPC_NO_STP);
    BITMAP_PART("ofp_port_config.OFPPC_NO_RECV", "Drop all packets received by port", 32, OFPPC_NO_RECV);
    BITMAP_PART("ofp_port_config.OFPPC_NO_RECV_STP", "Drop received 802.1D STP packets", 32, OFPPC_NO_RECV_STP);
    BITMAP_PART("ofp_port_config.OFPPC_NO_FLOOD", "Do not include this port when flooding", 32, OFPPC_NO_FLOOD);
    BITMAP_PART("ofp_port_config.OFPPC_NO_FWD", "Drop packets forwarded to port", 32, OFPPC_NO_FWD);
    BITMAP_PART("ofp_port_config.OFPPC_NO_PACKET_IN", "Do not send packet-in msgs for port", 32, OFPPC_NO_PACKET_IN);
    BITMAP_PART("ofp_port_config.RESERVED", "Reserved", 32, 0xffffff80);

    // ofp_port_state
    BITMAP_PART("ofp_port_state.OFPPS_LINK_DOWN", "No physical link present", 32, OFPPS_LINK_DOWN);
    //BITMAP_PART("ofp_port_state.OFPPS_STP_LISTEN", "Not learning or relaying frames", 32, OFPPS_STP_LISTEN);
    //BITMAP_PART("ofp_port_state.OFPPS_STP_LEARN", "Learning but not relaying frames", 32, OFPPS_STP_LEARN);
    //BITMAP_PART("ofp_port_state.OFPPS_STP_FORWARD", "Learning and relaying frames", 32, OFPPS_STP_FORWARD);
    //BITMAP_PART("ofp_port_state.OFPPS_STP_BLOCK", "Not part of spanning tree", 32, OFPPS_STP_BLOCK);
    //BITMAP_PART("ofp_port_state.OFPPS_STP_MASK", "Bit mask for OFPPS_STP_* values", 32, OFPPS_STP_MASK);
    BITMAP_PART("ofp_port_state.RESERVED", "Reserved", 32, 0xfffffcfe);

    // ofp_port_features
    BITMAP_PART("ofp_port_features.OFPPF_10MB_HD", "10 Mb half-duplex rate support", 32, OFPPF_10MB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_10MB_FD", "10 Mb full-duplex rate support", 32, OFPPF_10MB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_100MB_HD", "100 Mb half-duplex rate support", 32, OFPPF_100MB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_100MB_FD", "100 Mb full-duplex rate support", 32, OFPPF_100MB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_1GB_HD", "1 Gb half-duplex rate support", 32, OFPPF_1GB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_1GB_FD", "1 Gb full-duplex rate support", 32, OFPPF_1GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_10GB_FD", "10 Gb full-duplex rate support", 32, OFPPF_10GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_COPPER", "Copper medium", 32, OFPPF_COPPER);
    BITMAP_PART("ofp_port_features.OFPPF_FIBER", "Fiber medium", 32, OFPPF_FIBER);
    BITMAP_PART("ofp_port_features.OFPPF_AUTONEG", "Auto-negotiation", 32, OFPPF_AUTONEG);
    BITMAP_PART("ofp_port_features.OFPPF_PAUSE", "Pause", 32, OFPPF_PAUSE);
    BITMAP_PART("ofp_port_features.OFPPF_PAUSE_ASYM", "Asymmetric pause", 32, OFPPF_PAUSE_ASYM);
    BITMAP_PART("ofp_port_features.RESERVED", "Reserved", 32, 0xfffff000);

    // ofp_capabilities
    BITMAP_PART("ofp_capabilities.OFPC_FLOW_STATS", "Support flow statistics", 32, OFPC_FLOW_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_TABLE_STATS", "Support table statistics", 32, OFPC_TABLE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_PORT_STATS", "Support port statistics", 32, OFPC_PORT_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_STP", "Support 802.1d spanning tree", 32, OFPC_STP);
    BITMAP_PART("ofp_capabilities.OFPC_RESERVED", "Reserved, must be zero", 32, OFPC_RESERVED);
    BITMAP_PART("ofp_capabilities.OFPC_IP_REASM", "Support can reassemble IP fragments", 32, OFPC_IP_REASM);
    BITMAP_PART("ofp_capabilities.OFPC_QUEUE_STATS", "Support queue statistics", 32, OFPC_QUEUE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_ARP_MATCH_IP", "Support match IP addresses in ARP pkts", 32, OFPC_ARP_MATCH_IP);
    BITMAP_PART("ofp_capabilities.RESERVED", "Reserved", 32, 0xffffff00);

    // ofp_flow_wildcards
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_IN_PORT", "Switch input port", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_IN_PORT);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_VLAN", "VLAN id", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_VLAN);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_SRC", "Ethernet source address", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_SRC);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_DST", "Ethernet destination address", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_DST);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_TYPE", "Ethernet frame type", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_TYPE);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_NW_PROTO", "IP protocol", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_NW_PROTO);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_TP_SRC", "TCP/UDP source port", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_TP_SRC);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_TP_DST", "TCP/UDP destination port", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_TP_DST);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_NW_SRC_MASK", "Source IP Mask", BASE_DEC, VALS(addr_mask), OFPFW_NW_SRC_MASK);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_NW_DST_MASK", "Destination IP Mask", BASE_DEC, VALS(addr_mask), OFPFW_NW_DST_MASK);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_VLAN_PCP", "VLAN priority", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_VLAN_PCP);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_NW_TOS", "IP ToS (DSCP field, 6 bits)", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_NW_TOS);
    //BITMAP_WILDCARD_PART("ofp_flow_wildcards.RESERVED", "Reserved", BASE_DEC, VALS(ts_wildcard_choice), ~OFPFW_ALL);

    //ofp_action_type_bmp
    BITMAP_PART("ofp_action_type_bmp.OFPAT_OUTPUT", "Support output to switch port", 32, 1 << OFPAT_OUTPUT);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_VLAN_VID", "Support set the 802.1q VLAN id", 32, 1 << OFPAT_SET_VLAN_VID);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_VLAN_PCP", "Support set the 802.1q priority", 32, 1 << OFPAT_SET_VLAN_VID);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_STRIP_VLAN", "Support strip the 802.1q header", 32, 1 << OFPAT_STRIP_VLAN);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_DL_SRC", "Support ethernet source address", 32, 1 << OFPAT_SET_DL_SRC);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_DL_DST", "Support ethernet destination address", 32, 1 << OFPAT_SET_DL_DST);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_SRC", "Support IP source address", 32, 1 << OFPAT_SET_NW_SRC);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_DST", "Support IP destination address", 32, 1 << OFPAT_SET_NW_DST);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_TOS", "Support IP ToS (DSCP field, 6 bits)", 32, 1 << OFPAT_SET_NW_TOS);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_TP_SRC", "Support TCP/UDP source port", 32, 1 << OFPAT_SET_TP_SRC);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_TP_DST", "Support TCP/UDP destination port", 32, 1 << OFPAT_SET_TP_DST);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_ENQUEUE", "Support output to queue", 32, 1 << OFPAT_ENQUEUE);
    BITMAP_PART("ofp_action_type_bmp.OFPAT_VENDOR", "Support vendor", 32, 1 << (OFPAT_ENQUEUE + 1));
    BITMAP_PART("ofp_action_type_bmp.RESERVED", "Reserved", 32, 0xffffe000);

    // ofp_config_flags
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_DROP", "Drop fragments", 16, OFPC_FRAG_DROP);
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_REASM", "Reassemble (only if OFPC_IP_REASM set)", 16, OFPC_FRAG_REASM);
    //BITMAP_PART("ofp_config_flags.OFPC_FRAG_MASK", "IP fragments handle mask", 16, OFPC_FRAG_MASK);
    BITMAP_PART("ofp_config_flags.RESERVED", "Reserved", 16, 0xfffC);
    //BITMAP_PART("ofp_config_flags.OFPC_FRAG_NORMAL", "No special handling for fragments", 16, 0xffff);
    FIELD("ofp_config_flags.OFPC_FRAG_NORMAL", "No special handling for fragments", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    // ofp_flow_mod_flags
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", "Send flow removed message when flow expires or is deleted", 16, OFPFF_SEND_FLOW_REM);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", "Check for overlapping entries first", 16, OFPFF_CHECK_OVERLAP);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_EMERG", "Remark this flow is for emergency", 16, OFPFF_EMERG);
    BITMAP_PART("ofp_flow_mod_flags.RESERVED", "Reserved", 16, 0xfff8);

    // ofp_stats_reply_flags
    BITMAP_PART("ofp_stats_reply_flags.OFPSF_REPLY_MORE", "More replies to follow", 16, OFPSF_REPLY_MORE);
    BITMAP_PART("ofp_stats_reply_flags.RESERVED", "Reserved", 16, 0xfffe);
}

} /* namespace */

