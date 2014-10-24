/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2012 Barnstormer Softworks Ltd.
 * Copyright (c) 2013 LittleField
 *   -- modify to common
 */


#define OPENFLOW_INTERNAL

#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <of11/openflow-110.hpp>
#include <openflow-common.hpp>
#include "openflow/of11.h"
#include "field_type.hpp"

#define PROTO_TAG_OPENFLOW_VER "OFP11"

namespace openflow_110
{

DissectorContext * DissectorContext::mSingle = NULL;
DissectorContext * Context;

void DissectorContext::setHandles(dissector_handle_t data, dissector_handle_t openflow)
{
    this->mDataHandle = data;
    this->mOpenflowHandle = openflow;
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

void DissectorContext::prepDissect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW_VER);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    Context->dispatchMessage(tvb, pinfo, tree);
}

DissectorContext *DissectorContext::getInstance(int proto_openflow)
{
    if (mSingle == NULL) {
        mSingle = new DissectorContext(proto_openflow);
    }

    return mSingle;
}

DissectorContext::DissectorContext (int proto_openflow)
                    : mProtoOpenflow(proto_openflow), mFM(proto_openflow, "of11")
{
    Context = this;

    this->_ether_handle = find_dissector("eth_withoutfcs");
    this->setupCodes();
    this->setupFlags();
    this->setupFields();
    this->mFM.doRegister();
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
            case OFPT_ECHO_REQUEST:
            case OFPT_ECHO_REPLY:
                this->dissect_ofp_echo();
                break;
            case OFPT_EXPERIMENTER:
                IGNORE; // We don't know how to dissect
                break;
            case OFPT_FEATURES_REQUEST:
                this->dissect_ofp_feature_request();
                break;
            case OFPT_FEATURES_REPLY:
                this->dissect_ofp_switch_features();
                break;
            case OFPT_GET_CONFIG_REQUEST:
                IGNORE; // Nothing to parse
                break;
            case OFPT_GET_CONFIG_REPLY:
            case OFPT_SET_CONFIG:
                this->dissect_ofp_switch_config();
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
            case OFPT_GROUP_MOD:
                this->dissect_ofp_group_mod();
                break;
            case OFPT_PORT_MOD:
                this->dissect_ofp_port_mod();
                break;
            case OFPT_TABLE_MOD:
                this->dissect_ofp_table_mod();
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
                IGNORE;
                break;
            } /* end of switch */
        } /* end of if (this->_oflen > this->_offset) */
    } /* end of if (this->_tree) */
}

void DissectorContext::dissect_ofp_error(void)
{
    ADD_TREE(err_tree, "ofp_error");

    READ_UINT16(code);
    ADD_CHILD(err_tree, "ofp_error.type", 2);

    #define STR(a) #a
    #define ERROR(value) \
    case value: \
        ADD_CHILD(err_tree, STR(ofp_error.code.value), 2); \
        break;

    // TODO: this can improve...
    switch (code) {
        ERROR(OFPET_HELLO_FAILED)
        ERROR(OFPET_BAD_REQUEST)
        ERROR(OFPET_BAD_ACTION)
        ERROR(OFPET_BAD_INSTRUCTION)
        ERROR(OFPET_BAD_MATCH)
        ERROR(OFPET_FLOW_MOD_FAILED)
        ERROR(OFPET_GROUP_MOD_FAILED)
        ERROR(OFPET_PORT_MOD_FAILED)
        ERROR(OFPET_TABLE_MOD_FAILED)
        ERROR(OFPET_QUEUE_OP_FAILED)
        ERROR(OFPET_SWITCH_CONFIG_FAILED)
        default:
            break;
    }

    if (this->_oflen - this->_offset > 0) {
        ADD_OFDISSECTOR(err_tree, "ofp_error.data", this->_oflen - this->_offset);
    } else {
        ADD_CHILD(err_tree, "ofp_error.data", this->_oflen - this->_offset);
    }
}

void DissectorContext::dissect_ofp_echo(void)
{
    ADD_CHILD(this->_curOFPSubtree, "echo", this->_oflen - this->_offset);
    this->_offset = this->_oflen;
}

void DissectorContext::dissect_ofp_feature_request(void)
{
    ADD_CHILD(this->_curOFPSubtree, "ofp_feature_request", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_switch_features(void)
{
    ADD_TREE(rp_tree, "ofp_switch_features");

    ADD_CHILD(rp_tree, "ofp_switch_features.datapath_id", 8);
    ADD_CHILD(rp_tree, "ofp_switch_features.n_buffers", 4);
    ADD_CHILD(rp_tree, "ofp_switch_features.n_tables", 1);
    ADD_CHILD(rp_tree, "padding", 3);

    READ_UINT32(capabilities);
    ADD_SUBTREE(capabilities_tree, rp_tree, "ofp_switch_features.capabilities", 4);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_FLOW_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_TABLE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_PORT_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_GROUP_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_IP_REASM", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_QUEUE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_ARP_MATCH_IP", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.RESERVED", 4, capabilities);

    ADD_CHILD(rp_tree, "padding", 4);

    // Ports
    // TODO: shouldn't we use a while like in other parts?
    guint32 portlen = this->_oflen - 32;

    if (portlen < 0 || portlen % 64 != 0) {
        // Packet alignment is off, we should probably complain
    } else {
        guint32 ports =  portlen / 64;
        ADD_SUBTREE(port_tree, rp_tree, "ofp_switch_features.ports", portlen);
        ADD_UINT(port_tree, "ofp_switch_features.port_num", 4, ports);
        for (int port = 0; port < ports; ++port) {
            this->dissect_ofp_port(port_tree);
        }
    }
}

void DissectorContext::dissect_ofp_switch_config(void)
{
    ADD_TREE(tree, "ofp_switch_config");

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_switch_config.flags", 2);
    if (flags == 0) {
        ADD_UINT(flags_tree, "ofp_config_flags.OFPC_FRAG_NORMAL", 2, flags);
    } else {
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.RESERVED", 2, flags);
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_FRAG_DROP", 2, flags);
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_FRAG_REASM", 2, flags);
        ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_INVALID_TTL_TO_CONTROLLER", 2, flags);

    }
    CONSUME_BYTES(2);

    ADD_CHILD(tree, "ofp_switch_config.miss_send_len", 2);
}

void DissectorContext::dissect_ofp_flow_stats_request(proto_tree* parent)
{
    ADD_SUBTREE(flow_stat_tree, parent, "ofp_flow_stats_request",
        sizeof(struct ofp_flow_stats_request));
    READ_UINT8(tableid);
    add_child_ofp_table(flow_stat_tree, "ofp_flow_stats_request.table_id", tableid, 1);
    ADD_CHILD(flow_stat_tree, "padding", 3);
    READ_UINT32(portid);
    add_child_ofp_port_no(flow_stat_tree, "ofp_flow_stats_request.out_port", portid, 4);
    READ_UINT32(groupid);
    add_child_ofp_group(flow_stat_tree, "ofp_flow_stats_request.out_group", groupid, 4);
    ADD_CHILD(flow_stat_tree, "padding", 4);
    ADD_CHILD(flow_stat_tree, "ofp_flow_stats_request.cookie", 8);
    ADD_CHILD(flow_stat_tree, "ofp_flow_stats_request.cookie_mask", 8);
    this->dissect_ofp_match(flow_stat_tree);
}

void DissectorContext::dissect_ofp_flow_stats(proto_tree *tree)
{
    guint32 msg_end;

    while ((this->_oflen - this->_offset) > 0) {
        READ_UINT16(length);
        msg_end = this->_offset + length;
        ADD_SUBTREE(flow_stat_tree, tree, "ofp_flow_stats", length);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.length", 2);
        READ_UINT8(tableid);
        add_child_ofp_table(flow_stat_tree, "ofp_flow_stats.table_id", tableid, 1);
        ADD_CHILD(flow_stat_tree, "padding", 1);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.duration_sec", 4);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.duration_nsec", 4);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.priority", 2);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.idle_timeout", 2);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.hard_timeout", 2);
        ADD_CHILD(flow_stat_tree, "padding", 6);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.cookie", 8);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.packet_count", 8);
        ADD_CHILD(flow_stat_tree, "ofp_flow_stats.byte_count", 8);
        this->dissect_ofp_match(flow_stat_tree);

        try {
            while ((msg_end - this->_offset) > 0) {
                this->dissect_ofp_instruction(flow_stat_tree);
            }
        } catch (const ZeroLenInstruction &e) {
            return;
        }
    }
}

void DissectorContext::dissect_ofp_aggregate_stats_request(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_aggregate_stats_request",
        sizeof(struct ofp_aggregate_stats_request));
    READ_UINT8(tableid);
    add_child_ofp_table(tree, "ofp_aggregate_stats_request.table_id", tableid, 1);
    ADD_CHILD(tree, "padding", 3);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_aggregate_stats_request.out_port", portid, 4);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_aggregate_stats_request.out_group", groupid, 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_aggregate_stats_request.cookie", 8);
    ADD_CHILD(tree, "ofp_aggregate_stats_request.cookie_mask", 8);

    this->dissect_ofp_match(tree);
}


void DissectorContext::dissect_ofp_aggregate_stats(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_aggregate_stats_reply",
        sizeof(struct ofp_aggregate_stats_reply));
    ADD_CHILD(tree, "ofp_aggregate_stats_reply.packet_count", 8);
    ADD_CHILD(tree, "ofp_aggregate_stats_reply.byte_count", 8);
    ADD_CHILD(tree, "ofp_aggregate_stats_reply.flow_count", 4);
    ADD_CHILD(tree, "padding", 4);
}

void DissectorContext::dissect_ofp_port_stats_request(proto_tree* parent)
{
    ADD_SUBTREE(port_stat_tree, parent, "ofp_port_stats_request",
        sizeof(struct ofp_port_stats_request));
    READ_UINT32(portid);
    add_child_ofp_port_no(port_stat_tree, "ofp_port_stats_request.port_no", portid, 4);
    ADD_CHILD(port_stat_tree, "padding", 4);
}

void DissectorContext::dissect_ofp_port_stats(proto_tree* parent)
{
    while ((this->_oflen - this->_offset) > 0) {
        ADD_SUBTREE(port_stat_tree, parent, "ofp_port_stats", sizeof(struct ofp_port_stats));
        READ_UINT32(portid);
        add_child_ofp_port_no(port_stat_tree, "ofp_port_stats.port_no", portid, 4);
        ADD_CHILD(port_stat_tree, "padding", 4);
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

void DissectorContext::dissect_ofp_queue_stats_request(proto_tree* parent)
{
    ADD_SUBTREE(queue_stat_tree, parent, "ofp_queue_stats_request",
        sizeof(struct ofp_queue_stats_request));
    READ_UINT32(portid);
    add_child_ofp_port_no(queue_stat_tree, "ofp_queue_stats_request.port_no", portid, 4);
    READ_UINT32(queueid);
    add_child_ofp_queue_id(queue_stat_tree, "ofp_queue_stats_request.queue_id", queueid, 4);
}

void DissectorContext::dissect_ofp_queue_stats(proto_tree* parent)
{
    while ((this->_oflen - this->_offset) > 0) {
        ADD_SUBTREE(queue_stat_tree, parent, "ofp_queue_stats", sizeof(struct ofp_queue_stats));
        READ_UINT32(portid);
        add_child_ofp_port_no(queue_stat_tree, "ofp_queue_stats.port_no", portid, 4);
        READ_UINT32(queueid);
        add_child_ofp_queue_id(queue_stat_tree, "ofp_queue_stats.queue_id", queueid, 4);
        ADD_CHILD(queue_stat_tree, "ofp_queue_stats.tx_bytes", 8);
        ADD_CHILD(queue_stat_tree, "ofp_queue_stats.tx_packets", 8);
        ADD_CHILD(queue_stat_tree, "ofp_queue_stats.tx_errors", 8);
    }
}

void DissectorContext::dissect_ofp_group_stats_request(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_group_stats_request", sizeof(struct ofp_group_stats_request));
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_group_stats_request.group_id", groupid, 4);
    ADD_CHILD(tree, "padding", 4);
}

void DissectorContext::dissect_ofp_group_stats(proto_tree* parent)
{
    READ_UINT16(length);
    guint32 end = this->_offset + length;

    ADD_SUBTREE(tree, parent, "ofp_group_stats", length);
    ADD_CHILD(tree, "ofp_group_stats.length", 2);
    ADD_CHILD(tree, "padding", 2);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_group_stats.group_id", groupid, 4);
    ADD_CHILD(tree, "ofp_group_stats.ref_count", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_group_stats.packet_count", 8);
    ADD_CHILD(tree, "ofp_group_stats.byte_count", 8);

    while (this->_offset < end) {
        ADD_SUBTREE(bucket_tree, tree, "ofp_bucket_counter", sizeof(struct ofp_bucket_counter));
        ADD_CHILD(bucket_tree, "ofp_bucket_counter.packet_count", 8);
        ADD_CHILD(bucket_tree, "ofp_bucket_counter.byte_count", 8);
    }
}

void DissectorContext::dissect_ofp_desc_stats(proto_tree *parent)
{
    ADD_SUBTREE(desc_stat_tree, parent, "ofp_desc_stats", sizeof(struct ofp_desc_stats));
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.mfr_desc", DESC_STR_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.hw_desc", DESC_STR_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.sw_desc", DESC_STR_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.serial_num", SERIAL_NUM_LEN);
    ADD_CHILD(desc_stat_tree, "ofp_desc_stats.dp_desc", DESC_STR_LEN);
}

void DissectorContext::dissect_ofp_table_stats(proto_tree *parent)
{
    ADD_SUBTREE(table_stat_tree, parent, "ofp_table_stats", sizeof(struct ofp_table_stats));
    READ_UINT8(tableid);
    add_child_ofp_table(table_stat_tree, "ofp_table_stats.table_id", tableid, 1);
    ADD_CHILD(table_stat_tree, "padding", 7);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.name", OFP_MAX_TABLE_NAME_LEN);

    READ_UINT32(wildcards);
    ADD_SUBTREE(wct, table_stat_tree, "ofp_table_stats.wildcards", 4);
    this->dissect_ofp_wildcards(wct, wildcards);
    CONSUME_BYTES(4);

    READ_UINT32(match);
    ADD_SUBTREE(mt, table_stat_tree, "ofp_table_stats.match", 4);
    this->dissect_ofp_flow_match_field(mt, match);
    CONSUME_BYTES(4);

    READ_UINT32(instbmp);
    ADD_SUBTREE(inst, table_stat_tree, "ofp_table_stats.instructions", 4);
    this->dissect_ofp_instruction_type_bmp(inst, instbmp);
    CONSUME_BYTES(4);

    READ_UINT32(wract);
    ADD_SUBTREE(wrt, table_stat_tree, "ofp_table_stats.write_actions", 4);
    this->dissect_ofp_action_type_bmp(wrt, wract);
    CONSUME_BYTES(4);

    READ_UINT32(appact);
    ADD_SUBTREE(apt, table_stat_tree, "ofp_table_stats.apply_actions", 4);
    this->dissect_ofp_action_type_bmp(apt, appact);
    CONSUME_BYTES(4);

    READ_UINT32(config);
    ADD_SUBTREE(config_tree, table_stat_tree, "ofp_table_stats.config", 4);
    if (config == 0) {
        ADD_UINT(config_tree, "ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", 4, config);
    } else {
        ADD_BOOLEAN(config_tree, "ofp_table_config.OFPTC_TABLE_MISS_CONTINUE", 4, config);
        ADD_BOOLEAN(config_tree, "ofp_table_config.OFPTC_TABLE_MISS_DROP", 4, config);
        ADD_BOOLEAN(config_tree, "ofp_table_config.RESERVED", 4, config);
    }
    CONSUME_BYTES(4);

    ADD_CHILD(table_stat_tree, "ofp_table_stats.max_entries", 4);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.active_count", 4);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.lookup_count", 8);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.matched_count", 8);
}

void DissectorContext::dissect_ofp_group_bucket(proto_tree* parent)
{
    READ_UINT16(len);

    if (len == 0) {
        throw ZeroLenBucket();
    }

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_group_bucket", len);
    ADD_CHILD(tree, "ofp_group_bucket.len", 2);
    ADD_CHILD(tree, "ofp_group_bucket.weight", 2);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_group_bucket.watch_port", portid, 4);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_group_bucket.watch_group", groupid, 4);
    ADD_CHILD(tree, "padding", 4);

    try {
        while (this->_offset < message_end) {
            this->dissect_ofp_action(tree);
        }
    } catch(const ZeroLenAction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_group_desc(proto_tree* parent)
{
    READ_UINT16(length);
    guint32 end = this->_offset + length;

    ADD_SUBTREE(tree, parent, "ofp_group_desc", sizeof(struct ofp_group_desc_stats));
    ADD_CHILD(tree, "ofp_group_desc.length", 2);
    ADD_CHILD(tree, "ofp_group_desc.type", 1);
    ADD_CHILD(tree, "padding", 1);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_group_desc.group_id", groupid, 4);

    try {
        while((this->_offset < end)) {
            this->dissect_ofp_group_bucket(tree);
        }
    } catch (const ZeroLenBucket &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_stats_experimenter(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_experimenter_multipart_header", this->_oflen - this->_offset);
    ADD_CHILD(tree, "ofp_experimenter_multipart_header.experimenter", 4);
    ADD_CHILD(tree, "ofp_experimenter_multipart_header.data", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_stats_request(void)
{
    ADD_TREE(tree, "ofp_stats_request");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_stats_request.type", 2);
    ADD_CHILD(tree, "ofp_stats_request.flags", 2);

    switch (type) {
    case OFPST_FLOW:
        this->dissect_ofp_flow_stats_request(tree);
        break;
    case OFPST_AGGREGATE:
        this->dissect_ofp_aggregate_stats_request(tree);
        break;
    case OFPST_PORT:
        this->dissect_ofp_port_stats_request(tree);
        break;
    case OFPST_QUEUE:
        this->dissect_ofp_queue_stats_request(tree);
        break;
    case OFPST_GROUP:
        this->dissect_ofp_group_stats_request(tree);
        break;
    case OFPST_EXPERIMENTER:
        this->dissect_ofp_stats_experimenter(tree);
        break;
    case OFPST_GROUP_DESC:
    case OFPST_DESC:
    case OFPST_TABLE:
        this->_offset += this->_oflen - this->_offset;
        break;
    default:
        ADD_CHILD(tree, "ofp_stats_request.body", this->_oflen - this->_offset);
        break;
    }
}

void DissectorContext::dissect_ofp_stats_reply(void)
{
    ADD_TREE(tree, "ofp_stats_reply");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_stats_reply.type", 2);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_stats_reply.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_stats_reply_flags.OFPSF_REPLY_MORE", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_stats_reply_flags.RESERVED", 2, flags);
    CONSUME_BYTES(2);

    ADD_CHILD(tree, "padding", 4);
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
    case OFPST_GROUP:
        this->dissect_ofp_group_stats(tree);
        break;
    case OFPST_GROUP_DESC:
        this->dissect_ofp_group_desc(tree);
        break;
    case OFPST_EXPERIMENTER:
        this->dissect_ofp_stats_experimenter(tree);
        break;
    default:
        ADD_CHILD(tree, "ofp_stats_reply.body", this->_oflen - this->_offset);
        break;
    }
}

void DissectorContext::dissect_ofp_flow_remove(void)
{
    ADD_TREE(tree, "ofp_flow_removed");

    ADD_CHILD(tree, "ofp_flow_removed.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_removed.priority", 2);
    ADD_CHILD(tree, "ofp_flow_removed.reason", 1);
    READ_UINT8(tableid);
    add_child_ofp_table(tree, "ofp_flow_removed.table_id", tableid, 1);
    ADD_CHILD(tree, "ofp_flow_removed.duration_sec", 4);
    ADD_CHILD(tree, "ofp_flow_removed.duration_nsec", 4);
    ADD_CHILD(tree, "ofp_flow_removed.idle_timeout", 2);
    ADD_CHILD(tree, "padding", 2);
    ADD_CHILD(tree, "ofp_flow_removed.packet_count", 8);
    ADD_CHILD(tree, "ofp_flow_removed.byte_count", 8);

    this->dissect_ofp_match(tree);
}

void DissectorContext::dissect_ofp_port_status (void)
{
    ADD_TREE(tree, "ofp_port_status");

    ADD_CHILD(tree, "ofp_port_status.reason", 1);
    ADD_CHILD(tree, "padding", 7);

    ADD_SUBTREE(desc_tree, tree, "ofp_port_status.desc", this->_oflen - this->_offset);
    while ((this->_oflen - this->_offset) > 0) {
        this->dissect_ofp_port(desc_tree);
    }
}

void DissectorContext::dissect_ofp_packet_in(void)
{
    ADD_TREE(tree, "ofp_packet_in");

    ADD_CHILD(tree, "ofp_packet_in.buffer_id", 4);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_packet_in.in_port", portid, 4);
    ADD_CHILD(tree, "ofp_packet_in.in_phy_port", 4);
    ADD_CHILD(tree, "ofp_packet_in.total_len", 2);
    ADD_CHILD(tree, "ofp_packet_in.reason", 1);
    READ_UINT8(tableid);
    add_child_ofp_table(tree, "ofp_packet_in.table_id", tableid, 1);

    if (this->_oflen - this->_offset > 0) {
        ADD_DISSECTOR(tree, "ofp_packet_in.data", this->_oflen - this->_offset);
    } else {
        ADD_CHILD(tree, "ofp_packet_in.data", this->_oflen - this->_offset);
    }
}

void DissectorContext::dissect_ofp_packet_out(void)
{
    ADD_TREE(tree, "ofp_packet_out");

    ADD_CHILD(tree, "ofp_packet_out.buffer_id", 4);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_packet_out.in_port", portid, 4);
    READ_UINT16(actions_len);
    ADD_CHILD(tree, "ofp_packet_out.actions_len", 2);
    ADD_CHILD(tree, "padding", 6);

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

void DissectorContext::dissect_ofp_flow_mod(void)
{
    ADD_TREE(tree, "ofp_flow_mod");

    ADD_CHILD(tree, "ofp_flow_mod.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_mod.cookie_mask", 8);
    ADD_CHILD(tree, "ofp_flow_mod.tableid", 1);
    ADD_CHILD(tree, "ofp_flow_mod.command", 1);
    ADD_CHILD(tree, "ofp_flow_mod.idle_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_mod.hard_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_mod.priority", 2);
    ADD_CHILD(tree, "ofp_flow_mod.buffer_id", 4);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_flow_mod.out_port", portid, 4);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_flow_mod.out_group", groupid, 4);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_flow_mod.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", 2, flags);
    CONSUME_BYTES(2);

    ADD_CHILD(tree, "padding", 2);

    this->dissect_ofp_match(tree);

    try {
        while ((this->_oflen - this->_offset) > 0) {
            this->dissect_ofp_instruction(tree);
        }
    } catch (const ZeroLenInstruction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_group_mod(void)
{
    ADD_TREE(tree, "ofp_group_mod");

    ADD_CHILD(tree, "ofp_group_mod.command", 2);
    ADD_CHILD(tree, "ofp_group_mod.type", 1);
    ADD_CHILD(tree, "padding", 1);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_group_mod.groupid", groupid, 4);

    try {
        while((this->_oflen - this->_offset) > 0) {
            this->dissect_ofp_group_bucket(tree);
        }
    } catch (const ZeroLenBucket &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_table_mod(void)
{
    ADD_TREE(tree, "ofp_table_mod");

    READ_UINT8(tableid);
    add_child_ofp_table(tree, "ofp_table_mod.id", tableid, 1);

    ADD_CHILD(tree, "padding", 3);

    READ_UINT32(config);
    ADD_SUBTREE(config_tree, tree, "ofp_table_mod.config", 4);
    if (config == 0) {
        ADD_UINT(config_tree, "ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", 4, config);
    } else {
        ADD_BOOLEAN(config_tree, "ofp_table_config.OFPTC_TABLE_MISS_CONTINUE", 4, config);
        ADD_BOOLEAN(config_tree, "ofp_table_config.OFPTC_TABLE_MISS_DROP", 4, config);
        ADD_BOOLEAN(config_tree, "ofp_table_config.RESERVED", 4, config);
    }
    CONSUME_BYTES(4);
}

void DissectorContext::dissect_ofp_port_mod(void)
{
    ADD_TREE(tree, "ofp_port_mod");

    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_port_mod.port_no", portid, 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_port_mod.hw_addr", 6);
    ADD_CHILD(tree, "padding", 2);

    ADD_SUBTREE(config_tree, tree, "ofp_port_mod.config", 4);
    READ_UINT32(ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.RESERVED", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(mask_tree, tree, "ofp_port_mod.mask", 4);
    READ_UINT32(mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_RECV", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_FWD", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, mask);
    ADD_BOOLEAN(mask_tree, "ofp_port_config.RESERVED", 4, mask);
    CONSUME_BYTES(4);

    ADD_SUBTREE(advertised_tree, tree, "ofp_port_mod.advertised", 4);
    dissect_ofppf(advertised_tree);

    ADD_CHILD(tree, "padding", 4);
}

void DissectorContext::dissect_ofp_port (proto_tree *tree)
{
    ADD_SUBTREE(t, tree, "ofp_port", sizeof(struct ofp_port));

    READ_UINT32(portid);
    add_child_ofp_port_no(t, "ofp_port.num", portid, 4);
    ADD_CHILD(t, "padding", 4);
    ADD_CHILD(t, "ofp_port.hwaddr", OFP_ETH_ALEN);
    ADD_CHILD(t, "padding", 2);
    ADD_CHILD(t, "ofp_port.name", OFP_MAX_PORT_NAME_LEN);

    ADD_SUBTREE(config_tree, t, "ofp_port.config", 4);
    READ_UINT32(ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.RESERVED", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(state_tree, t, "ofp_port.state", 4);
    READ_UINT32(ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LINK_DOWN", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_BLOCKED", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LIVE", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.RESERVED", 4, ofpps);
    CONSUME_BYTES(4);

    ADD_SUBTREE(curr_feats_tree, t, "ofp_port.curr_feats", 4);
    this->dissect_ofppf(curr_feats_tree);

    ADD_SUBTREE(advertised_tree, t, "ofp_port.advertised", 4);
    this->dissect_ofppf(advertised_tree);

    ADD_SUBTREE(supported_tree, t, "ofp_port.supported", 4);
    this->dissect_ofppf(supported_tree);

    ADD_SUBTREE(peer_tree, t, "ofp_port.peer", 4);
    this->dissect_ofppf(peer_tree);

    ADD_CHILD(t, "ofp_port.curr_speed", 4);
    ADD_CHILD(t, "ofp_port.max_speed", 4);
}

void DissectorContext::dissect_ofppf(proto_tree *tree)
{
    READ_UINT32(ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.RESERVED", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10MB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10MB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100MB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100MB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1GB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_40GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1TB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_OTHER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_COPPER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_FIBER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_AUTONEG", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_PAUSE", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_PAUSE_ASYM", 4, ofppf);
    CONSUME_BYTES(4);
}

void DissectorContext::dissect_ofp_wildcards(proto_tree *wct, guint32 wildcards)
{
#if 0
    // This creates the wildcards as the standard bit-tree view in the UI
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_IN_PORT", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN_PCP", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_DL_TYPE", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_NW_TOS", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_NW_PROTO", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_TP_SRC", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_TP_DST", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_MPLS_LABEL", 4, wildcards);
    ADD_BOOLEAN(wct, "ofp_flow_wildcards.OFPFW_MPLS_TC", 4, wildcards);
    //ADD_BOOLEAN(wct, "ofp_flow_wildcards.RESERVED", 4, wildcards);
#else
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_IN_PORT", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_VLAN_PCP", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_DL_TYPE", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_NW_TOS", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_NW_PROTO", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_TP_SRC", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_TP_DST", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_MPLS_LABEL", 4);
    ADD_CHILD_CONST(wct, "ofp_flow_wildcards.OFPFW_MPLS_TC", 4);
#endif
}

void DissectorContext::dissect_ofp_flow_match_field(proto_tree *mt, guint32 match)
{
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_IN_PORT", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_DL_VLAN", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_DL_VLAN_PCP", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_DL_TYPE", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_NW_TOS", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_NW_PROTO", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_TP_SRC", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_TP_DST", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_MPLS_LABEL", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_MPLS_TC", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_TYPE", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_DL_SRC", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_DL_DST", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_NW_SRC", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_NW_DST", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPFMF_METADATA", 4, match);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.RESERVED", 4, match);
}

void DissectorContext::dissect_ofp_action_type_bmp(proto_tree *mt, guint32 actbmp)
{
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_OUTPUT", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_VLAN_VID", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_VLAN_PCP", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_DL_SRC", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_DL_DST", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_NW_SRC", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_NW_DST", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_NW_TOS", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_NW_ECN", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_TP_SRC", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_TP_DST", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_COPY_TTL_OUT", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_COPY_TTL_IN", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_MPLS_LABEL", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_MPLS_TC", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_MPLS_TTL", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_DEC_MPLS_TTL", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_PUSH_VLAN", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_POP_VLAN", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_PUSH_MPLS", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_POP_MPLS", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_QUEUE", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_GROUP", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_NW_TTL", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_DEC_NW_TTL", 4, actbmp);
}

void DissectorContext::dissect_ofp_instruction_type_bmp(proto_tree *mt, guint32 instbmp)
{
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_GOTO_TABLE", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_WRITE_METADATA", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_WRITE_ACTIONS", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_APPLY_ACTIONS", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_CLEAR_ACTIONS", 4, instbmp);
}

void DissectorContext::dissect_ofp_match(proto_tree *tree)
{
    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset + 2);

    ADD_SUBTREE(t, tree, "ofp_match", len);

#define CHECK_WILDCARD(m,t,f,l) \
    if (wildcards & (m)) { \
        CONSUME_BYTES(l); \
    } else  { \
        ADD_CHILD(t,f,l); \
    }

    /*FIXME: We should care if the type isn't STANDARD (0x00) */
    // We're going to grab the wildcards so we can selectively display info in the tree
    // CHECK_WILDCARD requires this local to exist
    guint32 wildcards = tvb_get_ntohl(this->_tvb, this->_offset + 8);

    ADD_CHILD(t, "ofp_match.type", 2);
    ADD_CHILD(t, "ofp_match.length", 2);
    if (wildcards & (OFPFW_IN_PORT)) {
        this->_offset += 4;
    } else  {
        READ_UINT32(portid);
        add_child_ofp_port_no(t, "ofp_match.in_port", portid, 4);
    }
    //CHECK_WILDCARD(OFPFW_IN_PORT, t, "ofp_match.in_port", 4);

    ADD_SUBTREE(wct, t, "ofp_match.wildcards", 4);
    this->dissect_ofp_wildcards(wct, wildcards);
    CONSUME_BYTES(4);

    ADD_CHILD(t, "ofp_match.dl_src", 6);
    ADD_CHILD(t, "ofp_match.dl_src_mask", 6);
    ADD_CHILD(t, "ofp_match.dl_dst", 6);
    ADD_CHILD(t, "ofp_match.dl_dst_mask", 6);

    //CHECK_WILDCARD(OFPFW_DL_VLAN, t, "ofp_match.dl_vlan", 2);
    if (wildcards & (OFPFW_DL_VLAN)) {
        this->_offset += 2;
    } else  {
        READ_UINT16(vlanid);
        add_child_ofp_vlanid(t, "ofp_match.dl_vlan", vlanid, 2);
    }
    CHECK_WILDCARD(OFPFW_DL_VLAN_PCP, t, "ofp_match.dl_vlan_pcp", 1);
    ADD_CHILD(t, "padding", 1);
    CHECK_WILDCARD(OFPFW_DL_TYPE, t, "ofp_match.dl_type", 2);
    CHECK_WILDCARD(OFPFW_NW_TOS, t, "ofp_match.nw_tos", 1);
    CHECK_WILDCARD(OFPFW_NW_PROTO, t, "ofp_match.nw_proto", 1);

    ADD_CHILD(t, "ofp_match.nw_src", 4);
    ADD_CHILD(t, "ofp_match.nw_src_mask", 4);
    ADD_CHILD(t, "ofp_match.nw_dst", 4);
    ADD_CHILD(t, "ofp_match.nw_dst_mask", 4);

    CHECK_WILDCARD(OFPFW_TP_SRC, t, "ofp_match.tp_src", 2);
    CHECK_WILDCARD(OFPFW_TP_DST, t, "ofp_match.tp_dst", 2);

    CHECK_WILDCARD(OFPFW_MPLS_LABEL, t, "ofp_match.mpls_label", 4);
    CHECK_WILDCARD(OFPFW_MPLS_TC, t, "ofp_match.mpls_tc", 1);
    ADD_CHILD(t, "padding", 3);

    ADD_CHILD(t, "ofp_match.metadata", 8);
    ADD_CHILD(t, "ofp_match.metadata_mask", 8);
}

void DissectorContext::dissect_ofp_instruction(proto_tree *parent)
{
    guint16 len;
    READ_UINT16(type);
    len = tvb_get_ntohs(this->_tvb, this->_offset + 2);

    guint32 message_end = this->_offset + len;
    if (len == 0) {
        throw ZeroLenInstruction();
        return;
    }

    ADD_SUBTREE(tree, parent, "ofp_instruction", len);
    ADD_CHILD(tree, "ofp_instruction.type", 2);
    ADD_CHILD(tree, "ofp_instruction.len", 2);

    // If we have just a header, stop here
    if (len <= 4) {
        return;
    }

    switch (type) {
    case OFPIT_GOTO_TABLE: {
        READ_UINT8(tableid);
        add_child_ofp_table(tree, "ofp_instruction_goto_table.table_id", tableid, 1);
        ADD_CHILD(tree, "padding", 3);
        break;
    }
    case OFPIT_WRITE_METADATA:
        ADD_CHILD(tree, "padding", 4);
        ADD_CHILD(tree, "ofp_instruction_write_metadata.metadata", 8);
        ADD_CHILD(tree, "ofp_instruction_write_metadata.metadata_mask", 8);
        break;
    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
        ADD_CHILD(tree, "padding", 4);
        try {
            while (this->_offset < message_end) {
                this->dissect_ofp_action(tree);
            }
        } catch (const ZeroLenAction &e) {
            break;
        }
        break;
    case OFPIT_CLEAR_ACTIONS:
        ADD_CHILD(tree, "padding", 4);
        break;
    default:
        // Unknown type
        CONSUME_BYTES(message_end - this->_offset);
        break;
    }
}

void DissectorContext::dissect_ofp_action(proto_tree *parent)
{
    guint16 len;
    READ_UINT16(type);
    len = tvb_get_ntohs(this->_tvb, this->_offset + 2);

    if (len == 0) {
        throw ZeroLenAction();
    }

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(t, parent, "ofp_action", len);
    ADD_CHILD(t, "ofp_action.type", 2);
    ADD_CHILD(t, "ofp_action.len", 2);

    switch (type) {
    case OFPAT_OUTPUT: {        // OUTPUT
        READ_UINT32(portid);
        add_child_ofp_port_no(t, "ofp_action_output.port", portid, 4);
        ADD_CHILD(t, "ofp_action_output.max_len", 2);
        ADD_CHILD(t, "padding", 6);
        break;
    }
    case OFPAT_SET_VLAN_VID: {   // SET_VLAN_VID
        READ_UINT16(vlanid);
        add_child_ofp_vlanid(t, "ofp_action_set_vlan_vid.vlan_vid", vlanid, 2);
        ADD_CHILD(t, "padding", 2);
        break;
    }
    case OFPAT_SET_VLAN_PCP:    // SET_VLAN_PCP
        ADD_CHILD(t, "ofp_action_set_vlan_pcp.vlan_pcp", 1);
        ADD_CHILD(t, "padding", 3);
        break;
    case OFPAT_SET_DL_SRC:      // SET_DL_SRC
        ADD_CHILD(t, "ofp_action_set_dl_src.dl_addr", 6);
        ADD_CHILD(t, "padding", 6);
        break;
    case OFPAT_SET_DL_DST:      // SET_DL_DST
        ADD_CHILD(t, "ofp_action_set_dl_dst.dl_addr", 6);
        ADD_CHILD(t, "padding", 6);
        break;
    case OFPAT_SET_NW_SRC:      // SET_NW_SRC
        ADD_CHILD(t, "ofp_action_set_nw_src.nw_addr", 4);
        break;
    case OFPAT_SET_NW_DST:      // SET_NW_DST
        ADD_CHILD(t, "ofp_action_set_nw_dst.nw_addr", 4);
        break;
    case OFPAT_SET_NW_TOS:      // SET_NW_TOS
        ADD_CHILD(t, "ofp_action_set_nw_tos.nw_tos", 1);
        ADD_CHILD(t, "padding", 3);
        break;
    case OFPAT_SET_NW_ECN:      // SET_NW_ECN
        ADD_CHILD(t, "ofp_action_set_nw_ecn.nw_ecn", 1);
        ADD_CHILD(t, "padding", 3);
        break;
    case OFPAT_SET_TP_SRC:      // SET_TP_SRC
        ADD_CHILD(t, "ofp_action_set_src_tp_port.tp_port", 2);
        ADD_CHILD(t, "padding", 2);
        break;
    case OFPAT_SET_TP_DST:      // SET_TP_DST
        ADD_CHILD(t, "ofp_action_set_dst_tp_port.tp_port", 2);
        ADD_CHILD(t, "padding", 2);
        break;
    case OFPAT_COPY_TTL_OUT:    // COPY_TTL_OUT
    case OFPAT_COPY_TTL_IN:     // COPY_TTL_IN
        ADD_CHILD(t, "padding", 4);
        break;
    case OFPAT_SET_MPLS_LABEL:  // SET_MPLS_LABEL
        ADD_CHILD(t, "ofp_action_set_mpls_label.mpls_label", 4);
        break;
    case OFPAT_SET_MPLS_TC:     // SET_MPLS_TC
        ADD_CHILD(t, "ofp_action_set_mpls_tc.mpls_tc", 1);
        ADD_CHILD(t, "padding", 3);
        break;
    case OFPAT_SET_MPLS_TTL:    // SET_MPLS_TTL
        ADD_CHILD(t, "ofp_action_set_mpls_ttl.mpls_ttl", 1);
        ADD_CHILD(t, "padding", 3);
        break;
    case OFPAT_DEC_MPLS_TTL:    // DEC_MPLS_TTL
    case OFPAT_DEC_NW_TTL:      // DEC_NW_TTL
        ADD_CHILD(t, "padding", 4);
        break;
    case OFPAT_PUSH_VLAN:       // PUSH_VLAN
    case OFPAT_PUSH_MPLS:       // PUSH_MPLS
        ADD_CHILD(t, "ofp_action_push.ethertype", 2);
        ADD_CHILD(t, "padding", 2);
        break;
    case OFPAT_POP_VLAN:        // POP_VLAN
        ADD_CHILD(t, "padding", 4);
        break;
    case OFPAT_POP_MPLS:        // POP_MPLS
        ADD_CHILD(t, "ofp_action_pop_mpls.ethertype", 4);
        break;
    case OFPAT_SET_QUEUE: {      // SET_QUEUE
        READ_UINT32(queueid);
        add_child_ofp_queue_id(t, "ofp_action_set_queue.queue_id", queueid, 4);
        break;
    }
    case OFPAT_GROUP:  {         // GROUP
        READ_UINT32(groupid);
        add_child_ofp_group(t, "ofp_action_group.group_id", groupid, 4);
        break;
    }
    case OFPAT_SET_NW_TTL:      // SET_NW_TTL
        ADD_CHILD(t, "ofp_action_set_nw_ttl.nw_ttl", 1);
        ADD_CHILD(t, "padding", 3);
        break;
    case OFPAT_EXPERIMENTER:    // EXPERIMENTER
        ADD_CHILD(t, "ofp_action_experimenter_header.experimenter", 4);
        break;
    default:
        CONSUME_BYTES(message_end - this->_offset);
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
    msg_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_packet_queue", len);

    READ_UINT32(queueid);
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

    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_queue_get_config_request.port", portid, 4);
    ADD_CHILD(tree, "padding", 4);
}

void DissectorContext::dissect_ofp_queue_get_config_reply(void)
{
    ADD_TREE(tree, "ofp_queue_get_config_reply");

    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_queue_get_config_reply.port", portid, 4);
    ADD_CHILD(tree, "padding", 4);

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
    default:
        str_table = str_tblid;
        snprintf(str_tblid, 6, "%u", tableid);
        str_tblid[5] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_table);
}

void DissectorContext::add_child_ofp_group(proto_tree* tree, const char *field, guint32 groupid,
                        guint32 len)
{
    const char* str_group = NULL;
    char str_gid[20];

    switch (groupid) {
    case OFPG_MAX:
        str_group = "OFPG_MAX(0xFFFFFF00) - Last usable group number";
        break;
    case OFPG_ANY:
        str_group = "OFPG_ANY(0xFFFFFFFF) - Selects all flows regardless of group";
        break;
    case OFPG_ALL:
        str_group = "OFPG_ALL(0xFFFFFFFC) - Represents all groups for group delete commands";
        break;
    default:
        str_group = str_gid;
        snprintf(str_gid, 20, "%u", groupid);
        str_gid[19] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_group);
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
    case OFPVID_ANY:
        str_vlan = "OFPVID_ANY(0xFFFE) - Indicate that a VLAN id is set but don't care about it's value";
        break;
    case OFPVID_NONE:
        str_vlan = "OFPVID_NONE(0xFFFF) - No VLAN id was set";
        break;
    default:
        str_vlan = str_vid;
        snprintf(str_vid, 10, "%u", vlanid);
        str_vid[9] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_vlan);
}

void DissectorContext::add_child_ofp_port_no(proto_tree* tree, const char *field, guint32 portid,
                        guint32 len)
{
    const char* str_port = NULL;
    char str_pid[20];

    switch (portid) {
    case OFPP_MAX:
        str_port = "OFPP_MAX(0xFFFFFF00) - Maximum number of physical and logical switch ports";
        break;
    case OFPP_IN_PORT:
        str_port = "OFPP_IN_PORT(0xFFFFFFF8) - Send the packet out the input port";
        break;
    case OFPP_TABLE:
        str_port = "OFPP_TABLE(0xFFFFFFF9) - Submit the packet to the first flow table";
        break;
    case OFPP_NORMAL:
        str_port = "OFPP_NORMAL(0xFFFFFFFA) - Process with normal L2/L3 switching";
        break;
    case OFPP_FLOOD:
        str_port = "OFPP_FLOOD(0xFFFFFFFB) - All physical ports in VLAN, except input port and those blocked or link down";
        break;
    case OFPP_ALL:
        str_port = "OFPP_ALL(0xFFFFFFFC) - All physical ports except input port";
        break;
    case OFPP_CONTROLLER:
        str_port = "OFPP_CONTROLLER(0xFFFFFFFD) - Send to controller";
        break;
    case OFPP_LOCAL:
        str_port = "OFPP_LOCAL(0xFFFFFFFE) - Local openflow \"port\"";
        break;
    case OFPP_ANY:
        str_port = "OFPP_ANY(0xFFFFFFFF) - Any port. For flow mod (delete) and flow stats requests only";
        break;
    default:
        str_port = str_pid;
        snprintf(str_pid, 20, "%u", portid);
        str_pid[19] = '\0';
        break;
    }

    ADD_CHILD_STR(tree, field, len, str_port);
}

void DissectorContext::setupFlags(void)
{
    // ofp_capabilities
    BITMAP_PART("ofp_capabilities.OFPC_FLOW_STATS", "Support flow statistics", 32, OFPC_FLOW_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_TABLE_STATS", "Support table statistics", 32, OFPC_TABLE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_PORT_STATS", "Support port statistics", 32, OFPC_PORT_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_GROUP_STATS", "Support group statistics", 32, OFPC_GROUP_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_IP_REASM", "Support can reassemble IP fragments", 32, OFPC_IP_REASM);
    BITMAP_PART("ofp_capabilities.OFPC_QUEUE_STATS", "Support queue statistics", 32, OFPC_QUEUE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_ARP_MATCH_IP", "Support match IP addresses in ARP pkts", 32, OFPC_ARP_MATCH_IP);
    BITMAP_PART("ofp_capabilities.RESERVED", "Reserved", 32, 0xffffff80);

    // ofp_port_config
    BITMAP_PART("ofp_port_config.OFPPC_PORT_DOWN", "Port is administratively down", 32, OFPPC_PORT_DOWN);
    BITMAP_PART("ofp_port_config.OFPPC_NO_RECV", "Drop all packets received by port", 32, OFPPC_NO_RECV);
    BITMAP_PART("ofp_port_config.OFPPC_NO_FWD", "Drop packets forwarded to port", 32, OFPPC_NO_FWD);
    BITMAP_PART("ofp_port_config.OFPPC_NO_PACKET_IN", "Do not send packet-in msgs for port", 32, OFPPC_NO_PACKET_IN);
    BITMAP_PART("ofp_port_config.RESERVED", "Reserved", 32, 0xFFFFFF9A);

    // ofp_port_state
    BITMAP_PART("ofp_port_state.OFPPS_LINK_DOWN", "No physical link present", 32, OFPPS_LINK_DOWN);
    BITMAP_PART("ofp_port_state.OFPPS_BLOCKED", "Port is blocked", 32, OFPPS_BLOCKED);
    BITMAP_PART("ofp_port_state.OFPPS_LIVE", "Live for Fast Failover Group", 32, OFPPS_LIVE);
    BITMAP_PART("ofp_port_state.RESERVED", "Reserved", 32, 0xFFFFFFF8);

    // ofp_port_features
    BITMAP_PART("ofp_port_features.OFPPF_10MB_HD", "10 Mb half-duplex rate support", 32, OFPPF_10MB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_10MB_FD", "10 Mb full-duplex rate support", 32, OFPPF_10MB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_100MB_HD", "100 Mb half-duplex rate support", 32, OFPPF_100MB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_100MB_FD", "100 Mb full-duplex rate support", 32, OFPPF_100MB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_1GB_HD", "1 Gb half-duplex rate support", 32, OFPPF_1GB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_1GB_FD", "1 Gb full-duplex rate support", 32, OFPPF_1GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_10GB_FD", "10 Gb full-duplex rate support", 32, OFPPF_10GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_40GB_FD", "40 Gb full-duplex rate support", 32, OFPPF_40GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_100GB_FD", "100 Gb full-duplex rate support", 32, OFPPF_100GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_1TB_FD", "1 Tb full-duplex rate support", 32, OFPPF_1TB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_OTHER", "Other rate, not in the list", 32, OFPPF_OTHER);
    BITMAP_PART("ofp_port_features.OFPPF_COPPER", "Copper medium", 32, OFPPF_COPPER);
    BITMAP_PART("ofp_port_features.OFPPF_FIBER", "Fiber medium", 32, OFPPF_FIBER);
    BITMAP_PART("ofp_port_features.OFPPF_AUTONEG", "Auto-negotiation", 32, OFPPF_AUTONEG);
    BITMAP_PART("ofp_port_features.OFPPF_PAUSE", "Pause", 32, OFPPF_PAUSE);
    BITMAP_PART("ofp_port_features.OFPPF_PAUSE_ASYM", "Asymmetric pause", 32, OFPPF_PAUSE_ASYM);
    BITMAP_PART("ofp_port_features.RESERVED", "Reserved", 32, 0xffff0000);

    // ofp_config_flags
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_DROP", "Drop fragments", 16, OFPC_FRAG_DROP);
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_REASM", "Reassemble (only if OFPC_IP_REASM set)", 16, OFPC_FRAG_REASM);
    BITMAP_PART("ofp_config_flags.OFPC_INVALID_TTL_TO_CONTROLLER", "Send packets with invalid TTL to the controller", 16, OFPC_INVALID_TTL_TO_CONTROLLER);
    BITMAP_PART("ofp_config_flags.RESERVED", "Reserved", 16, 0xfff8);
    //BITMAP_PART("ofp_config_flags.OFPC_FRAG_NORMAL", "No special handling for fragments", 16, 0xffff);
    FIELD("ofp_config_flags.OFPC_FRAG_NORMAL", "No special handling for fragments", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    // ofp_flow_wildcards
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_IN_PORT", "Switch input port", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_IN_PORT);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_VLAN", "VLAN id", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_VLAN);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_VLAN_PCP", "VLAN pcp", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_VLAN_PCP);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_DL_TYPE", "Ethernet frame type", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_TYPE);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_NW_TOS", "IP ToS (DSCP field, 6 bits)", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_NW_TOS);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_NW_PROTO", "IP protocol", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_NW_PROTO);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_TP_SRC", "TCP/UDP/SCTP source por", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_TP_SRC);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_TP_DST", "TCP/UDP/SCTP destination port", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_TP_DST);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_MPLS_LABEL", "MPLS label", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_MPLS_LABEL);
    BITMAP_WILDCARD_PART("ofp_flow_wildcards.OFPFW_MPLS_TC", "MPLS TC", BASE_DEC, VALS(ts_wildcard_choice), OFPFW_MPLS_TC);
    //BITMAP_WILDCARD_PART("ofp_flow_wildcards.RESERVED", "Reserved", BASE_DEC, VALS(ts_wildcard_choice), 0xFFFFFC00);

    //ofp_table_config(OFPTC_*)
    FIELD("ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", "Send to controller", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
//    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", "Send to controller", 32, 0xffffffff);
    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_CONTINUE", "Continue to the next table in the pipeline", 32, (OFPTC_TABLE_MISS_CONTINUE));
    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_DROP", "Drop the packet", 32, (OFPTC_TABLE_MISS_DROP));
//    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_MASK", "Table miss mask", 32, (OFPTC_TABLE_MISS_MASK));
    BITMAP_PART("ofp_table_config.RESERVED", "Reserved", 32, 0xFFFFFFFC);

    //ofp_action_type_bmp (1 << OFPAT_*)
    BITMAP_PART("ofp_action_type_bmp.OFPAT_OUTPUT", "Support output to switch port", 32, (1 << OFPAT_OUTPUT));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_VLAN_VID", "Support set the 802.1q VLAN id", 32, (1 << OFPAT_SET_VLAN_VID));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_VLAN_PCP", "Support set the 802.1q priority", 32, (1 << OFPAT_SET_VLAN_PCP));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_DL_SRC", "Support ethernet source address", 32, (1 << OFPAT_SET_DL_SRC));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_DL_DST", "Support ethernet destination address", 32, (1 << OFPAT_SET_DL_DST));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_SRC", "Support IP source address", 32, (1 << OFPAT_SET_NW_SRC));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_DST", "Support IP destination address", 32, (1 << OFPAT_SET_NW_DST));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_TOS", "Support IP ToS (DSCP field, 6 bits)", 32, (1 << OFPAT_SET_NW_TOS));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_ECN", "Support IP ECN (2 bits)", 32, (1 << OFPAT_SET_NW_ECN));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_TP_SRC", "Support TCP/UDP/SCTP source port", 32, (1 << OFPAT_SET_TP_SRC));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_TP_DST", "Support TCP/UDP/SCTP destination port", 32, (1 << OFPAT_SET_TP_DST));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_COPY_TTL_OUT", "Support copy TTL \"outwards\"", 32, (1 << OFPAT_COPY_TTL_OUT));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_COPY_TTL_IN", "Support copy TTL \"inwards\"", 32, (1 << OFPAT_COPY_TTL_IN));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_MPLS_LABEL", "Support MPLS label", 32, (1 << OFPAT_SET_MPLS_LABEL));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_MPLS_TC", "Support MPLS TC ", 32, (1 << OFPAT_SET_MPLS_TC));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_MPLS_TTL", "Support MPLS TTL", 32, (1 << OFPAT_SET_MPLS_TTL));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_DEC_MPLS_TTL", "Support decrement MPLS TTL", 32, (1 << OFPAT_DEC_MPLS_TTL));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_PUSH_VLAN", "Support push a new VLAN tag", 32, (1 << OFPAT_PUSH_VLAN));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_POP_VLAN", "Support pop the outer VLAN tag", 32, (1 << OFPAT_POP_VLAN));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_PUSH_MPLS", "Support push a new MPLS tag", 32, (1 << OFPAT_PUSH_MPLS));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_POP_MPLS", "Support pop the outer MPLS tag", 32, (1 << OFPAT_POP_MPLS));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_QUEUE", "Support set queue id when outputting to a port", 32, (1 << OFPAT_SET_QUEUE));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_GROUP", "Support apply group", 32, (1 << OFPAT_GROUP));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_NW_TTL", "Support IP TTL", 32, (1 << OFPAT_SET_NW_TTL));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_DEC_NW_TTL", "Support decrement IP TTL", 32, (1 << OFPAT_DEC_NW_TTL));

    //ofp_instruction_type_bmp(1 << OFPIT_*)
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_GOTO_TABLE", "Support setup the next table in the lookup pipeline", 32, (1 << OFPIT_GOTO_TABLE));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_WRITE_METADATA", "Support setup the metadata field for use later in pipeline", 32, (1 << OFPIT_WRITE_METADATA));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_WRITE_ACTIONS", "Support write the action(s) onto the datapath action set", 32, (1 << OFPIT_WRITE_ACTIONS));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_APPLY_ACTIONS", "Support applies the action(s) immediately", 32, (1 << OFPIT_APPLY_ACTIONS));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_CLEAR_ACTIONS", "Support clears all actions from the datapath action set", 32, (1 << OFPIT_CLEAR_ACTIONS));

    // ofp_flow_match_fields
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_IN_PORT", "Switch input port", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_IN_PORT);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_DL_VLAN", "VLAN id", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_DL_VLAN);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_DL_VLAN_PCP", "VLAN pcp", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_DL_VLAN_PCP);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_DL_TYPE", "Ethernet frame type", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_DL_TYPE);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_NW_TOS", "IP ToS (DSCP field, 6 bits)", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_NW_TOS);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_NW_PROTO", "IP protocol", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_NW_PROTO);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_TP_SRC", "TCP/UDP/SCTP source por", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_TP_SRC);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_TP_DST", "TCP/UDP/SCTP destination port", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_TP_DST);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_MPLS_LABEL", "MPLS label", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_MPLS_LABEL);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_MPLS_TC", "MPLS TC", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_MPLS_TC);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_TYPE", "Match type", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_TYPE);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_DL_SRC", "Ethernet source address", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_DL_SRC);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_DL_DST", "Ethernet destination address", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_DL_DST);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_NW_SRC", "IP source address", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_NW_SRC);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_NW_DST", "IP destination address", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_NW_DST);
    BITMAP_WILDCARD_PART("ofp_flow_match_fields.OFPFMF_METADATA", "Metadata passed between tables", BASE_DEC, VALS(ts_wildcard_choice), OFPFMF_METADATA);
    //BITMAP_WILDCARD_PART("ofp_flow_match_fields.RESERVED", "Reserved", BASE_DEC, VALS(ts_wildcard_choice), 0xFFFF0000);

    // ofp_flow_mod_flags
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", "Send flow removed message when flow expires or is deleted", 16, OFPFF_SEND_FLOW_REM);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", "Check for overlapping entries first", 16, OFPFF_CHECK_OVERLAP);
    BITMAP_PART("ofp_flow_mod_flags.RESERVED", "Reserved", 16, 0xfffC);

}

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
    FIELD("ofp_error.code.OFPET_BAD_INSTRUCTION", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_action_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_MATCH", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_action_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_FLOW_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_flow_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_GROUP_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_group_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_PORT_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_port_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_TABLE_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_table_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_QUEUE_OP_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_queue_op_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_SWITCH_CONFIG_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_switch_config_failed_code), NO_MASK);
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
    TREE_FIELD("ofp_switch_features.ports", "Ports");
    FIELD("ofp_switch_features.port_num", "Number of ports", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_port
    TREE_FIELD("ofp_port", "Port Description");
    FIELD("ofp_port.num", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.hwaddr", "Hardware Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port.config", "Config", FT_UINT32);
    BITMAP_FIELD("ofp_port.state", "State", FT_UINT32);
    FIELD("ofp_port.stp", "STP", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port.curr_feats", "Current Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.advertised", "Advertised Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.supported", "Supported Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.peer", "Peer Features", FT_UINT32);
    FIELD("ofp_port.curr_speed", "Current Speed (kbps)", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_port.max_speed", "Maximum Speed (kbps)", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_switch_config
    TREE_FIELD("ofp_switch_config", "Switch Configuration");
    BITMAP_FIELD("ofp_switch_config.flags", "Flags", FT_UINT16);
    FIELD("ofp_switch_config.miss_send_len", "Max new flow bytes to controller", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_match
    TREE_FIELD("ofp_match", "Match");
    FIELD("ofp_match.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_match_type), NO_MASK);
    FIELD("ofp_match.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.in_port", "In Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_match.wildcards", "Wildcards");
    BITMAP_FIELD("ofp_flow_wildcards", "Wildcards", FT_UINT32);

    /*FIXME: There's no BASE_BINARY, so FT_ETHER is how you're getting ethernet masks.  Have fun. */
    FIELD("ofp_match.dl_src", "Ethernet Source Addr", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_src_mask", "Ethernet Source Addr Mask", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_dst", "Ethernet Dest Addr", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_dst_mask", "Ethernet Dest Addr Mask", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_vlan", "VLAN ID",FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_vlan_pcp", "VLAN PCP", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.dl_type", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_tos", "IP DSCP", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_proto", "IP Protocol", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_src", "IP Source Addr", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_src_mask", "IP Source Addr Mask", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_dst", "IP Dest Addr", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_match.nw_dst_mask", "Dest Addr mask", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    /*FIXME: should really add individual entries for TCP/UDP/SCTP/whatever ports and switch on protocol */
    FIELD("ofp_match.tp_src", "TCP/UDP/SCTP Source Port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.tp_dst", "TCP/UDP/SCTP Dest Port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.mpls_label", "MPLS label", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.mpls_tc", "MPLS TC", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.metadata", "Metadata passed between tables", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_match.metadata_mask", "Metadata_mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_instruction
    TREE_FIELD("ofp_instruction", "Instruction");
    FIELD("ofp_instruction.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_instruction_type), NO_MASK);
    FIELD("ofp_instruction.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_goto_table.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_write_metadata.metadata", "Metadata", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_write_metadata.metadata_mask", "Metadata Mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_action
    TREE_FIELD("ofp_action", "Action");
    FIELD("ofp_action.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_action_type), NO_MASK);
    FIELD("ofp_action.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.port", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.max_len", "Max Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_group.group_id", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_queue.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_vlan_vid.vlan_vid", "VLAN ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_vlan_pcp.vlan_pcp", "VLAN priority", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_mpls_label.mpls_label", "MPLS label", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_mpls_tc.mpls_tc", "MPLS TC", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_mpls_ttl.mpls_ttl", "MPLS TTL", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_dl_src.dl_addr", "Src Ethernet address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_dl_dst.dl_addr", "Dst Ethernet address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_nw_src.nw_addr", "Src IP address", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_nw_dst.nw_addr", "Dst IP address", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_nw_tos.nw_tos", "IP ToS (DSCP field, 6 bits)", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_nw_ecn.nw_ecn", "IP ECN (2 bits)", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_nw_ttl.nw_ttl", "IP TTL", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_src_tp_port.tp_port", "Src TCP/UDP/SCTP port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_dst_tp_port.tp_port", "Dst TCP/UDP/SCTP port", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_push.ethertype", "ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_action_pop_mpls.ethertype", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    //ofp_action_set_field is defined using ofp_oxm
    FIELD("ofp_action_experimenter_header.experimenter", "Experimenter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

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

    //ofp_flow_stats_request
    TREE_FIELD("ofp_flow_stats_request", "Flow Stats Request");
    FIELD("ofp_flow_stats_request.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.out_port", "Output Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.out_group", "Output Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.cookie_mask", "Cookie mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_flow_stats
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

    //ofp_aggregate_stats_request
    TREE_FIELD("ofp_aggregate_stats_request", "Aggregate Flow Statistics request");
    FIELD("ofp_aggregate_stats_request.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_request.out_port", "Output Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_request.out_group", "Output Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_request.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_request.cookie_mask", "Cookie mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_aggregate_stats_reply
    TREE_FIELD("ofp_aggregate_stats_reply", "Aggregate Flow Statistics");
    FIELD("ofp_aggregate_stats_reply.packet_count", "Packet count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_reply.byte_count", "Byte count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_aggregate_stats_reply.flow_count", "flow_count", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_table_stats
    TREE_FIELD("ofp_table_stats", "Table Stats Reply");
    FIELD("ofp_table_stats.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_table_stats.wildcards", "Bitmap of Wildcards", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.match", "Bitmap of match", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.instructions", "Bitmap of Instructions", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.write_actions", "Bitmap of Write Action", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.apply_actions", "Bitmap of Apply Action", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.config", "Bitmap of Config", FT_UINT32);
    FIELD("ofp_table_stats.max_entries", "Max Supported Entries", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.active_count", "Active Entry Count", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.lookup_count", "Lookup Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.matched_count", "Packet Match Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_port_stats_request
    TREE_FIELD("ofp_port_stats_request", "Port Stats Request");
    FIELD("ofp_port_stats_request.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_port_stats
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

    //ofp_queue_stats_request
    TREE_FIELD("ofp_queue_stats_request", "Queue Stats Request");
    FIELD("ofp_queue_stats_request.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats_request.queue_id", "Queue ID",FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_queue_stats
    TREE_FIELD("ofp_queue_stats", "Queue Stats Reply");
    FIELD("ofp_queue_stats.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.tx_bytes", "Transmitted bytes", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.tx_packets", "transmitted packets", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_queue_stats.tx_errors", "TX errors", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_group_stats_request
    TREE_FIELD("ofp_group_stats_request", "Group Stats Request");
    FIELD("ofp_group_stats_request.group_id", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_group_stats
    TREE_FIELD("ofp_group_stats", "Group Stats Reply");
    FIELD("ofp_group_stats.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_stats.group_id", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_group_stats.ref_count", "Flows or groups forward to this group", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_stats.packet_count", "Packets proc by group", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_stats.byte_count", "Bytes proc by group", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_bucket_counter
    TREE_FIELD("ofp_bucket_counter", "One counter set per bucket");
    FIELD("ofp_bucket_counter.packet_count", "Packets proc by bucket", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_bucket_counter.byte_count", "Bytes proc by bucket", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_experimenter_multipart_header
    TREE_FIELD("ofp_experimenter_multipart_header", "Experimenter");
    FIELD("ofp_experimenter_multipart_header.experimenter", "Experimenter ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_experimenter_multipart_header.data", "Experimenter data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_port_status
    TREE_FIELD("ofp_port_status", "Port Status");
    FIELD("ofp_port_status.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_port_reason), NO_MASK);
    TREE_FIELD("ofp_port_status.desc", "Ports");

    //ofp_packet_in
    TREE_FIELD("ofp_packet_in", "Packet in");
    FIELD("ofp_packet_in.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.in_port", "Input Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.in_phy_port", "Input Physical Port", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.total_len", "Total length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_packet_in_reason), NO_MASK);
    FIELD("ofp_packet_in.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_packet_out
    TREE_FIELD("ofp_packet_out", "Packet out");
    FIELD("ofp_packet_out.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.in_port", "Input port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.actions_len", "Actions length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_flow_mod
    TREE_FIELD("ofp_flow_mod", "Flow Mod");
    FIELD("ofp_flow_mod.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.cookie_mask", "Cookie MASK", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.tableid", "Table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.command", "Command", FT_UINT8, BASE_HEX, VALUES(ofp_flow_mod_command), NO_MASK);
    FIELD("ofp_flow_mod.idle_timeout", "Idle Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.hard_timeout", "Hard Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_port", "Output Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_group", "Output Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_flow_mod.flags", "Flags", FT_UINT16);

    //ofp_flow_removed
    TREE_FIELD("ofp_flow_removed", "Flow Removed");
    FIELD("ofp_flow_removed.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.priority", "Priority level", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.reason", "Reason", FT_UINT8, BASE_DEC, VALUES(ofp_flow_removed_reason), NO_MASK);
    FIELD("ofp_flow_removed.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.duration_sec", "Flow Duration (sec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.duration_nsec", "Flow Duration (nsec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.idle_timeout", "Idle timeout (sec)", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.packet_count", "Packet Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_removed.byte_count", "Byte Count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_group_desc
    TREE_FIELD("ofp_group_desc", "Group Description");
    FIELD("ofp_group_desc.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_desc.type", "Group_type", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_desc.group_id", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_group_mod
    TREE_FIELD("ofp_group_mod", "Group Mod");
    FIELD("ofp_group_mod.command", "Command", FT_UINT16, BASE_HEX, VALUES(ofp_group_mod_command), NO_MASK);
    FIELD("ofp_group_mod.type", "Type", FT_UINT8, BASE_HEX, VALUES(ofp_group_type), NO_MASK);
    FIELD("ofp_group_mod.groupid", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_group_bucket
    TREE_FIELD("ofp_group_bucket", "Bucket");
    FIELD("ofp_group_bucket.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_bucket.weight", "Weight", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_bucket.watch_port", "Watch Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_group_bucket.watch_group", "Watch Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_table_mod
    TREE_FIELD("ofp_table_mod", "Table Mod");
    FIELD("ofp_table_mod.id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_table_mod.config", "Config", FT_UINT32);

    //ofp_port_mod
    TREE_FIELD("ofp_port_mod", "Port Mod");
    FIELD("ofp_port_mod.port_no", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port_mod.hw_addr", "MAC Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port_mod.config", "Port Config Flags", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.mask", "Port Mask Flags", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.advertised", "Port Advertise Flags", FT_UINT32);

    //ofp_queue_get_config_request
    TREE_FIELD("ofp_queue_get_config_request", "Queue Configuration Request");
    FIELD("ofp_queue_get_config_request.port", "Port(< OFPP_MAX) ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_queue_get_config_reply
    TREE_FIELD("ofp_queue_get_config_reply", "Queue Configuration Reply");
    FIELD("ofp_queue_get_config_reply.port", "Port(< OFPP_MAX) ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_packet_queue
    TREE_FIELD("ofp_packet_queue", "Queue desc");
    FIELD("ofp_packet_queue.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_queue.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_queue_prop_header
    TREE_FIELD("ofp_queue_prop_header", "Queue property");
    FIELD("ofp_packet_queue.property", "property", FT_UINT16, BASE_DEC, VALUES(ofp_queue_property), NO_MASK);
    FIELD("ofp_packet_queue.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_queue_prop_min_rate
    FIELD("ofp_queue_prop_min_rate.rate", "Min rate In 1/10 of a percent", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
}

// Generated code
void DissectorContext::setupCodes(void)
{
    // ofp_type
    TYPE_ARRAY(ofp_type);
    TYPE_ARRAY_ADD(ofp_type, OFPT_HELLO, "Hello (SM) - OFPT_HELLO");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ERROR, "Error (SM) - OFPT_ERROR");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ECHO_REQUEST, "Echo request (SM) - OFPT_ECHO_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ECHO_REPLY, "Echo reply (SM) - OFPT_ECHO_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_EXPERIMENTER, "Experimenter (SM) - OFPT_EXPERIMENTER");

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
    TYPE_ARRAY_ADD(ofp_type, OFPT_GROUP_MOD, "Group mod (CSM) - OFPT_GROUP_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PORT_MOD, "Port mod (CSM) - OFPT_PORT_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_TABLE_MOD, "Table mod (CSM) - OFPT_TABLE_MOD");

    TYPE_ARRAY_ADD(ofp_type, OFPT_STATS_REQUEST, "Stats request (CSM) - OFPT_STATS_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_STATS_REPLY, "Stats reply (CSM) - OFPT_STATS_REPLY");

    TYPE_ARRAY_ADD(ofp_type, OFPT_BARRIER_REQUEST, "Barrier request (CSM) - OFPT_BARRIER_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_BARRIER_REPLY, "Barrier reply (CSM) - OFPT_BARRIER_REPLY");

    TYPE_ARRAY_ADD(ofp_type, OFPT_QUEUE_GET_CONFIG_REQUEST, "Queue get config request (CSM) - OFPT_QUEUE_GET_CONFIG_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_QUEUE_GET_CONFIG_REPLY, "Queue get config reply (CSM) - OFPT_QUEUE_GET_CONFIG_REPLY");

    // ofp_flow_mod_command
    TYPE_ARRAY(ofp_flow_mod_command);
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_ADD, "New flow - OFPFC_ADD");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY, "Modify all matching flows - OFPFC_MODIFY");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY_STRICT, "Modify entry strictly matching wildcards and priority - OFPFC_MODIFY_STRICT");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE, "Delete all matching flows - OFPFC_DELETE");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE_STRICT, "Delete entry strictly matching wildcards and priority - OFPFC_DELETE_STRICT");

    // ofp_match_type
    TYPE_ARRAY(ofp_match_type);
    TYPE_ARRAY_ADD(ofp_match_type, OFPMT_STANDARD, "Deprecated - OFPMT_STANDARD");

    // ofp_instruction_type
    TYPE_ARRAY(ofp_instruction_type);
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_GOTO_TABLE, "Goto Table - OFPIT_GOTO_TABLE");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_WRITE_METADATA, "Write Metadatae - OFPIT_WRITE_METADATA");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_WRITE_ACTIONS, "Write Actions - OFPIT_WRITE_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_APPLY_ACTIONS, "Apply Actions - OFPIT_APPLY_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_CLEAR_ACTIONS, "Clear Actions - OFPIT_CLEAR_ACTIONS");

    // ofp_action_type
    TYPE_ARRAY(ofp_action_type);
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_OUTPUT, "Output to switch port - OFPAT_OUTPUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_VLAN_VID, "Set the 802.1q VLAN id - OFPAT_SET_VLAN_VID");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_VLAN_PCP, "Set the 802.1q priority - OFPAT_SET_VLAN_PCP");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_DL_SRC, "Set Ethernet source address - OFPAT_SET_DL_SRC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_DL_DST, "Set Ethernet destination address - OFPAT_SET_DL_DST");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_SRC, "Set IP source address - OFPAT_SET_NW_SRC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_DST, "Set IP destination address - OFPAT_SET_NW_DST");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_TOS, "Set IP ToS (DSCP field, 6 bits) - OFPAT_SET_NW_TOS");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_ECN, "Set IP ECN (2 bits) - OFPAT_SET_NW_ECN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_TP_SRC, "Set TCP/UDP/SCTP source port - OFPAT_SET_TP_SRC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_TP_DST, "Set TCP/UDP/SCTP destination port - OFPAT_SET_TP_DST");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_COPY_TTL_OUT, "Copy TTL \"outwards\" -- from next-to-outermost to outermost - OFPAT_COPY_TTL_OUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_COPY_TTL_IN, "Copy TTL \"inwards\" -- from outermost to next-to-outermost - OFPAT_COPY_TTL_IN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_MPLS_LABEL, "Set MPLS label - OFPAT_SET_MPLS_LABEL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_MPLS_TC, "Set MPLS TC - OFPAT_SET_MPLS_TC");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_MPLS_TTL, "MPLS TTL - OFPAT_SET_MPLS_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_DEC_MPLS_TTL, "Decrement MPLS TTL - OFPAT_DEC_MPLS_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_PUSH_VLAN, "Push a new VLAN tag - OFPAT_PUSH_VLAN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_POP_VLAN, "Pop the outer VLAN tag - OFPAT_POP_VLAN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_PUSH_MPLS, "Push a new MPLS tag - OFPAT_PUSH_MPLS");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_POP_MPLS, "Pop the outer MPLS tag - OFPAT_POP_MPLS");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_QUEUE, "Set queue id when outputting to a port - OFPAT_SET_QUEUE");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_GROUP, "Apply group - OFPAT_GROUP");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_TTL, "IP TTL - OFPAT_SET_NW_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_DEC_NW_TTL, "Decrement IP TTL - OFPAT_DEC_NW_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_EXPERIMENTER, "Experimenter action - OFPAT_EXPERIMENTER");

    // ofp_stats_types
    TYPE_ARRAY(ofp_stats_types);
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_DESC, "Description of an OpenFlow switch - OFPST_DESC");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_FLOW, "Individual flow statistics - OFPST_FLOW");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_AGGREGATE, "Aggregate flow statistics - OFPST_AGGREGATE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_TABLE, "Flow table statistics - OFPST_TABLE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_PORT, "Port statistics - OFPST_PORT");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_GROUP, "Group statistics - OFPST_GROUP");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_GROUP_DESC, "Group Description - OFPST_GROUP_DESC");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_QUEUE, "Queue statistics for a port - OFPST_QUEUE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_EXPERIMENTER, "Experimenter - OFPST_EXPERIMENTER");

    // ofp_error_type
    TYPE_ARRAY(ofp_error_type);
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_HELLO_FAILED, "Hello protocol failed - OFPET_HELLO_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_REQUEST, "Request was not understood - OFPET_BAD_REQUEST");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_ACTION, "Error in action description - OFPET_BAD_ACTION");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_INSTRUCTION, "Error in instruction list - OFPET_BAD_INSTRUCTION");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_MATCH, "Error in match - OFPET_BAD_MATCH");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_FLOW_MOD_FAILED, "Problem modifying flow entry - OFPET_FLOW_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_GROUP_MOD_FAILED, "Problem modifying group entry - OFPET_GROUP_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_PORT_MOD_FAILED, "Port mod request failed - OFPET_PORT_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_TABLE_MOD_FAILED, "Table mod request failed - OFPET_TABLE_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_QUEUE_OP_FAILED, "Queue operation failed - OFPET_QUEUE_OP_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_SWITCH_CONFIG_FAILED, "Switch config request failed - OFPET_SWITCH_CONFIG_FAILED");

    // ofp_hello_failed_code
    TYPE_ARRAY(ofp_hello_failed_code);
    TYPE_ARRAY_ADD(ofp_hello_failed_code, OFPHFC_INCOMPATIBLE, "No compatible version - OFPHFC_INCOMPATIBLE");
    TYPE_ARRAY_ADD(ofp_hello_failed_code, OFPHFC_EPERM, "Permissions error - OFPHFC_EPERM");

    // ofp_bad_request_code
    TYPE_ARRAY(ofp_bad_request_code);
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_VERSION, "ofp_header.version not supported - OFPBRC_BAD_VERSION");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_TYPE, "ofp_header.type not supported - OFPBRC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_STAT, "ofp_stats_request.type not supported - OFPBRC_BAD_STAT");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_EXPERIMENTER, "Experimenter id not supported - OFPBRC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_SUBTYPE, "Experimenter subtype not supported - OFPBRC_BAD_SUBTYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_EPERM, "Permissions error - OFPBRC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_LEN, "Wrong request length for type - OFPBRC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_EMPTY, "Specified buffer has already been used - OFPBRC_BUFFER_EMPTY");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_UNKNOWN, "Specified buffer does not exist - OFPBRC_BUFFER_UNKNOWN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_TABLE_ID, "Specified table-id invalid or does not exist - OFPBRC_BAD_TABLE_ID");

    // ofp_bad_action_code
    TYPE_ARRAY(ofp_bad_action_code);
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TYPE, "Unknown action type - OFPBAC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_LEN, "Length problem in actions - OFPBAC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_EXPERIMENTER, "Unknown experimenter id specified - OFPBAC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_EXPERIMENTER_TYPE, "Unknown action type for experimenter id - OFPBAC_BAD_EXPERIMENTER_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_PORT, "Problem validating output port - OFPBAC_BAD_OUT_PORT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_ARGUMENT, "Bad action argument - OFPBAC_BAD_ARGUMENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_EPERM, "Permissions error - OFPBAC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_TOO_MANY, "Can't handle this many actions - OFPBAC_TOO_MANY");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_QUEUE, "Problem validating output queue - OFPBAC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_GROUP, "Invalid group id in forward action - OFPBAC_BAD_OUT_GROUP");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_MATCH_INCONSISTENT, "Action can't apply for this match - OFPBAC_MATCH_INCONSISTENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_UNSUPPORTED_ORDER, "Action order is unsupported in Apply-Actions instruction - OFPBAC_UNSUPPORTED_ORDER");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TAG, "Actions uses an unsupported tag/encap - OFPBAC_BAD_TAG");

    // ofp_bad_match_code
    TYPE_ARRAY(ofp_bad_match_code);
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_TYPE, "Unsupported match type specified by the match - OFPBMC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_LEN, "Length problem in match - OFPBMC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_TAG, "Match uses an unsupported tag/encap - OFPBMC_BAD_TAG");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_DL_ADDR_MASK, "Unsupported datalink addr mask - OFPBMC_BAD_DL_ADDR_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_NW_ADDR_MASK, "Unsupported network addr mask - OFPBMC_BAD_NW_ADDR_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_WILDCARDS, "Unsupported wildcard specified in the match - OFPFMFC_BAD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_FIELD, "Unsupported field in the match - OFPBMC_BAD_FIELD");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_VALUE, "Unsupported value in a match field - OFPBMC_BAD_VALUE");

    // ofp_bad_instruction_code
    TYPE_ARRAY(ofp_bad_instruction_code);
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNKNOWN_INST, "Unknown instruction - OFPBIC_UNKNOWN_INST");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_INST, "Switch or table does not support the instruction - OFPBIC_UNSUP_INST");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_TABLE_ID, "Invalid Table-ID specified - OFPBIC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_METADATA, "Metadata value unsupported by datapath - OFPBIC_UNSUP_METADATA");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_METADATA_MASK, "Metadata mask value unsupported by datapath - OFPBIC_UNSUP_METADATA_MASK");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_EXP_INST, "Specific experimenter instruction unsupported - OFPBIC_UNSUP_EXP_INST");

    // ofp_flow_mod_failed_code
    TYPE_ARRAY(ofp_flow_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_UNKNOWN, "Unspecified error - OFPFMFC_UNKNOWN");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_TABLE_FULL, "Flow not added because table was full - OFPFMFC_TABLE_FULL");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_TABLE_ID, "Table does not exist - OFPFMFC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_OVERLAP, "Attempted to add overlapping flow with CHECK_OVERLAP flag set - OFPFMFC_OVERLAP");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_EPERM, "Permissions error - OFPFMFC_EPERM");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_TIMEOUT, "Flow not added because of unsupported idle/hard timeout - OFPFMFC_BAD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_COMMAND, "Unsupported or unknown command - OFPFMFC_BAD_COMMAND");

    // ofp_group_mod_failed_code
    TYPE_ARRAY(ofp_group_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_GROUP_EXISTS, "Group not added because a group ADD attempted to replace an already present group - OFPGMFC_GROUP_EXISTS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_INVALID_GROUP, "Group not added because specified group is invalid - OFPGMFC_INVALID_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_WEIGHT_UNSUPPORTED, "Switch does not support unequal load sharing between groups - OFPGMFC_WEIGHT_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_OUT_OF_GROUPS, "Group table is full - OFPGMFC_OUT_OF_GROUPS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_OUT_OF_BUCKETS, "The maximum number of action buckets for a group has been exceeded - OFPGMFC_OUT_OF_BUCKETS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_CHAINING_UNSUPPORTED, "Switch does not support groups that forward to groups - OFPGMFC_CHAINING_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_WATCH_UNSUPPORTED, "This group cannot watch the port or group specified - OFPGMFC_WATCH_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_LOOP, "Group entry would cause a loop - OFPGMFC_LOOP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_UNKNOWN_GROUP, "Group not modified because specified group does not exist - OFPGMFC_UNKNOWN_GROUP");

    // ofp_port_mod_failed_code
    TYPE_ARRAY(ofp_port_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_PORT, "Specified port number does not exist - OFPPMFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_HW_ADDR, "Specified hardware address does not match the port number - OFPPMFC_BAD_HW_ADDR");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_CONFIG, "Specified config is invalid - OFPPMFC_BAD_CONFIG");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_ADVERTISE, "Specified advertise is invalid - OFPPMFC_BAD_ADVERTISE");

    // ofp_table_mod_failed_code
    TYPE_ARRAY(ofp_table_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_BAD_TABLE, "Specified table does not exist - OFPTMFC_BAD_TABLE");
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_BAD_CONFIG, "Specified config is invalid - OFPTMFC_BAD_CONFIG");

    // ofp_table_mod_failed_code
    TYPE_ARRAY(ofp_queue_op_failed_code);
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_PORT, "Invalid port - OFPQOFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_QUEUE, "Queue does not exist - OFPQOFC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_EPERM, "Permissions error - OFPQOFC_EPERM");

    // ofp_switch_config_failed_code
    TYPE_ARRAY(ofp_switch_config_failed_code);
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_BAD_FLAGS, "Specified flags are invalid - OFPSCFC_BAD_FLAGS");
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_BAD_LEN, "Specified length is inavlid - OFPSCFC_BAD_LEN");

    // ofp_flow_removed_reason
    TYPE_ARRAY(ofp_flow_removed_reason);
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_IDLE_TIMEOUT, "Flow idle time exceeded idle_timeout - OFPRR_IDLE_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_HARD_TIMEOUT, "Time exceeded hard_timeout - OFPRR_HARD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_DELETE, "Evicted by a DELETE flow mod - OFPRR_DELETE");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_GROUP_DELETE, "Group was removed - OFPRR_GROUP_DELETE");

    // ofp_port_reason
    TYPE_ARRAY(ofp_port_reason);
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_ADD, "The port was added - OFPPR_ADD");
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_DELETE, "The port was removed - OFPPR_DELETE");
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_MODIFY, "Some attribute of the port has changed - OFPPR_MODIFY");

    // ofp_group_mod_command
    TYPE_ARRAY(ofp_group_mod_command);
    TYPE_ARRAY_ADD(ofp_group_mod_command, OFPGC_ADD, "New group - OFPGC_ADD");
    TYPE_ARRAY_ADD(ofp_group_mod_command, OFPGC_MODIFY, "Modify all matching groups - OFPGC_MODIFY");
    TYPE_ARRAY_ADD(ofp_group_mod_command, OFPGC_DELETE, "Delete all matching groups - OFPGC_DELETE");

    // ofp_group_type
    TYPE_ARRAY(ofp_group_type);
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_ALL, "All (multicast/broadcast) group - OFPGT_ALL");
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_SELECT, "Select group - OFPGT_SELECT");
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_INDIRECT, "Indirect group - OFPGT_INDIRECT");
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_FF, "Fast failover group - OFPGT_FF");

    // ofp_packet_in_reason
    TYPE_ARRAY(ofp_packet_in_reason);
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_NO_MATCH, "No matching flow - OFPR_NO_MATCH");
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_ACTION, "Action explicitly output to controller - OFPR_ACTION");

    // ofp_queue_property
    TYPE_ARRAY(ofp_queue_property);
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_NONE, "No property defined for queue (default) - OFPQT_NONE");
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_MIN_RATE, "Minimum datarate guaranteed - OFPQT_MIN_RATE");
}

void init(int proto_openflow)
{
    DissectorContext::getInstance(proto_openflow);
}

}
