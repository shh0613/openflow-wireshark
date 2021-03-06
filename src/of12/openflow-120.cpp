/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2012 Barnstormer Softworks Ltd.
 * Copyright (c) 2012 CPqD
 * Copyright (c) 2013 LittleField
 *   -- complete it
 */

#define OPENFLOW_INTERNAL

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <of12/openflow-120.hpp>
#include <openflow-common.hpp>
#include "openflow/of12.h"
#include "field_type.hpp"

#define PROTO_TAG_OPENFLOW_VER "OFP12"

namespace openflow_120 {

DissectorContext * DissectorContext::mSingle = NULL;
DissectorContext * Context;

DissectorContext * DissectorContext::getInstance(int proto_openflow)
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

void DissectorContext::dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, DissectorContext::getMessageLen, DissectorContext::prepDissect);
}

guint DissectorContext::getMessageLen(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    // 0-7    version
    // 8-15   type
    // 16-31  length
    return (guint) tvb_get_ntohs(tvb, offset + 2);
}

void init(int proto_openflow) {
    DissectorContext::getInstance(proto_openflow);
}

DissectorContext::DissectorContext(int proto_openflow)
                    : mProtoOpenflow(proto_openflow), mFM(proto_openflow, "of12")
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
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(type, (value_string*) this->ofp_type->data, "Unknown Type (0x%02x)"));

    if (this->_tree) {
        this->_curOFPSubtree = this->mFM.addSubtree(tree, "data", this->_tvb, 0, -1);
        proto_tree *hdr_tree = this->mFM.addSubtree(this->_curOFPSubtree, "header", this->_tvb, this->_offset, 8);

        ADD_CHILD(hdr_tree, "version", 1);
        ADD_CHILD(hdr_tree, "type", 1);
        ADD_CHILD(hdr_tree, "length", 2);
        ADD_CHILD(hdr_tree, "xid", 4);

        if (this->_oflen > this->_rawLen)
            this->_oflen = this->_rawLen;

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
                this->dissect_ofp_features_request();
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
                IGNORE; // Not yet implemented
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
                this->dissect_stats_request();
                break;

            case OFPT_STATS_REPLY:
                this->dissect_stats_reply();
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

            case OFPT_ROLE_REQUEST:
                this->dissect_ofp_role_request();
                break;
            case OFPT_ROLE_REPLY:
                this->dissect_ofp_role_reply();
                break;

            default:
                IGNORE; // We don't know what to do
            }
        }
    }
}

// Dissection methods
void DissectorContext::dissect_ofp_echo()
{
    ADD_CHILD(this->_curOFPSubtree, "echo", this->_oflen - this->_offset);
    this->_offset = this->_oflen;
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
        ERROR(OFPET_BAD_INSTRUCTION)
        ERROR(OFPET_BAD_MATCH)
        ERROR(OFPET_FLOW_MOD_FAILED)
        ERROR(OFPET_GROUP_MOD_FAILED)
        ERROR(OFPET_PORT_MOD_FAILED)
        ERROR(OFPET_TABLE_MOD_FAILED)
        ERROR(OFPET_QUEUE_OP_FAILED)
        ERROR(OFPET_SWITCH_CONFIG_FAILED)
        ERROR(OFPET_ROLE_REQUEST_FAILED)
        ERROR(OFPET_EXPERIMENTER)
        default:
            break;
    }

    if (this->_oflen - this->_offset > 0) {
        ADD_OFDISSECTOR(tree, "ofp_error.data", this->_oflen - this->_offset);
    } else {
        ADD_CHILD(tree, "ofp_error.data", this->_oflen - this->_offset);
    }
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
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.RESERVED", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_FLOW_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_TABLE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_PORT_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_GROUP_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_IP_REASM", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_QUEUE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_PORT_BLOCKED", 4, capabilities);
    CONSUME_BYTES(4);

    ADD_CHILD(tree, "ofp_switch_features.reserved", 4);

    // Ports
    // TODO: shouldn't we use a while like in other parts?
    guint32 portlen = this->_oflen - 32;
    if (portlen % 64 != 0) {
        // Packet alignment is off, we should probably complain
    }
    else {
        guint32 ports =  portlen / 64;
        for (int port = 0; port < ports; ++port) {
            ADD_SUBTREE(port_tree, tree, "ofp_switch_features.ports", portlen);
            ADD_UINT(port_tree, "ofp_switch_features.port_num", 4, ports);
            this->dissect_ofp_port(port_tree);
        }
    }
}

void DissectorContext::dissect_ofp_switch_config()
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
    ADD_SUBTREE(flow_stat_tree, parent, "ofp_flow_stats_request", this->_oflen - this->_offset);
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
    ADD_SUBTREE(tree, parent, "ofp_aggregate_stats_request", sizeof(struct ofp_aggregate_stats_request));
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
    ADD_SUBTREE(tree, parent, "ofp_aggregate_stats_reply", sizeof(struct ofp_aggregate_stats_reply));
    ADD_CHILD(tree, "ofp_aggregate_stats_reply.packet_count", 8);
    ADD_CHILD(tree, "ofp_aggregate_stats_reply.byte_count", 8);
    ADD_CHILD(tree, "ofp_aggregate_stats_reply.flow_count", 4);
    ADD_CHILD(tree, "padding", 4);
}


void DissectorContext::dissect_ofp_port_stats_request(proto_tree* parent)
{
    ADD_SUBTREE(port_stat_tree, parent, "ofp_port_stats_request", sizeof(struct ofp_port_stats_request));
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
    ADD_SUBTREE(queue_stat_tree, parent, "ofp_queue_stats_request", sizeof(struct ofp_queue_stats_request));
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

    ADD_SUBTREE(tree, parent, "ofp_group_stats", sizeof(struct ofp_group_stats));
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

    READ_UINT64(match);
    ADD_SUBTREE(mt, table_stat_tree, "ofp_table_stats.match", 8);
    this->dissect_ofp_flow_match_field(mt, match);
    CONSUME_BYTES(8);

    READ_UINT64(wildcards);
    ADD_SUBTREE(wct, table_stat_tree, "ofp_table_stats.wildcards", 8);
    this->dissect_ofp_flow_match_field(wct, wildcards);
    CONSUME_BYTES(8);

    READ_UINT32(wract);
    ADD_SUBTREE(wrt, table_stat_tree, "ofp_table_stats.write_actions", 4);
    this->dissect_ofp_action_type_bmp(wrt, wract);
    CONSUME_BYTES(4);

    READ_UINT32(appact);
    ADD_SUBTREE(apt, table_stat_tree, "ofp_table_stats.apply_actions", 4);
    this->dissect_ofp_action_type_bmp(apt, appact);
    CONSUME_BYTES(4);

    READ_UINT64(wrset);
    ADD_SUBTREE(wrs, table_stat_tree, "ofp_table_stats.write_setfields", 8);
    this->dissect_ofp_flow_match_field(wrs, wrset);
    CONSUME_BYTES(8);

    READ_UINT64(appset);
    ADD_SUBTREE(apps, table_stat_tree, "ofp_table_stats.apply_setfields", 8);
    this->dissect_ofp_flow_match_field(apps, appset);
    CONSUME_BYTES(8);

    ADD_CHILD(table_stat_tree, "ofp_table_stats.metadata_match", 8);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.metadata_write", 8);

    READ_UINT32(instbmp);
    ADD_SUBTREE(inst, table_stat_tree, "ofp_table_stats.instructions", 4);
    this->dissect_ofp_instruction_type_bmp(inst, instbmp);
    CONSUME_BYTES(4);

    READ_UINT32(config);
    ADD_SUBTREE(configt, table_stat_tree, "ofp_table_stats.config", 4);
    if (config == 0) {
        ADD_UINT(configt, "ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", 4, config);
    } else {
        ADD_BOOLEAN(configt, "ofp_table_config.OFPTC_TABLE_MISS_CONTINUE", 4, config);
        ADD_BOOLEAN(configt, "ofp_table_config.OFPTC_TABLE_MISS_DROP", 4, config);
        ADD_BOOLEAN(configt, "ofp_table_config.RESERVED", 4, config);
    }
    CONSUME_BYTES(4);

    ADD_CHILD(table_stat_tree, "ofp_table_stats.max_entries", 4);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.active_count", 4);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.lookup_count", 8);
    ADD_CHILD(table_stat_tree, "ofp_table_stats.matched_count", 8);
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

void DissectorContext::dissect_ofp_group_features(proto_tree* parent)
{
    guint32 i;

    ADD_SUBTREE(tree, parent, "ofp_group_features", sizeof(struct ofp_group_features_stats));

    READ_UINT32(types);
    ADD_SUBTREE(types_tree, tree, "ofp_group_features.types", 4);
    ADD_BOOLEAN(types_tree, "ofp_group_type.RESERVED", 4, types);
    ADD_BOOLEAN(types_tree, "ofp_group_type.OFPGT_ALL", 4, types);
    ADD_BOOLEAN(types_tree, "ofp_group_type.OFPGT_SELECT", 4, types);
    ADD_BOOLEAN(types_tree, "ofp_group_type.OFPGT_INDIRECT", 4, types);
    ADD_BOOLEAN(types_tree, "ofp_group_type.OFPGT_FF", 4, types);
    CONSUME_BYTES(4);

    READ_UINT32(capabilities);
    ADD_SUBTREE(capabilities_tree, tree, "ofp_group_features.capabilities", 4);
    ADD_BOOLEAN(capabilities_tree, "ofp_group_capabilities.RESERVED", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_group_capabilities.OFPGFC_SELECT_WEIGHT", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_group_capabilities.OFPGFC_SELECT_LIVENESS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_group_capabilities.OFPGFC_CHAINING", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_group_capabilities.OFPGFC_CHAINING_CHECKS", 4, capabilities);
    CONSUME_BYTES(4);

    for (i = 0; i < 4; i++) {
        ADD_CHILD(tree, "ofp_group_features.max_groups", 4);
    }

    for (i = 0; i < 4; i++) {
        READ_UINT32(actions);
        ADD_SUBTREE(actions_tree, tree, "ofp_group_features.actions", 4);
        this->dissect_ofp_action_type_bmp(actions_tree, actions);
        CONSUME_BYTES(4);
    }
}

void DissectorContext::dissect_ofp_stats_experimenter(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_experimenter_multipart_header", this->_oflen - this->_offset);
    ADD_CHILD(tree, "ofp_experimenter_multipart_header.experimenter", 4);
    ADD_CHILD(tree, "ofp_experimenter_multipart_header.exp_type", 4);
    ADD_CHILD(tree, "ofp_experimenter_multipart_header.data", this->_oflen - this->_offset);
}

void DissectorContext::dissect_stats_request()
{
    ADD_TREE(tree, "ofp_stats_request");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_stats_request.type", 2);
    ADD_CHILD(tree, "ofp_stats_request.flags", 2);
    ADD_CHILD(tree, "padding", 4);
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
    case OFPST_GROUP_FEATURES:
    case OFPST_DESC:
    case OFPST_TABLE:
        this->_offset += this->_oflen - this->_offset;
        break;
    default:
        ADD_CHILD(tree, "ofp_stats_request.body", this->_oflen - this->_offset);
        break;
    }
}

void DissectorContext::dissect_stats_reply()
{
    ADD_TREE(tree, "ofp_stats_reply");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_stats_reply.type", 2);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_stats_reply.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_stats_reply_flags.RESERVED", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_stats_reply_flags.OFPSF_REPLY_MORE", 2, flags);
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
    case OFPST_GROUP_FEATURES:
        this->dissect_ofp_group_features(tree);
        break;
    case OFPST_EXPERIMENTER:
        this->dissect_ofp_stats_experimenter(tree);
        break;
    default:
        ADD_CHILD(tree, "ofp_stats_reply.body", this->_oflen - this->_offset);
        break;
    }
}

void DissectorContext::dissect_ofp_flow_match_field(proto_tree *mt, guint64 match)
{
    guint32 part1, part2;

    /* part1 */
    part1 = (guint32)(match & UINT_MAX);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IN_PORT", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IN_PHY_PORT", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_METADATA", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ETH_DST", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ETH_SRC", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ETH_TYPE", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_VLAN_VID", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_VLAN_PCP", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IP_DSCP", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IP_ECN", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IP_PROTO", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV4_SRC", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV4_DST", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_TCP_SRC", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_TCP_DST", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_UDP_SRC", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_UDP_DST", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_SCTP_SRC", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_SCTP_DST", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ICMPV4_TYPE", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ICMPV4_CODE", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ARP_OP", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ARP_SPA", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ARP_TPA", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ARP_SHA", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ARP_THA", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV6_SRC", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV6_DST", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV6_FLABEL", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ICMPV6_TYPE", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_ICMPV6_CODE", 4, part1);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV6_ND_TARGET", 4, part1);
    /* part2 */
    part2 = (guint32)((match >> 32) & UINT_MAX);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV6_ND_SLL", 4, part2);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_IPV6_ND_TLL", 4, part2);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_MPLS_LABEL", 4, part2);
    ADD_BOOLEAN(mt, "ofp_flow_match_fields.OFPXMT_OFB_MPLS_TC", 4, part2);
}

void DissectorContext::dissect_ofp_action_type_bmp(proto_tree *mt, guint32 actbmp)
{
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_OUTPUT", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_COPY_TTL_OUT", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_COPY_TTL_IN", 4, actbmp);
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
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_SET_FIELD", 4, actbmp);
    ADD_BOOLEAN(mt, "ofp_action_type_bmp.OFPAT_EXPERIMENTER", 4, actbmp);
}

void DissectorContext::dissect_ofp_instruction_type_bmp(proto_tree *mt, guint32 instbmp)
{
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_GOTO_TABLE", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_WRITE_METADATA", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_WRITE_ACTIONS", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_APPLY_ACTIONS", 4, instbmp);
    ADD_BOOLEAN(mt, "ofp_instruction_type_bmp.OFPIT_CLEAR_ACTIONS", 4, instbmp);
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

void DissectorContext::dissect_ofp_flow_mod()
{
    ADD_TREE(tree, "ofp_flow_mod");

    ADD_CHILD(tree, "ofp_flow_mod.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_mod.cookie_mask", 8);
    READ_UINT8(tableid);
    add_child_ofp_table(tree, "ofp_flow_mod.table_id", tableid, 1);
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
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.RESERVED", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_RESET_COUNTS", 2, flags);
    CONSUME_BYTES(2);
    ADD_CHILD(tree, "padding", 2);

    ADD_SUBTREE(match_tree, tree, "ofp_flow_mod.match", this->_oflen - this->_offset);
    this->dissect_ofp_match(match_tree);

    try {
        while ((this->_oflen - this->_offset) > 0) {
            this->dissect_ofp_instruction(tree);
        }
    } catch (const ZeroLenInstruction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_packet_in(void)
{
    ADD_TREE(tree, "ofp_packet_in");

    ADD_CHILD(tree, "ofp_packet_in.buffer_id", 4);
    ADD_CHILD(tree, "ofp_packet_in.total_len", 2);
    ADD_CHILD(tree, "ofp_packet_in.reason", 1);
    READ_UINT8(tableid);
    add_child_ofp_table(tree, "ofp_packet_in.table_id", tableid, 1);

    ADD_SUBTREE(match_tree, tree, "ofp_packet_in.match", this->_oflen - this->_offset);
    this->dissect_ofp_match(match_tree);

    ADD_CHILD(tree, "padding", 2);

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

void DissectorContext::dissect_ofp_group_mod(void)
{
    ADD_TREE(tree, "ofp_group_mod");

    ADD_CHILD(tree, "ofp_group_mod.command", 2);
    ADD_CHILD(tree, "ofp_group_mod.type", 1);
    ADD_CHILD(tree, "padding", 1);
    READ_UINT32(group_id);
    add_child_ofp_group(tree, "ofp_group_mod.groupid", group_id, 4);

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

void DissectorContext::dissect_ofp_port(proto_tree* parent)
{
    ADD_SUBTREE(tree, parent, "ofp_port", 64);

    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_port.num", portid, 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_port.hwaddr", 6);
    ADD_CHILD(tree, "padding", 2);
    ADD_CHILD(tree, "ofp_port.name", 16);

    ADD_SUBTREE(config_tree, tree, "ofp_port.config", 4);
    READ_UINT32(ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.RESERVED", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(state_tree, tree, "ofp_port.state", 4);
    READ_UINT32(ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.RESERVED", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LINK_DOWN", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_BLOCKED", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LIVE", 4, ofpps);
    CONSUME_BYTES(4);

    ADD_SUBTREE(curr_feats_tree, tree, "ofp_port.curr_feats", 4);
    dissect_ofppf(curr_feats_tree);

    ADD_SUBTREE(advertised_tree, tree, "ofp_port.advertised", 4);
    dissect_ofppf(advertised_tree);

    ADD_SUBTREE(supported_tree, tree, "ofp_port.supported", 4);
    dissect_ofppf(supported_tree);

    ADD_SUBTREE(peer_tree, tree, "ofp_port.peer", 4);
    dissect_ofppf(peer_tree);

    ADD_CHILD(tree, "ofp_port.curr_speed", 4);
    ADD_CHILD(tree, "ofp_port.max_speed", 4);
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

void DissectorContext::dissect_ofp_match(proto_tree *tree)
{
    /*FIXME: We should care if the type isn't OXM (0x01) */
    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_match.type", 2);
    READ_UINT16(length);
    ADD_CHILD(tree, "ofp_match.len", 2);

    if (type != OFPMT_OXM) {
        SHOW_ERROR(tree, "Openflow1.2 only suppport OFPMT_OXM");
        ADD_CHILD(tree, "ofp_match.data", length - 4);
        return;
    }

    /* If the length is 8, we have an empty ofp_match, meaning that oxm_fields
    filled with padding bits. Otherwise, we have valid OXM fields. */
    if (length == 8) {
        ADD_CHILD(tree, "padding", 4);
    } else {
        dissect_ofp_oxm(tree, length);
    }
}

void DissectorContext::dissect_ofp_oxm(proto_tree *parent, guint32 length)
{
    int end = this->_offset + (length - 4);
    // Dissect each field
    while (this->_offset < end) {
        dissect_ofp_oxm_field(parent);
    }

    if (OFP_MATCH_OXM_PADDING(length) > 0) {
        ADD_CHILD(parent, "padding", OFP_MATCH_OXM_PADDING(length));
    }
}

int DissectorContext::dissect_ofp_oxm_field(proto_tree *parent)
{
    // Header contains length
    READ_UINT32(header);
    // Length tells us how long this field is
    guint32 length = UNPACK_OXM_LENGTH(header);

    ADD_SUBTREE(tree, parent, "ofp_oxm", length + 4);
    ADD_CHILD(tree, "ofp_oxm.oxm_class", 2);
    ADD_CHILD(tree, "ofp_oxm.oxm_field", 1);
    this->_offset -= 1; // Go back, we're not done with this byte!
    ADD_CHILD(tree, "ofp_oxm.oxm_hasmask", 1);
    ADD_CHILD(tree, "ofp_oxm.oxm_length", 1);

    // Choose field type to display the formatted value
    // TODO: add support for more types
    std::string value_field;
    switch (UNPACK_OXM_FIELD(header)) {
    case OFPXMT_OFB_IPV4_SRC:
    case OFPXMT_OFB_IPV4_DST:
        value_field = "ofp_oxm.value-IPV4";
        break;
    default:
        value_field = "ofp_oxm.value";
        break;
    }

    // If we have a mask, the body is double its normal size
    if (UNPACK_OXM_HASMASK(header)) {
        ADD_CHILD(tree, value_field, length/2);
        ADD_CHILD(tree, "ofp_oxm.mask", length/2);
    } else {
        ADD_CHILD(tree, value_field, length);
    }

    // TODO: based on field type, use the proper format for value and mask
    return length + 4;
}

void DissectorContext::dissect_ofp_instruction(proto_tree* parent)
{
    guint16 len;
    READ_UINT16(type);
    len = tvb_get_ntohs(this->_tvb, this->_offset + 2);

    guint32 message_end = this->_offset + len;
    if (len == 0) {
        throw ZeroLenInstruction();
    }

    ADD_SUBTREE(tree, parent, "ofp_instruction", len);
    ADD_CHILD(tree, "ofp_instruction.type", 2);
    ADD_CHILD(tree, "ofp_instruction.len", 2);

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
            while (this->_offset < message_end)
                this->dissect_ofp_action(tree);
        }
        catch (const ZeroLenAction &e) {
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

void DissectorContext::dissect_ofp_action(proto_tree* parent)
{
    guint16 len;
    guint32 end, oxm_len;

    READ_UINT16(type);
    len = tvb_get_ntohs(this->_tvb, this->_offset + 2);
    if (len == 0)
      { throw ZeroLenAction(); }

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_action", len);
    ADD_CHILD(tree, "ofp_action.type", 2);
    ADD_CHILD(tree, "ofp_action.len", 2);

    switch (type) {
    case OFPAT_OUTPUT: {
        READ_UINT32(portid);
        add_child_ofp_port_no(tree, "ofp_action_output.port", portid, 4);
        ADD_CHILD(tree, "ofp_action_output.max_len", 2);
        ADD_CHILD(tree, "padding", 6);
        break;
    }
    // Fieldless actions
    case OFPAT_COPY_TTL_OUT:
    case OFPAT_COPY_TTL_IN:
    case OFPAT_DEC_NW_TTL:
    case OFPAT_DEC_MPLS_TTL:
    case OFPAT_POP_VLAN:
        ADD_CHILD(tree, "padding", 4);
        break;
    case OFPAT_SET_MPLS_TTL:
        ADD_CHILD(tree, "ofp_action_mpls_ttl.mpls_ttl", 1);
        ADD_CHILD(tree, "padding", 3);
        break;
    case OFPAT_PUSH_VLAN:
    case OFPAT_PUSH_MPLS:
        ADD_CHILD(tree, "ofp_action_push.ethertype", 2);
        ADD_CHILD(tree, "padding", 2);
        break;
    case OFPAT_POP_MPLS:
        ADD_CHILD(tree, "ofp_action_pop_mpls.ethertype", 2);
        ADD_CHILD(tree, "padding", 2);
        break;
    case OFPAT_SET_QUEUE: {
        READ_UINT32(queueid);
        add_child_ofp_queue_id(tree, "ofp_action_set_queue.queue_id", queueid, 4);
        break;
    }
    case OFPAT_GROUP: {
        READ_UINT32(groupid);
        add_child_ofp_group(tree, "ofp_action_group.group_id", groupid, 4);
        break;
    }
    case OFPAT_SET_NW_TTL:
        ADD_CHILD(tree, "ofp_action_nw_ttl.nw_ttl", 1);
        ADD_CHILD(tree, "padding", 3);
        break;
    case OFPAT_SET_FIELD:
        // We can reuse ofp_oxm_field becauseofp_action_set_field contains only one OXM field
        oxm_len = dissect_ofp_oxm_field(tree);
        ADD_CHILD(tree, "padding", OFP_ACTION_SET_FIELD_OXM_PADDING(oxm_len));
        break;
    case OFPAT_EXPERIMENTER:
        ADD_CHILD(tree, "ofp_action_experimenter_header.experimenter", 4);
        break;
    default:
        CONSUME_BYTES(message_end - this->_offset);
        break;
    }
}

void DissectorContext::dissect_ofp_group_bucket(proto_tree* parent)
{
    READ_UINT16(len);

    if (len == 0) {
        throw ZeroLenBucket();
    }

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_group_mod.bucket", len);
    ADD_CHILD(tree, "ofp_group_mod_bucket.len", 2);
    ADD_CHILD(tree, "ofp_group_mod_bucket.weight", 2);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_group_mod_bucket.watch_port", portid, 4);
    READ_UINT32(groupid);
    add_child_ofp_group(tree, "ofp_group_mod_bucket.watch_group", groupid, 4);
    ADD_CHILD(tree, "padding", 4);

    try {
        while (this->_offset < message_end) {
            this->dissect_ofp_action(tree);
        }
    } catch(const ZeroLenAction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_role_request(void)
{
    ADD_TREE(tree, "ofp_role_request");
    ADD_CHILD(tree, "ofp_role_request.role", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_role_request.generation_id", 8);
}

void DissectorContext::dissect_ofp_role_reply(void)
{
    ADD_TREE(tree, "ofp_role_reply");
    ADD_CHILD(tree, "ofp_role_reply.role", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_role_reply.generation_id", 8);
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
    } else if (property == OFPQT_MAX_RATE) {
        ADD_CHILD(tree, "ofp_queue_prop_max_rate.rate", 2);
        ADD_CHILD(tree, "padding", 6);
    } else if (property == OFPQT_EXPERIMENTER) {
        ADD_CHILD(tree, "ofp_queue_prop_experimenter.experimenter", 4);
        ADD_CHILD(tree, "padding", 4);
    }
}

void DissectorContext::dissect_ofp_packet_queue(proto_tree *parent)
{
    guint32 msg_end;

    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset + 8);
    msg_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_packet_queue", len);

    READ_UINT32(queueid);
    add_child_ofp_queue_id(tree, "ofp_packet_queue.queue_id", queueid, 4);
    READ_UINT32(portid);
    add_child_ofp_port_no(tree, "ofp_packet_queue.port", portid, 4);
    ADD_CHILD(tree, "ofp_packet_queue.len", 2);
    ADD_CHILD(tree, "padding", 6);

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

void DissectorContext::add_child_ofp_table(proto_tree* tree, const char *field, guint8 tableid,
                        guint32 len)
{
    const char* str_table = NULL;
    char str_tblid[6];

    switch (tableid) {
    case OFPTT_MAX:
        str_table = "OFPTT_MAX(0xFE) - Last usable table number";
        break;
    case OFPTT_ALL:
        str_table = "OFPTT_ALL(0xFF) - Fake tables";
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
    case OFPVID_PRESENT:
        str_vlan = "OFPVID_PRESENT(0x1000) - Bit that indicate that a VLAN id is set";
        break;
    case OFPVID_NONE:
        str_vlan = "OFPVID_NONE(0x0000) - No VLAN id was set";
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

// Boring part
void DissectorContext::setupFields()
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
    FIELD("ofp_error.code.OFPET_BAD_INSTRUCTION", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_instruction_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_MATCH", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_match_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_FLOW_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_flow_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_GROUP_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_group_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_PORT_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_port_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_TABLE_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_table_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_QUEUE_OP_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_queue_op_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_SWITCH_CONFIG_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_switch_config_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_ROLE_REQUEST_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_role_request_failed_code), NO_MASK);
    FIELD("ofp_error.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_feature_request
    FIELD("ofp_feature_request", "Feature Request", FT_NONE, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_switch_features
    TREE_FIELD("ofp_switch_features", "Feature Reply");
    FIELD("ofp_switch_features.datapath_id", "Datapath ID", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.n_buffers", "Buffers", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.n_tables", "Tables", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_switch_features.capabilities", "Capabilities", FT_UINT32);
    FIELD("ofp_switch_features.reserved", "Reserved", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_switch_features.ports", "Ports");
    FIELD("ofp_switch_features.port_num", "Number of ports", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_port
    TREE_FIELD("ofp_port", "Port Description");
    FIELD("ofp_port.num", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.hwaddr", "Hardware Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port.config", "Config", FT_UINT32);
    BITMAP_FIELD("ofp_port.state", "State", FT_UINT32);
    BITMAP_FIELD("ofp_port.curr_feats", "Current Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.advertised", "Advertised Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.supported", "Supported Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.peer", "Peer Features", FT_UINT32);
    FIELD("ofp_port.curr_speed", "Current Speed (kbps)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port.max_speed", "Maximum Speed (kbps)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_switch_config
    TREE_FIELD("ofp_switch_config", "Switch Configuration");
    BITMAP_FIELD("ofp_switch_config.flags", "Flags", FT_UINT16);
    FIELD("ofp_switch_config.miss_send_len", "Max new flow bytes to controller", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_match
    TREE_FIELD("ofp_match", "Match");
    FIELD("ofp_match.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_match_type), NO_MASK);
    FIELD("ofp_match.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_match.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_oxm_field
    TREE_FIELD("ofp_oxm", "OXM field");
    FIELD("ofp_oxm.oxm_class", "Class", FT_UINT16, BASE_HEX, VALUES(ofp_oxm_class), NO_MASK);
    FIELD("ofp_oxm.oxm_field", "Field", FT_UINT8, BASE_HEX, VALUES(oxm_ofb_match_fields), 0xFE);
    FIELD("ofp_oxm.oxm_hasmask", "Has mask", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x01);
    FIELD("ofp_oxm.oxm_length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_oxm.value", "Value", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_oxm.value-IPV4", "Value", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_oxm.mask", "Mask", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_action_*
    TREE_FIELD("ofp_action", "Action");
    FIELD("ofp_action.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_action_type), NO_MASK);
    FIELD("ofp_action.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.port", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.max_len", "Max Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_group.group_id", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_queue.queue_id", "Queue ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_mpls_ttl.mpls_ttl", "MPLS TTL", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_nw_ttl.nw_ttl", "NW TTL", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_push.ethertype", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_action_pop_mpls.ethertype", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    //ofp_action_set_field is defined using ofp_oxm
    FIELD("ofp_action_experimenter_header.experimenter", "Experimenter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

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
    BITMAP_FIELD("ofp_table_stats.match", "Bitmap of match", FT_UINT64);
    BITMAP_FIELD("ofp_table_stats.wildcards", "Bitmap of Wildcards", FT_UINT64);
    BITMAP_FIELD("ofp_table_stats.write_actions", "Bitmap of Write Action", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.apply_actions", "Bitmap of Apply Action", FT_UINT32);
    BITMAP_FIELD("ofp_table_stats.write_setfields", "Bitmap of Write Set Field", FT_UINT64);
    BITMAP_FIELD("ofp_table_stats.apply_setfields", "Bitmap of Apply Set Field", FT_UINT64);
    FIELD("ofp_table_stats.metadata_match", "Metadata match", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_table_stats.metadata_write", "Metadata write", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_table_stats.instructions", "Bitmap of Instructions", FT_UINT32);
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

    //ofp_group_desc
    TREE_FIELD("ofp_group_desc", "Group Description");
    FIELD("ofp_group_desc.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_desc.type", "Group_type", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_desc.group_id", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_group_features
    TREE_FIELD("ofp_group_features", "Group Features");
    BITMAP_FIELD("ofp_group_features.types", "Group types supported", FT_UINT32);
    BITMAP_FIELD("ofp_group_features.capabilities", "Capability supported", FT_UINT32);
    FIELD("ofp_group_features.max_groups", "Maximum number of groups for each type", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_group_features.actions", "Actions supported for each type", FT_UINT32);

    //ofp_experimenter_multipart_header
    TREE_FIELD("ofp_experimenter_multipart_header", "Experimenter");
    FIELD("ofp_experimenter_multipart_header.experimenter", "Experimenter ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_experimenter_multipart_header.exp_type", "Experimenter defined type", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_experimenter_multipart_header.data", "Experimenter data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_stats_request
    TREE_FIELD("ofp_stats_request", "Stats Request");
    FIELD("ofp_stats_request.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_stats_types), NO_MASK);
    FIELD("ofp_stats_request.flags", "Flags", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    //BITMAP_FIELD("ofp_flow_mod.flags", "Flags", FT_UINT16);
    FIELD("ofp_stats_request.body", "Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_stats_reply
    TREE_FIELD("ofp_stats_reply", "Stats Reply");
    FIELD("ofp_stats_reply.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_stats_types), NO_MASK);
    BITMAP_FIELD("ofp_stats_reply.flags", "Flags", FT_UINT16);
    FIELD("ofp_stats_reply.body", "Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_port_status
    TREE_FIELD("ofp_port_status", "Port Status");
    FIELD("ofp_port_status.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_port_reason), NO_MASK);
    TREE_FIELD("ofp_port_status.desc", "Ports");

    //ofp_flow_mod
    TREE_FIELD("ofp_flow_mod", "Flow Mod");
    FIELD("ofp_flow_mod.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.cookie_mask", "Cookie Mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.command", "Command", FT_UINT8, BASE_HEX, VALUES(ofp_flow_mod_command), NO_MASK);
    FIELD("ofp_flow_mod.idle_timeout", "Idle Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.hard_timeout", "Hard Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_port", "Output Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_group", "Output Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_flow_mod.flags", "Flags", FT_UINT16);
    TREE_FIELD("ofp_flow_mod.match", "Match");

    //ofp_instruction
    TREE_FIELD("ofp_instruction", "Instruction");
    FIELD("ofp_instruction.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_instruction_type), NO_MASK);
    FIELD("ofp_instruction.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    FIELD("ofp_instruction_goto_table.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_write_metadata.metadata", "Metadata", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_write_metadata.metadata_mask", "Metadata Mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_group_mod
    TREE_FIELD("ofp_group_mod", "Group Mod");
    FIELD("ofp_group_mod.command", "Command", FT_UINT16, BASE_HEX, VALUES(ofp_group_mod_command), NO_MASK);
    FIELD("ofp_group_mod.type", "Type", FT_UINT8, BASE_HEX, VALUES(ofp_group_type), NO_MASK);
    FIELD("ofp_group_mod.groupid", "Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_group_mod.bucket", "Bucket");
    FIELD("ofp_group_mod_bucket.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_mod_bucket.weight", "Weight", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_group_mod_bucket.watch_port", "Watch Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_group_mod_bucket.watch_group", "Watch Group ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_table_mod
    TREE_FIELD("ofp_table_mod", "Table Mod");
    FIELD("ofp_table_mod.id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_table_mod.config", "Config", FT_UINT32);

    //ofp_port_mod
    TREE_FIELD("ofp_port_mod", "Port Mod");
    FIELD("ofp_port_mod.port_no", "Port NO ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port_mod.hw_addr", "MAC Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port_mod.config", "Port Config Flags", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.mask", "Port Mask Flags", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.advertised", "Port Advertise Flags", FT_UINT32);

    //ofp_packet_in
    TREE_FIELD("ofp_packet_in", "Packet in");
    FIELD("ofp_packet_in.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.total_len", "Total length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_packet_in_reason), NO_MASK);
    FIELD("ofp_packet_in.table_id", "Table ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_packet_in.match", "Match");
    FIELD("ofp_packet_in.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_packet_out
    TREE_FIELD("ofp_packet_out", "Packet out");
    FIELD("ofp_packet_out.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.in_port", "Input port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.actions_len", "Actions length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_role_request
    TREE_FIELD("ofp_role_request", "Role request");
    FIELD("ofp_role_request.role", "Role", FT_UINT32, BASE_HEX, VALUES(ofp_controller_role), NO_MASK);
    FIELD("ofp_role_request.generation_id", "Generation ID", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_role_reply
    TREE_FIELD("ofp_role_reply", "Role reply");
    FIELD("ofp_role_reply.role", "Role", FT_UINT32, BASE_HEX, VALUES(ofp_controller_role), NO_MASK);
    FIELD("ofp_role_reply.generation_id", "Generation ID", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    //ofp_queue_get_config_request
    TREE_FIELD("ofp_queue_get_config_request", "Queue Configuration Request");
    FIELD("ofp_queue_get_config_request.port", "Port(< OFPP_MAX) ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_queue_get_config_reply
    TREE_FIELD("ofp_queue_get_config_reply", "Queue Configuration Reply");
    FIELD("ofp_queue_get_config_reply.port", "Port(< OFPP_MAX) ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    //ofp_packet_queue
    TREE_FIELD("ofp_packet_queue", "Queue desc");
    FIELD("ofp_packet_queue.queue_id", "Queue ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_queue.port", "Port ID", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_queue.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_queue_prop_header
    TREE_FIELD("ofp_queue_prop_header", "Queue property");
    FIELD("ofp_packet_queue.property", "property", FT_UINT16, BASE_DEC, VALUES(ofp_queue_property), NO_MASK);
    FIELD("ofp_packet_queue.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_queue_prop_min_rate
    TREE_FIELD("ofp_queue_prop_min_rate", "Min-Rate queue property");
    FIELD("ofp_queue_prop_min_rate.rate", "Min rate In 1/10 of a percent", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_queue_prop_max_rate
    TREE_FIELD("ofp_queue_prop_max_rate", "Max-Rate queue property");
    FIELD("ofp_queue_prop_max_rate.rate", "Max rate In 1/10 of a percent", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    //ofp_queue_prop_experimenter
    TREE_FIELD("ofp_queue_prop_experimenter", "Experimenter queue property");
    FIELD("ofp_queue_prop_experimenter.experimenter", "Experimenter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
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
    TYPE_ARRAY_ADD(ofp_type, OFPT_EXPERIMENTER, "Experimenter message (SM) - OFPT_EXPERIMENTER");
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
    TYPE_ARRAY_ADD(ofp_type, OFPT_ROLE_REQUEST, "Role request (CSM) - OFPT_ROLE_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ROLE_REPLY, "Role reply (CSM) - OFPT_ROLE_REPLY");

    // ofp_queue_properties
    TYPE_ARRAY(ofp_queue_properties);
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_MIN_RATE, "Minimum datarate guaranteed - OFPQT_MIN_RATE");
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_MAX_RATE, "Maximum datarate - OFPQT_MAX_RATE");
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_EXPERIMENTER, "Experimenter defined property - OFPQT_EXPERIMENTER");

    // ofp_match_type
    TYPE_ARRAY(ofp_match_type);
    TYPE_ARRAY_ADD(ofp_match_type, OFPMT_STANDARD, "Deprecated - OFPMT_STANDARD");
    TYPE_ARRAY_ADD(ofp_match_type, OFPMT_OXM, "OpenFlow Extensible Match - OFPMT_OXM");

    // ofp_oxm_class
    TYPE_ARRAY(ofp_oxm_class);
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_NXM_0, "Backward compatibility with NXM - OFPXMC_NXM_0");
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_NXM_1, "Backward compatibility with NXM - OFPXMC_NXM_1");
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_OPENFLOW_BASIC, "Basic class for OpenFlow - OFPXMC_OPENFLOW_BASIC");
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_EXPERIMENTER, "Experimenter class - OFPXMC_EXPERIMENTER");

    // oxm_ofb_match_fields
    TYPE_ARRAY(oxm_ofb_match_fields);
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IN_PORT, "Switch input port - OFPXMT_OFB_IN_PORT");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IN_PHY_PORT, "Switch physical input port - OFPXMT_OFB_IN_PHY_PORT");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_METADATA, "Metadata passed between tables - OFPXMT_OFB_METADATA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ETH_DST, "Ethernet destination address - OFPXMT_OFB_ETH_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ETH_SRC, "Ethernet source address - OFPXMT_OFB_ETH_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ETH_TYPE, "Ethernet frame type - OFPXMT_OFB_ETH_TYPE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_VLAN_VID, "VLAN id - OFPXMT_OFB_VLAN_VID");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_VLAN_PCP, "VLAN priority - OFPXMT_OFB_VLAN_PCP");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IP_DSCP, "IP DSCP (6 bits in ToS field) - OFPXMT_OFB_IP_DSCP");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IP_ECN, "IP ECN (2 bits in ToS field) - OFPXMT_OFB_IP_ECN");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IP_PROTO, "IP protocol - OFPXMT_OFB_IP_PROTO");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV4_SRC, "IPv4 source address - OFPXMT_OFB_IPV4_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV4_DST, "IPv4 destination address - OFPXMT_OFB_IPV4_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_TCP_SRC, "TCP source port - OFPXMT_OFB_TCP_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_TCP_DST, "TCP destination port - OFPXMT_OFB_TCP_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_UDP_SRC, "UDP source port - OFPXMT_OFB_UDP_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_UDP_DST, "UDP destination port - OFPXMT_OFB_UDP_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_SCTP_SRC, "SCTP source port - OFPXMT_OFB_SCTP_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_SCTP_DST, "SCTP destination port - OFPXMT_OFB_SCTP_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV4_TYPE, "ICMP type - OFPXMT_OFB_ICMPV4_TYPE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV4_CODE, "ICMP code - OFPXMT_OFB_ICMPV4_CODE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_OP, "ARP opcode - OFPXMT_OFB_ARP_OP");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_SPA, "ARP source IPv4 address - OFPXMT_OFB_ARP_SPA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_TPA, "ARP target IPv4 address - OFPXMT_OFB_ARP_TPA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_SHA, "ARP source hardware address - OFPXMT_OFB_ARP_SHA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_THA, "ARP target hardware address - OFPXMT_OFB_ARP_THA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_SRC, "IPv6 source address - OFPXMT_OFB_IPV6_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_DST, "IPv6 destination address - OFPXMT_OFB_IPV6_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_FLABEL, "IPv6 Flow Label - OFPXMT_OFB_IPV6_FLABEL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV6_TYPE, "ICMPv6 type - OFPXMT_OFB_ICMPV6_TYPE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV6_CODE, "ICMPv6 code - OFPXMT_OFB_ICMPV6_CODE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_ND_TARGET, "Target address for ND - OFPXMT_OFB_IPV6_ND_TARGET");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_ND_SLL, "Source link-layer for ND - OFPXMT_OFB_IPV6_ND_SLL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_ND_TLL, "Target link-layer for ND - OFPXMT_OFB_IPV6_ND_TLL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_MPLS_LABEL, "MPLS label - OFPXMT_OFB_MPLS_LABEL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_MPLS_TC, "MPLS TC - OFPXMT_OFB_MPLS_TC");

    // ofp_instruction_type
    TYPE_ARRAY(ofp_instruction_type);
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_GOTO_TABLE, "Setup the next table in the lookup - OFPIT_GOTO_TABLE");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_WRITE_METADATA, "Setup the metadata field for use later in pipeline - OFPIT_WRITE_METADATA");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_WRITE_ACTIONS, "Write the action(s) onto the datapath action set - OFPIT_WRITE_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_APPLY_ACTIONS, "Applies the action(s) immediately - OFPIT_APPLY_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_CLEAR_ACTIONS, "Clears all actions from the datapath action set - OFPIT_CLEAR_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_EXPERIMENTER, "Experimenter instruction - OFPIT_EXPERIMENTER");

    // ofp_action_type
    TYPE_ARRAY(ofp_action_type);
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_OUTPUT, "Output to switch port - OFPAT_OUTPUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_COPY_TTL_OUT, "Copy TTL \"outwards\" -- from next-to-outermost to outermost - OFPAT_COPY_TTL_OUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_COPY_TTL_IN, "Copy TTL \"inwards\" -- from outermost to next-to-outermost - OFPAT_COPY_TTL_IN");
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
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_FIELD, "Set a header field using OXM TLV format - OFPAT_SET_FIELD");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_EXPERIMENTER, "Experimenter action - OFPAT_EXPERIMENTER");

    // ofp_controller_max_len
    TYPE_ARRAY(ofp_controller_max_len);
    TYPE_ARRAY_ADD(ofp_controller_max_len, OFPCML_MAX, "maximum max_len value which can be used to request a specific byte length - OFPCML_MAX");
    TYPE_ARRAY_ADD(ofp_controller_max_len, OFPCML_NO_BUFFER, "indicates that no buffering should be applied and the whole packet is to be sent to the controller - OFPCML_NO_BUFFER");

    // ofp_flow_mod_command
    TYPE_ARRAY(ofp_flow_mod_command);
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_ADD, "New flow - OFPFC_ADD");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY, "Modify all matching flows - OFPFC_MODIFY");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY_STRICT, "Modify entry strictly matching wildcards and priority - OFPFC_MODIFY_STRICT");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE, "Delete all matching flows - OFPFC_DELETE");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE_STRICT, "Delete entry strictly matching wildcards and priority - OFPFC_DELETE_STRICT");

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

    // ofp_stats_types
    TYPE_ARRAY(ofp_stats_types);
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_DESC, "Description of an OpenFlow switch - OFPST_DESC");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_FLOW, "Individual flow statistics - OFPST_FLOW");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_AGGREGATE, "Aggregate flow statistics - OFPST_AGGREGATE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_TABLE, "Flow table statistics - OFPST_TABLE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_PORT, "Port statistics - OFPST_PORT");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_QUEUE, "Queue statistics for a port - OFPST_QUEUE");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_GROUP, "Group counter statistics - OFPST_GROUP");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_GROUP_DESC, "Group description statistics - OFPST_GROUP_DESC");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_GROUP_FEATURES, "Group features - OFPST_GROUP_FEATURES");
    TYPE_ARRAY_ADD(ofp_stats_types, OFPST_EXPERIMENTER, "Experimenter extension - OFPST_EXPERIMENTER");

    // ofp_controller_role
    TYPE_ARRAY(ofp_controller_role);
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_NOCHANGE, "don't change current role - OFPCR_ROLE_NOCHANGE");
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_EQUAL, "Default role, full access - OFPCR_ROLE_EQUAL");
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_MASTER, "Full access, at most one master - OFPCR_ROLE_MASTER");
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_SLAVE, "Read-only access - OFPCR_ROLE_SLAVE");

    // ofp_packet_in_reason
    TYPE_ARRAY(ofp_packet_in_reason);
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_NO_MATCH, "No matching flow - OFPR_NO_MATCH");
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_ACTION, "Action explicitly output to controller - OFPR_ACTION");
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_INVALID_TTL, "Packet has invalid TTL - OFPR_INVALID_TTL");

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
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_ROLE_REQUEST_FAILED, "Controller Role request failed - OFPET_ROLE_REQUEST_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_EXPERIMENTER, "Experimenter error messages - OFPET_EXPERIMENTER");

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
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_EXP_TYPE, "Experimenter type not supported - OFPBRC_BAD_EXP_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_EPERM, "Permissions error - OFPBRC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_LEN, "Wrong request length for type - OFPBRC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_EMPTY, "Specified buffer has already been used - OFPBRC_BUFFER_EMPTY");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_UNKNOWN, "Specified buffer does not exist - OFPBRC_BUFFER_UNKNOWN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_TABLE_ID, "Specified table-id invalid or does not exist - OFPBRC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_IS_SLAVE, "Denied because controller is slave - OFPBRC_IS_SLAVE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_PORT, "Invalid port - OFPBRC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_PACKET, "Invalid packet in packet-out - OFPBRC_BAD_PACKET");

    // ofp_bad_action_code
    TYPE_ARRAY(ofp_bad_action_code);
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TYPE, "Unknown action type - OFPBAC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_LEN, "Length problem in actions - OFPBAC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_EXPERIMENTER, "Unknown experimenter id specified - OFPBAC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_EXP_TYPE, "Unknown action for experimenter id - OFPBAC_BAD_EXP_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_PORT, "Problem validating output port - OFPBAC_BAD_OUT_PORT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_ARGUMENT, "Bad action argument - OFPBAC_BAD_ARGUMENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_EPERM, "Permissions error - OFPBAC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_TOO_MANY, "Can't handle this many actions - OFPBAC_TOO_MANY");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_QUEUE, "Problem validating output queue - OFPBAC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_GROUP, "Invalid group id in forward action - OFPBAC_BAD_OUT_GROUP");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_MATCH_INCONSISTENT, "Action can't apply for this match or Set-Field missing prerequisite - OFPBAC_MATCH_INCONSISTENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_UNSUPPORTED_ORDER, "Action order is unsupported for the action list in an Apply-Actions instruction - OFPBAC_UNSUPPORTED_ORDER");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TAG, "Actions uses an unsupported tag/encap - OFPBAC_BAD_TAG");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_SET_TYPE, "Unsupported type in SET_FIELD action - OFPBAC_BAD_SET_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_SET_LEN, "Length problem in SET_FIELD action - OFPBAC_BAD_SET_LEN");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_SET_ARGUMENT, "Bad argument in SET_FIELD action - OFPBAC_BAD_SET_ARGUMENT");

    // ofp_bad_instruction_code
    TYPE_ARRAY(ofp_bad_instruction_code);
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNKNOWN_INST, "Unknown instruction - OFPBIC_UNKNOWN_INST");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_INST, "Switch or table does not support the instruction - OFPBIC_UNSUP_INST");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_TABLE_ID, "Invalid Table-ID specified - OFPBIC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_METADATA, "Metadata value unsupported by datapath - OFPBIC_UNSUP_METADATA");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_METADATA_MASK, "Metadata mask value unsupported by datapath - OFPBIC_UNSUP_METADATA_MASK");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_EXPERIMENTER, "Unknown experimenter id specified - OFPBIC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_EXP_TYPE, "Unknown instruction for experimenter id - OFPBIC_BAD_EXP_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_LEN, "Length problem in instructions - OFPBIC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_EPERM, "Permissions error - OFPBIC_EPERM");

    // ofp_bad_match_code
    TYPE_ARRAY(ofp_bad_match_code);
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_TYPE, "Unsupported match type specified by the match - OFPBMC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_LEN, "Length problem in match - OFPBMC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_TAG, "Match uses an unsupported tag/encap - OFPBMC_BAD_TAG");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_DL_ADDR_MASK, "Unsupported datalink addr mask - switch does not support arbitrary datalink address mask - OFPBMC_BAD_DL_ADDR_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_NW_ADDR_MASK, "Unsupported network addr mask - switch does not support arbitrary network address mask - OFPBMC_BAD_NW_ADDR_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_WILDCARDS, "Unsupported combination of fields masked or omitted in the match - OFPBMC_BAD_WILDCARDS");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_FIELD, "Unsupported field type in the match - OFPBMC_BAD_FIELD");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_VALUE, "Unsupported value in a match field - OFPBMC_BAD_VALUE");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_MASK, "Unsupported mask specified in the match, field is not dl-address or nw-address - OFPBMC_BAD_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_PREREQ, "A prerequisite was not met - OFPBMC_BAD_PREREQ");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_DUP_FIELD, "A field type was duplicated - OFPBMC_DUP_FIELD");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_EPERM, "Permissions error - OFPBMC_EPERM");

    // ofp_flow_mod_failed_code
    TYPE_ARRAY(ofp_flow_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_UNKNOWN, "Unspecified error - OFPFMFC_UNKNOWN");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_TABLE_FULL, "Flow not added because table was full - OFPFMFC_TABLE_FULL");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_TABLE_ID, "Table does not exist - OFPFMFC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_OVERLAP, "Attempted to add overlapping flow with CHECK_OVERLAP flag set - OFPFMFC_OVERLAP");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_EPERM, "Permissions error - OFPFMFC_EPERM");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_TIMEOUT, "Flow not added because of unsupported idle/hard timeout - OFPFMFC_BAD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_COMMAND, "Unsupported or unknown command - OFPFMFC_BAD_COMMAND");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_FLAGS, "Unsupported or unknown flags - OFPFMFC_BAD_FLAGS");

    // ofp_group_mod_failed_code
    TYPE_ARRAY(ofp_group_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_GROUP_EXISTS, "Group not added because a group ADD attempted to replace an already-present group - OFPGMFC_GROUP_EXISTS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_INVALID_GROUP, "Group not added because Group - OFPGMFC_INVALID_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_OUT_OF_GROUPS, "The group table is full - OFPGMFC_OUT_OF_GROUPS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_OUT_OF_BUCKETS, "The maximum number of action buckets for a group has been exceeded - OFPGMFC_OUT_OF_BUCKETS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_CHAINING_UNSUPPORTED, "Switch does not support groups that forward to groups - OFPGMFC_CHAINING_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_WATCH_UNSUPPORTED, "This group cannot watch the watch_port or watch_group specified - OFPGMFC_WATCH_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_LOOP, "Group entry would cause a loop - OFPGMFC_LOOP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_UNKNOWN_GROUP, "Group not modified because a group MODIFY attempted to modify a non-existent group - OFPGMFC_UNKNOWN_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_CHAINED_GROUP, "Group not deleted because another group is forwarding to it - OFPGMFC_CHAINED_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_TYPE, "Unsupported or unknown group type - OFPGMFC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_COMMAND, "Unsupported or unknown command - OFPGMFC_BAD_COMMAND");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_BUCKET, "Error in bucket - OFPGMFC_BAD_BUCKET");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_WATCH, "Error in watch port/group - OFPGMFC_BAD_WATCH");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_EPERM, "Permissions error - OFPGMFC_EPERM");

    // ofp_port_mod_failed_code
    TYPE_ARRAY(ofp_port_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_PORT, "Specified port number does not exist - OFPPMFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_HW_ADDR, "Specified hardware address does not match the port number - OFPPMFC_BAD_HW_ADDR");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_CONFIG, "Specified config is invalid - OFPPMFC_BAD_CONFIG");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_ADVERTISE, "Specified advertise is invalid - OFPPMFC_BAD_ADVERTISE");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_EPERM, "Permissions error - OFPPMFC_EPERM");

    // ofp_table_mod_failed_code
    TYPE_ARRAY(ofp_table_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_BAD_TABLE, "Specified table does not exist - OFPTMFC_BAD_TABLE");
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_BAD_CONFIG, "Specified config is invalid - OFPTMFC_BAD_CONFIG");
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_EPERM, "Permissions error - OFPTMFC_EPERM");

    // ofp_queue_op_failed_code
    TYPE_ARRAY(ofp_queue_op_failed_code);
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_PORT, "Invalid port (or port does not exist) - OFPQOFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_QUEUE, "Queue does not exist - OFPQOFC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_EPERM, "Permissions error - OFPQOFC_EPERM");

    // ofp_switch_config_failed_code
    TYPE_ARRAY(ofp_switch_config_failed_code);
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_BAD_FLAGS, "Specified flags is invalid - OFPSCFC_BAD_FLAGS");
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_BAD_LEN, "Specified len is invalid - OFPSCFC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_EPERM, "Permissions error - OFPSCFC_EPERM");

    // ofp_role_request_failed_code
    TYPE_ARRAY(ofp_role_request_failed_code);
    TYPE_ARRAY_ADD(ofp_role_request_failed_code, OFPRRFC_STALE, "Stale Message: old generation_id - OFPRRFC_STALE");
    TYPE_ARRAY_ADD(ofp_role_request_failed_code, OFPRRFC_UNSUP, "Controller role change unsupported - OFPRRFC_UNSUP");
    TYPE_ARRAY_ADD(ofp_role_request_failed_code, OFPRRFC_BAD_ROLE, "Invalid role - OFPRRFC_BAD_ROLE");

    // ofp_queue_property
    TYPE_ARRAY(ofp_queue_property);
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_MIN_RATE, "Minimum datarate guaranteed - OFPQT_MIN_RATE");
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_MAX_RATE, "Maximum datarate - OFPQT_MAX_RATE");
    TYPE_ARRAY_ADD(ofp_queue_property, OFPQT_EXPERIMENTER, "Experimenter defined property - OFPQT_EXPERIMENTER");
}


void DissectorContext::setupFlags(void)
{
    // ofp_port_config
    BITMAP_PART("ofp_port_config.OFPPC_PORT_DOWN", "Port is administratively down", 32, OFPPC_PORT_DOWN);
    BITMAP_PART("ofp_port_config.OFPPC_NO_RECV", "Drop all packets received by port", 32, OFPPC_NO_RECV);
    BITMAP_PART("ofp_port_config.OFPPC_NO_FWD", "Drop packets forwarded to port", 32, OFPPC_NO_FWD);
    BITMAP_PART("ofp_port_config.OFPPC_NO_PACKET_IN", "Do not send packet-in msgs for port", 32, OFPPC_NO_PACKET_IN);
    BITMAP_PART("ofp_port_config.RESERVED", "Reserved", 32, 0xffffff9a);

    // ofp_port_state
    BITMAP_PART("ofp_port_state.OFPPS_LINK_DOWN", "No physical link present", 32, OFPPS_LINK_DOWN);
    BITMAP_PART("ofp_port_state.OFPPS_BLOCKED", "Port is blocked", 32, OFPPS_BLOCKED);
    BITMAP_PART("ofp_port_state.OFPPS_LIVE", "Live for Fast Failover Group", 32, OFPPS_LIVE);
    BITMAP_PART("ofp_port_state.RESERVED", "Reserved", 32, 0xfffffff8);

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

    // ofp_capabilities
    BITMAP_PART("ofp_capabilities.OFPC_FLOW_STATS", "Support flow statistics", 32, OFPC_FLOW_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_TABLE_STATS", "Support table statistics", 32, OFPC_TABLE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_PORT_STATS", "Support port statistics", 32, OFPC_PORT_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_GROUP_STATS", "Support group statistics", 32, OFPC_GROUP_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_IP_REASM", "Support can reassemble IP fragments", 32, OFPC_IP_REASM);
    BITMAP_PART("ofp_capabilities.OFPC_QUEUE_STATS", "Support queue statistics", 32, OFPC_QUEUE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_PORT_BLOCKED", "Support switch will block looping ports", 32, OFPC_PORT_BLOCKED);
    BITMAP_PART("ofp_capabilities.RESERVED", "Reserved", 32, 0xfffffe90);

    // ofp_config_flags
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_DROP", "Drop fragments", 16, OFPC_FRAG_DROP);
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_REASM", "Reassemble (only if OFPC_IP_REASM set)", 16, OFPC_FRAG_REASM);
    BITMAP_PART("ofp_config_flags.OFPC_INVALID_TTL_TO_CONTROLLER", "Send packets with invalid TTL to the controller", 16, OFPC_INVALID_TTL_TO_CONTROLLER);
    BITMAP_PART("ofp_config_flags.RESERVED", "Reserved", 16, 0xfff8);
    //BITMAP_PART("ofp_config_flags.OFPC_FRAG_NORMAL", "No special handling for fragments", 16, 0xffff);
    FIELD("ofp_config_flags.OFPC_FRAG_NORMAL", "No special handling for fragments", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    // ofp_flow_mod_flags
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", "Send flow removed message when flow expires or is deleted", 16, OFPFF_SEND_FLOW_REM);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", "Check for overlapping entries first", 16, OFPFF_CHECK_OVERLAP);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_RESET_COUNTS", "Reset flow packet and byte counts", 16, OFPFF_RESET_COUNTS);
    BITMAP_PART("ofp_flow_mod_flags.RESERVED", "Reserved", 16, 0xfff8);

    // ofp_stats_reply_flags
    BITMAP_PART("ofp_stats_reply_flags.OFPSF_REPLY_MORE", "More replies to follow", 16, OFPSF_REPLY_MORE);
    BITMAP_PART("ofp_stats_reply_flags.RESERVED", "Reserved", 16, 0xfffe);

    // ofp_group_capabilities
    BITMAP_PART("ofp_group_capabilities.OFPGFC_SELECT_WEIGHT", "Support weight for select groups", 32, OFPGFC_SELECT_WEIGHT);
    BITMAP_PART("ofp_group_capabilities.OFPGFC_SELECT_LIVENESS", "Support liveness for select groups", 32, OFPGFC_SELECT_LIVENESS);
    BITMAP_PART("ofp_group_capabilities.OFPGFC_CHAINING", "Support chaining groups", 32, OFPGFC_CHAINING);
    BITMAP_PART("ofp_group_capabilities.OFPGFC_CHAINING_CHECKS", "Check chaining for loops and delete", 32, OFPGFC_CHAINING_CHECKS);
    BITMAP_PART("ofp_group_capabilities.RESERVED", "Reserved", 32, 0xfffffff0);

    //ofp_group_types (1 << OFPGT_*)
    BITMAP_PART("ofp_group_type.OFPGT_ALL", "Support all group", 32, (1 << OFPGT_ALL));
    BITMAP_PART("ofp_group_type.OFPGT_SELECT", "Support select group", 32, (1 << OFPGT_SELECT));
    BITMAP_PART("ofp_group_type.OFPGT_INDIRECT", "Support indirect group", 32, (1 << OFPGT_INDIRECT));
    BITMAP_PART("ofp_group_type.OFPGT_FF", "Support fast failover group", 32, (1 << OFPGT_FF));
    BITMAP_PART("ofp_group_type.RESERVED", "Reserved", 32, 0xfffffff0);

    //ofp_flow_match_fields(1 << OFPXMT_*)
    /* 64bit part1 */
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IN_PORT", "(Low-32bit) Support switch input port", 32, (1 << OFPXMT_OFB_IN_PORT));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IN_PHY_PORT", "(Low-32bit) Support switch physical input port", 32, (1 << OFPXMT_OFB_IN_PHY_PORT));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_METADATA", "(Low-32bit) Support metadata passed between tables", 32, (1 << OFPXMT_OFB_METADATA));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ETH_DST", "(Low-32bit) Support ethernet destination address", 32, (1 << OFPXMT_OFB_ETH_DST));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ETH_SRC", "(Low-32bit) Support ethernet source address", 32, (1 << OFPXMT_OFB_ETH_SRC));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ETH_TYPE", "(Low-32bit) Support ethernet frame type", 32, (1 << OFPXMT_OFB_ETH_TYPE));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_VLAN_VID", "(Low-32bit) Support VLAN id", 32, (1 << OFPXMT_OFB_VLAN_VID));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_VLAN_PCP", "(Low-32bit) Support VLAN priority", 32, (1 << OFPXMT_OFB_VLAN_PCP));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IP_DSCP", "(Low-32bit) Support IP DSCP (6 bits in ToS field)", 32, (1 << OFPXMT_OFB_IP_DSCP));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IP_ECN", "(Low-32bit) Support IP ECN (2 bits in ToS field)", 32, (1 << OFPXMT_OFB_IP_ECN));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IP_PROTO", "(Low-32bit) Support IP protocol", 32, (1 << OFPXMT_OFB_IP_PROTO));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV4_SRC", "(Low-32bit) Support IPv4 source address", 32, (1 << OFPXMT_OFB_IPV4_SRC));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV4_DST", "(Low-32bit) Support IPv4 destination address", 32, (1 << OFPXMT_OFB_IPV4_DST));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_TCP_SRC", "(Low-32bit) Support TCP source port", 32, (1 << OFPXMT_OFB_TCP_SRC));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_TCP_DST", "(Low-32bit) Support TCP destination port", 32, (1 << OFPXMT_OFB_TCP_DST));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_UDP_SRC", "(Low-32bit) Support UDP source port", 32, (1 << OFPXMT_OFB_UDP_SRC));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_UDP_DST", "(Low-32bit) Support UDP destination port", 32, (1 << OFPXMT_OFB_UDP_DST));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_SCTP_SRC", "(Low-32bit) Support SCTP source port", 32, (1 << OFPXMT_OFB_SCTP_SRC));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_SCTP_DST", "(Low-32bit) Support SCTP destination port", 32, (1 << OFPXMT_OFB_SCTP_DST));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ICMPV4_TYPE", "(Low-32bit) Support ICMP type", 32, (1 << OFPXMT_OFB_ICMPV4_TYPE));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ICMPV4_CODE", "(Low-32bit) Support ICMP code", 32, (1 << OFPXMT_OFB_ICMPV4_CODE));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ARP_OP", "(Low-32bit) Support ARP opcode", 32, (1 << OFPXMT_OFB_ARP_OP));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ARP_SPA", "(Low-32bit) Support ARP source IPv4 address", 32, (1 << OFPXMT_OFB_ARP_SPA));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ARP_TPA", "(Low-32bit) Support ARP target IPv4 address", 32, (1 << OFPXMT_OFB_ARP_TPA));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ARP_SHA", "(Low-32bit) Support ARP source hardware address", 32, (1 << OFPXMT_OFB_ARP_SHA));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ARP_THA", "(Low-32bit) Support ARP target hardware address", 32, (1 << OFPXMT_OFB_ARP_THA));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV6_SRC", "(Low-32bit) Support IPv6 source address", 32, (1 << OFPXMT_OFB_IPV6_SRC));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV6_DST", "(Low-32bit) Support IPv6 destination address", 32, (1 << OFPXMT_OFB_IPV6_DST));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV6_FLABEL", "(Low-32bit) Support IPv6 Flow Label", 32, (1 << OFPXMT_OFB_IPV6_FLABEL));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ICMPV6_TYPE", "(Low-32bit) Support ICMPv6 type", 32, (1 << OFPXMT_OFB_ICMPV6_TYPE));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_ICMPV6_CODE", "(Low-32bit) Support ICMPv6 code", 32, (1 << OFPXMT_OFB_ICMPV6_CODE));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV6_ND_TARGET", "(Low-32bit) Support target address for ND", 32, (1 << OFPXMT_OFB_IPV6_ND_TARGET));
    /* 64bit part2 */
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV6_ND_SLL", "(High-32bit) Support source link-layer for ND", 32, (1 << (OFPXMT_OFB_IPV6_ND_SLL - 32)));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_IPV6_ND_TLL", "(High-32bit) Support target link-layer for ND", 32, (1 << (OFPXMT_OFB_IPV6_ND_TLL - 32)));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_MPLS_LABEL", "(High-32bit) Support MPLS label", 32, (1 << (OFPXMT_OFB_MPLS_LABEL - 32)));
    BITMAP_PART("ofp_flow_match_fields.OFPXMT_OFB_MPLS_TC", "(High-32bit) Support MPLS TC", 32, (1 << (OFPXMT_OFB_MPLS_TC - 32)));

    //ofp_action_type_bmp(1 << OFPAT_*)
    BITMAP_PART("ofp_action_type_bmp.OFPAT_OUTPUT", "Support output to switch port", 32, (1 << OFPAT_OUTPUT));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_COPY_TTL_OUT", "Support copy TTL \"outwards\"", 32, (1 << OFPAT_COPY_TTL_OUT));
    BITMAP_PART("ofp_action_type_bmp.OFPAT_COPY_TTL_IN", "Support copy TTL \"inwards\"", 32, (1 << OFPAT_COPY_TTL_IN));
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
    BITMAP_PART("ofp_action_type_bmp.OFPAT_SET_FIELD", "Support set a header field using OXM TLV format", 32, (1 << OFPAT_SET_FIELD));
    //BITMAP_PART("ofp_action_type_bmp.OFPAT_EXPERIMENTER", "Experimenter", 32, (1 << OFPAT_EXPERIMENTER));

    //ofp_instruction_type_bmp(1 << OFPIT_*)
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_GOTO_TABLE", "Support setup the next table in the lookup pipeline", 32, (1 << OFPIT_GOTO_TABLE));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_WRITE_METADATA", "Support setup the metadata field for use later in pipeline", 32, (1 << OFPIT_WRITE_METADATA));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_WRITE_ACTIONS", "Support write the action(s) onto the datapath action set", 32, (1 << OFPIT_WRITE_ACTIONS));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_APPLY_ACTIONS", "Support applies the action(s) immediately", 32, (1 << OFPIT_APPLY_ACTIONS));
    BITMAP_PART("ofp_instruction_type_bmp.OFPIT_CLEAR_ACTIONS", "Support clears all actions from the datapath action set", 32, (1 << OFPIT_CLEAR_ACTIONS));

    //ofp_table_config(OFPTC_*)
    FIELD("ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", "Send to controller", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
//    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_CONTROLLER", "Send to controller", 32, 0xffffffff);
    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_CONTINUE", "Continue to the next table in the pipeline", 32, (OFPTC_TABLE_MISS_CONTINUE));
    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_DROP", "Drop the packet", 32, (OFPTC_TABLE_MISS_DROP));
//    BITMAP_PART("ofp_table_config.OFPTC_TABLE_MISS_MASK", "Table miss mask", 32, (OFPTC_TABLE_MISS_MASK));
    BITMAP_PART("ofp_table_config.RESERVED", "Reserved", 32, 0xFFFFFFFC);
}

}
