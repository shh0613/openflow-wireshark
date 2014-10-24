/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2012 Barnstormer Softworks Ltd.
 * Copyright (c) 2012 CPqD
 * Copyright (c) 2013 LittleField
 *   -- complete it
 */

#ifndef HDR_OPENFLOW_120_HPP
#define HDR_OPENFLOW_120_HPP

#define OFP_120_NS openflow_120

#include <string.h>
#include <openflow-common.hpp>
#include <util/FieldManager.hpp>

// Wireshark isn't a C++ application, so don't try
// to initialize C++ objects before main()

namespace openflow_120 {
    static const guint16 gVersion = 0x03;
    
    // Importing from epan/tfs.h wreaks havoc
    const true_false_string tfs_set_notset = {"Yes(1)", "No(0)"};
    //const true_false_string tfs_wildcard = {"NoMatch(1)", "Match(0)"};

    class DLLEXPORT DissectorContext {
    public:
        static DissectorContext* getInstance(int);
        void setHandles(dissector_handle_t, dissector_handle_t);
        static void prepDissect(tvbuff_t *, packet_info *, proto_tree *);
        void dissect(tvbuff_t *, packet_info *, proto_tree *);
        static guint getMessageLen(packet_info *, tvbuff_t *, int);
        
    private:
        DissectorContext(int);

        void setupCodes(void);
        void setupFlags(void);
        void setupFields(void);
        
        void dispatchMessage(tvbuff_t *, packet_info *, proto_tree *);
        void dissect_ofp_error(void);
        void dissect_ofp_echo(void);
        void dissect_ofp_features_request(void);
        void dissect_ofp_switch_features(void);
        void dissect_ofp_switch_config(void);
        void dissect_stats_request(void);
        void dissect_stats_reply(void);
        void dissect_ofp_port_status(void);
        void dissect_ofp_flow_mod(void);
        void dissect_ofp_table_mod(void);
        void dissect_ofp_group_mod(void);
        void dissect_ofp_port_mod(void);

        void dissect_ofp_flow_stats_request(proto_tree* parent);
        void dissect_ofp_flow_stats(proto_tree *tree);
        void dissect_ofp_aggregate_stats_request(proto_tree* parent);
        void dissect_ofp_aggregate_stats(proto_tree* parent);
        void dissect_ofp_port_stats_request(proto_tree* parent);
        void dissect_ofp_port_stats(proto_tree* parent);
        void dissect_ofp_queue_stats_request(proto_tree* parent);
        void dissect_ofp_queue_stats(proto_tree* parent);
        void dissect_ofp_group_stats_request(proto_tree* parent);
        void dissect_ofp_group_stats(proto_tree* parent);
        void dissect_ofp_desc_stats(proto_tree *parent);
        void dissect_ofp_table_stats(proto_tree *parent);
        void dissect_ofp_group_desc(proto_tree* parent);
        void dissect_ofp_group_features(proto_tree* parent);
        void dissect_ofp_stats_experimenter(proto_tree* parent);

        void dissect_ofp_match(proto_tree *);
        void dissect_ofp_port(proto_tree *);
        void dissect_ofppf(proto_tree*);
        void dissect_ofp_instruction(proto_tree *);
        void dissect_ofp_action(proto_tree *);
        void dissect_ofp_group_bucket(proto_tree *);

        void dissect_ofp_oxm(proto_tree *, guint32 length);
        int dissect_ofp_oxm_field(proto_tree*);
        void dissect_ofp_packet_in(void);
        void dissect_ofp_packet_out(void);
        void dissect_ofp_role_request(void);
        void dissect_ofp_role_reply(void);
        
        void dissect_ofp_queue_prop(proto_tree *parent);
        void dissect_ofp_packet_queue(proto_tree *parent);
        void dissect_ofp_queue_get_config_request(void);
        void dissect_ofp_queue_get_config_reply(void);

        void add_child_ofp_group(proto_tree* tree, const char *field, guint32 groupid, guint32 len);
        void add_child_ofp_table(proto_tree* tree, const char *field, guint8 tableid, guint32 len);
        void add_child_ofp_vlanid(proto_tree* tree, const char *field, guint16 vlanid, guint32 len);
        void add_child_ofp_port_no(proto_tree* tree, const char *field, guint32 portid, guint32 len);
        void add_child_ofp_queue_id(proto_tree* tree, const char *field, guint32 queueid, guint32 len);

        void dissect_ofp_flow_match_field(proto_tree *mt, guint64 match);
        void dissect_ofp_action_type_bmp(proto_tree *mt, guint32 actbmp);
        void dissect_ofp_instruction_type_bmp(proto_tree *mt, guint32 instbmp);

        dissector_handle_t mDataHandle;
        dissector_handle_t mOpenflowHandle;
        int mProtoOpenflow;
        FieldManager mFM;

        // Temporary context for dissection
        tvbuff_t *_tvb;
        packet_info *_pinfo;
        proto_tree *_tree;
        dissector_handle_t _ether_handle;
        guint32 _offset;
        guint32 _rawLen;
        guint16 _oflen;
        proto_tree *_curOFPSubtree;
        static DissectorContext *mSingle;

        // Generated code
        GArray* ofp_type;
        //GArray* ofp_port_no;
        GArray* ofp_queue_properties;
        GArray* ofp_match_type;
        GArray* ofp_oxm_class;
        GArray* oxm_ofb_match_fields;
        //GArray* ofp_vlan_id;
        GArray* ofp_instruction_type;
        GArray* ofp_action_type;
        GArray* ofp_controller_max_len;
        //GArray* ofp_table;
        GArray* ofp_flow_mod_command;
        //GArray* ofp_group;
        GArray* ofp_group_mod_command;
        GArray* ofp_group_type;
        GArray* ofp_stats_types;
        GArray* ofp_controller_role;
        GArray* ofp_packet_in_reason;
        GArray* ofp_flow_removed_reason;
        GArray* ofp_port_reason;
        GArray* ofp_error_type;
        GArray* ofp_hello_failed_code;
        GArray* ofp_bad_request_code;
        GArray* ofp_bad_action_code;
        GArray* ofp_bad_instruction_code;
        GArray* ofp_bad_match_code;
        GArray* ofp_flow_mod_failed_code;
        GArray* ofp_group_mod_failed_code;
        GArray* ofp_port_mod_failed_code;
        GArray* ofp_table_mod_failed_code;
        GArray* ofp_queue_op_failed_code;
        GArray* ofp_switch_config_failed_code;
        GArray* ofp_role_request_failed_code;
        GArray* ofp_queue_property;
    };

    void init(int);
    extern DissectorContext * Context;
}

#endif // Header guard
