/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2013 LittleField
 *   -- add and complete it
 */

#ifndef HDR_OPENFLOW_100_HPP
#define HDR_OPENFLOW_100_HPP

#define OFP_100_NS  openflow_100

#include <string.h>
#include <openflow-common.hpp>
#include <util/FieldManager.hpp>

namespace openflow_100
{
  static const guint16  gVersion = 0x01;

  // Importing from epan/tfs.h wreaks havoc
  const true_false_string tfs_set_notset = {"Yes(1)", "No(0)"};
  //const true_false_string tfs_wildcard = {"NoMatch(1)", "Match(0)"};

  /** wildcard or not for bitfields field */
  static const value_string ts_wildcard_choice[] = {
      { 0, "Match"  },
      { 1, "Allow" },
      { 0, NULL  }
  };

  /** Address masks */
  static const value_string addr_mask[] = {
      { 0, "/32"  },
      { 1, "/31" },
      { 2, "/30" },
      { 3, "/29" },
      { 4, "/28" },
      { 5, "/27" },
      { 6, "/26" },
      { 7, "/25" },
      { 8, "/24" },
      { 9, "/23" },
      { 10, "/22" },
      { 11, "/21" },
      { 12, "/20" },
      { 13, "/19" },
      { 14, "/18" },
      { 15, "/17" },
      { 16, "/16" },
      { 17, "/15" },
      { 18, "/14" },
      { 19, "/13" },
      { 20, "/12" },
      { 21, "/11" },
      { 22, "/10" },
      { 23, "/9" },
      { 24, "/8" },
      { 25, "/7" },
      { 26, "/6" },
      { 27, "/5" },
      { 28, "/4" },
      { 29, "/3" },
      { 30, "/2" },
      { 31, "/1" },
      { 32, "/0" },
      { 63, "/0" },
      { 0, NULL  }
  };

  class DLLEXPORT DissectorContext {
  public:
    static DissectorContext *getInstance (int);
    static guint getMessageLen(packet_info *, tvbuff_t *, int);
    void setHandles(dissector_handle_t, dissector_handle_t);
    void dissect(tvbuff_t *, packet_info *, proto_tree *);
    static void prepDissect(tvbuff_t *, packet_info *, proto_tree *);

  private:
    DissectorContext (int);

    void setupCodes(void);
    void setupFlags(void);
    void setupFields(void);

    //void dispatchMessage(tvbuff_t *, packet_info *, proto_tree *);
    void dispatchMessage(tvbuff_t *, packet_info *, proto_tree *);
    void dissect_ofp_error();
    void dissect_ofp_echo();
    void dissect_ofp_vendor();
    void dissect_ofp_features_request();
    void dissect_ofp_switch_features();
    void dissect_ofp_set_config(void);

    void dissect_ofp_flow_stats_request(proto_tree *);
    void dissect_ofp_flow_stats(proto_tree *);
    void dissect_ofp_aggregate_stats_request(proto_tree *);
    void dissect_ofp_aggregate_stats(proto_tree *);
    void dissect_ofp_port_stats_request(proto_tree *);
    void dissect_ofp_port_stats(proto_tree *);
    void dissect_ofp_queue_stats_request(proto_tree *);
    void dissect_ofp_queue_stats(proto_tree *);
    void dissect_ofp_vendor_stats_vendor(proto_tree *);
    void dissect_ofp_table_stats(proto_tree *);
    void dissect_ofp_desc_stats(proto_tree *);

    void dissect_ofp_stats_request();
    void dissect_ofp_stats_reply();

    void dissect_ofp_port_status();
    void dissect_ofp_wildcards(proto_tree *, guint32);
    void dissect_ofp_flow_mod();
    void dissect_ofp_flow_remove();
    void dissect_ofp_port_mod();
    void dissect_ofp_match(proto_tree *);
    void dissect_ofp_port(proto_tree *);
    void dissect_ofppf(proto_tree*);
    void dissect_ofp_action(proto_tree *);
    void dissect_ofp_packet_in();
    void dissect_ofp_packet_out();

    void dissect_ofp_queue_prop(proto_tree *parent);
    void dissect_ofp_packet_queue(proto_tree *parent);
    void dissect_ofp_queue_get_config_request(void);
    void dissect_ofp_queue_get_config_reply(void);

    void add_child_ofp_port_no(proto_tree* tree, const char *field, guint16 portid, guint32 len);
    void add_child_ofp_table(proto_tree* tree, const char *field, guint8 tableid, guint32 len);
    void add_child_ofp_queue_id(proto_tree* tree, const char *field, guint32 queueid, guint32 len);
    void add_child_ofp_vlanid(proto_tree* tree, const char *field, guint16 vlanid, guint32 len);

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
    GArray* ofp_flow_wildcards;
    GArray* ofp_action_type;
    GArray* ofp_flow_mod_command;
    GArray* ofp_stats_types;
    GArray* ofp_packet_in_reason;
    GArray* ofp_flow_removed_reason;
    GArray* ofp_port_reason;
    GArray* ofp_error_type;
    GArray* ofp_hello_failed_code;
    GArray* ofp_bad_request_code;
    GArray* ofp_bad_action_code;
    GArray* ofp_flow_mod_failed_code;
    GArray* ofp_port_mod_failed_code;
    GArray* ofp_queue_op_failed_code;
    GArray* ofp_queue_property;

    //GArray* ofp_table_id;
    //GArray* ofp_config_flags;
    //GArray* addr_mask;
    GArray* port_state;
  };

  extern DissectorContext *Context;
  void init (int);
}

#endif // Header guard
