/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2013 LittleField
 *   -- modify to support more wireshark version
 */

#ifndef HDR_FIELD_TYPE_HPP
#define HDR_FIELD_TYPE_HPP

#if defined(__cplusplus)
extern "C" {
    #endif

    #include <epan/dissectors/packet-tcp.h>
    #include <epan/value_string.h>
    #include <epan/tfs.h>

    #if defined(__cplusplus)
}
#endif

// Exceptions
class ZeroLenInstruction { };
class ZeroLenAction { };
class ZeroLenBucket { };

/* Fill an oxm_header */
#define OXM_HEADER(class, field, hasmask, length) \
    ((class << 16) | (field << 9) | (hasmask << 8) | (length/8))
/* Get the padding needed for some structs */
#define OFP_MATCH_OXM_PADDING(length) \
    ((length + 7)/8*8 - length)
#define OFP_ACTION_SET_FIELD_OXM_PADDING(oxm_len) \
    (((oxm_len + 4) + 7)/8*8 - (oxm_len + 4))
/* Extract fields from an oxm_header */
#define UNPACK_OXM_VENDOR(header) (header >> 16)
#define UNPACK_OXM_FIELD(header) ((header >> 9) & 0x0000007F)
#define UNPACK_OXM_HASMASK(header) ((header >> 8) & 0x00000001)
#define UNPACK_OXM_LENGTH(header) (header & 0x000000FF)

/* WARNING: Yep, macros can be evil when used this way, but they are here
 * because they simplified the development in this case. In the future, we will
 * try to get rid of them through a different API in FieldManager and new
 * functions and methods.
 */

/* Create a type array, used to map codes to values */
#define TYPE_ARRAY(name) this->name = g_array_new(FALSE, FALSE, sizeof (value_string))
/* Maps a value code to a string value */
#define TYPE_ARRAY_ADD(array, value, str) addValueString(this->array, value, str)

/* Create a tree structure for a given field in variable name */
#define ADD_TREE(name, field) \
        proto_tree* name = this->mFM.addSubtree(this->_curOFPSubtree, field, this->_tvb, this->_offset, this->_oflen - this->_offset)

/* Create a subtree structure with a given parent and length in a variable name */
#define ADD_SUBTREE(name, parent, field, length) \
        proto_tree* name = this->mFM.addSubtree(parent, field, this->_tvb, this->_offset, length)

/* Read values in network order */
#define READ_UINT8(name) \
    guint8 name = tvb_get_guint8(this->_tvb, this->_offset);
#define READ_UINT16(name) \
    guint16 name = tvb_get_ntohs(this->_tvb, this->_offset)
#define READ_UINT32(name) \
    guint32 name = tvb_get_ntohl(this->_tvb, this->_offset)
#define READ_UINT64(name) \
    guint64 name = tvb_get_ntoh64(this->_tvb, this->_offset)

/* Adds fields to a tree */
#define ADD_BOOLEAN(tree, field, length, bitmap) \
    this->mFM.addBoolean(tree, field, this->_tvb, this->_offset, length, bitmap)
#define ADD_UINT(tree, field, length, value) \
    this->mFM.addUint(tree, field, this->_tvb, this->_offset, length, value)
#define ADD_CHILD(tree, field, length) \
    this->mFM.addItem(tree, field, this->_tvb, this->_offset, length); this->_offset += length
#define ADD_CHILD_CONST(tree, field, length) \
    this->mFM.addItem(tree, field, this->_tvb, this->_offset, length);
#define ADD_CHILD_STR(tree, field, length, str) \
    this->mFM.addString(tree, field, this->_tvb, this->_offset, length, str); this->_offset += length
#define ADD_DISSECTOR(tree, field, length)  \
    this->mFM.addDissector(tree, field, this->_tvb, this->_pinfo, this->_ether_handle, this->_offset, length); this->_offset += length
#define ADD_OFDISSECTOR(tree, field, length)  \
    this->mFM.addDissector(tree, field, this->_tvb, this->_pinfo, this->mOpenflowHandle, this->_offset, length); this->_offset += length
#define CONSUME_BYTES(length) \
    this->_offset += length

/*  Values based on type arrays and masks */
#define VALUES(array) (void *) VALS(this->array->data)
#define NO_VALUES NULL
#define NO_MASK 0x0
/* A tree field contains one or more children fields */
#define TREE_FIELD(key, desc) \
    this->mFM.createField(key, desc, FT_NONE, BASE_NONE, NO_VALUES, NO_MASK, true)
#define FIELD(key, desc, type, base, values, mask) \
    this->mFM.createField(key, desc, type, base, values, mask, false)
/* A bitmap field is a tree containing several bitmap parts */
#define BITMAP_FIELD(field, desc, type) \
    this->mFM.createField(field, desc, type, BASE_HEX, NO_VALUES, NO_MASK, true)
#define BITMAP_PART(field, desc, length, mask) \
    this->mFM.createField(field, desc, FT_BOOLEAN, length, TFS(&tfs_set_notset), mask, false)
#define BITMAP_WILDCARD_PART(field, desc, base, values, mask) \
    this->mFM.createField(field, desc, FT_UINT32, base, values, mask, false)

#define SHOW_ERROR(where, msg) expert_add_info_format(this->_pinfo, where, PI_MALFORMED, PI_ERROR, msg)

#endif /* HDR_FIELD_TYPE_HPP */
