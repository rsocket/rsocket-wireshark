/* packet-rsocket.c
 *
 * Routines for RSocket packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "config.h"

#include <epan/dissectors/packet-tcp.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#define RSOCKET_TCP_PORT 9898  /* Not IANA registered */
#define RSOCKET_WEBSOCKET_PORT 9897  /* Not IANA registered */

void proto_reg_handoff_rsocket(void);

static int proto_rsocket = -1;

static int hf_rsocket_frame_len = -1;
static int hf_rsocket_stream_id = -1;
static int hf_rsocket_frame_type = -1;
static int hf_rsocket_mdata_len = -1;
static int hf_rsocket_mdata = -1;
static int hf_rsocket_data = -1;
static int hf_rsocket_major_version = -1;
static int hf_rsocket_minor_version = -1;
static int hf_rsocket_keepalive_interval = -1;
static int hf_rsocket_max_lifetime = -1;
static int hf_rsocket_mdata_mime_length = -1;
static int hf_rsocket_mdata_mime_type = -1;
static int hf_rsocket_data_mime_length = -1;
static int hf_rsocket_data_mime_type = -1;
static int hf_rsocket_req_n = -1;
static int hf_rsocket_error_code = -1;
static int hf_rsocket_keepalive_last_rcvd_pos = -1;
static int hf_rsocket_resume_token_len = -1;
static int hf_rsocket_resume_token = -1;

// other flags
static int hf_rsocket_ignore_flag = -1;
static int hf_rsocket_metadata_flag = -1;
static int hf_rsocket_resume_flag = -1;
static int hf_rsocket_lease_flag = -1;
static int hf_rsocket_follows_flag = -1;
static int hf_rsocket_complete_flag = -1;
static int hf_rsocket_next_flag = -1;
static int hf_rsocket_respond_flag = -1;

static gint ett_rsocket = -1;
static gint ett_rframe = -1;

static gint frame_len_field_size = 3;

static expert_field ei_rsocket_frame_len_mismatch = EI_INIT;

static guint prefs_rsocket_tcp_port = RSOCKET_TCP_PORT;
static guint prefs_rsocket_websocket_port = RSOCKET_WEBSOCKET_PORT;

static const value_string frameTypeNames[] = {{0x00, "RESERVED"},
                                              {0x01, "SETUP"},
                                              {0x02, "LEASE"},
                                              {0x03, "KEEPALIVE"},
                                              {0x04, "REQUEST_RESPONSE"},
                                              {0x05, "REQUEST_FNF"},
                                              {0x06, "REQUEST_STREAM"},
                                              {0x07, "REQUEST_CHANNEL"},
                                              {0x08, "REQUEST_N"},
                                              {0x09, "CANCEL"},
                                              {0x0A, "PAYLOAD"},
                                              {0x0B, "ERROR"},
                                              {0x0C, "METADATA_PUSH"},
                                              {0x0D, "RESUME"},
                                              {0x0E, "RESUME_OK"},
                                              {0x3F, "SETUP"}};

static const value_string errorCodeNames[] = {
    {0x00000000, "RESERVED"},          {0x00000001, "INVALID_SETUP"},
    {0x00000002, "UNSUPPORTED_SETUP"}, {0x00000003, "REJECTED_SETUP"},
    {0x00000004, "REJECTED_RESUME"},   {0x00000101, "CONNECTION_ERROR"},
    {0x00000102, "CONNECTION_CLOSE"},  {0x00000201, "APPLICATION_ERROR"},
    {0x00000202, "REJECTED"},          {0x00000203, "CANCELED"},
    {0x00000204, "INVALID"},           {0xFFFFFFFF, "REJECTED"}};

static const gchar *getFrameTypeName(const guint64 frame_type) {
  for (unsigned long i = 0; i < sizeof(frameTypeNames) / sizeof(value_string);
       i++) {
    if (frameTypeNames[i].value == frame_type) {
      return frameTypeNames[i].strptr;
    }
  }
  return NULL;
}

static gint read_rsocket_setup_frame(proto_tree *tree, tvbuff_t *tvb,
                                     gint offset) {

  gint8 resume_flag = tvb_get_bits8(tvb, (offset + 1) * 8, 1);
  proto_tree_add_item(tree, hf_rsocket_resume_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_rsocket_lease_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_rsocket_major_version, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_rsocket_minor_version, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_rsocket_keepalive_interval, tvb, offset, 4,
                      ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_rsocket_max_lifetime, tvb, offset, 4,
                      ENC_BIG_ENDIAN);
  offset += 4;

  if (resume_flag) {
    guint resume_token_len;
    proto_tree_add_item_ret_uint(tree, hf_rsocket_resume_token_len, tvb, offset,
                                 2, ENC_BIG_ENDIAN, &resume_token_len);
    offset += 2;
    proto_tree_add_item(tree, hf_rsocket_resume_token, tvb, offset,
                        resume_token_len, ENC_STRING);
    offset += resume_token_len;
  }

  guint mdata_mime_length;
  proto_tree_add_item_ret_uint(tree, hf_rsocket_mdata_mime_length, tvb, offset,
                               1, ENC_BIG_ENDIAN, &mdata_mime_length);
  offset += 1;
  proto_tree_add_item(tree, hf_rsocket_mdata_mime_type, tvb, offset,
                      mdata_mime_length, ENC_BIG_ENDIAN);
  offset += mdata_mime_length;

  guint data_mime_length;
  proto_tree_add_item_ret_uint(tree, hf_rsocket_data_mime_length, tvb, offset,
                               1, ENC_BIG_ENDIAN, &data_mime_length);
  offset += 1;
  proto_tree_add_item(tree, hf_rsocket_data_mime_type, tvb, offset,
                      data_mime_length, ENC_BIG_ENDIAN);
  offset += data_mime_length;

  return offset;
}

static gint read_rsocket_keepalive_frame(proto_tree *tree, tvbuff_t *tvb,
                                         gint offset) {

  proto_tree_add_item(tree, hf_rsocket_respond_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_rsocket_keepalive_last_rcvd_pos, tvb, offset, 8,
                      ENC_BIG_ENDIAN);
  offset += 8;

  return offset;
}

static gint read_rsocket_req_resp_frame(proto_tree *tree, tvbuff_t *tvb,
                                        gint offset) {

  proto_tree_add_item(tree, hf_rsocket_follows_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;
  return offset;
}

static gint read_rsocket_fnf_frame(proto_tree *tree, tvbuff_t *tvb,
                                   gint offset) {

  proto_tree_add_item(tree, hf_rsocket_follows_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;
  return offset;
}

static gint read_rsocket_req_stream_frame(packet_info *pinfo, proto_tree *tree,
                                          tvbuff_t *tvb, gint offset) {

  proto_tree_add_item(tree, hf_rsocket_follows_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  guint32 req_n = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, " InitialRequestN=%d", req_n);

  proto_tree_add_item(tree, hf_rsocket_req_n, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  return offset;
}

static gint read_rsocket_req_channel_frame(proto_tree *tree, tvbuff_t *tvb,
                                           gint offset) {

  proto_tree_add_item(tree, hf_rsocket_follows_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_rsocket_complete_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_rsocket_req_n, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  return offset;
}

static gint read_rsocket_req_n_frame(packet_info *pinfo, proto_tree *tree,
                                     tvbuff_t *tvb, gint offset) {
  // no special flags
  offset += 2;

  guint32 req_n = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, " N=%d", req_n);

  proto_tree_add_item(tree, hf_rsocket_req_n, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  return offset;
}

static gint read_rsocket_cancel_frame(gint offset) {
  // no special flags
  offset += 2;
  // no other content
  return offset;
}

static gint read_rsocket_payload_frame(proto_tree *tree, tvbuff_t *tvb,
                                       gint offset) {

  proto_tree_add_item(tree, hf_rsocket_follows_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_rsocket_complete_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_rsocket_next_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);

  offset += 2;
  return offset;
}

static gint read_rsocket_error_frame(proto_tree *tree, tvbuff_t *tvb,
                                     gint offset) {
  // no special flags
  offset += 2;
  proto_tree_add_item(tree, hf_rsocket_error_code, tvb, offset, 4,
                      ENC_BIG_ENDIAN);
  offset += 4;
  return offset;
}

static int dissect_rsocket(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, gint frame_length_field_size);

static int frame_length_field_dissector(tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, void *data _U_) {
    return dissect_rsocket(tvb, pinfo, tree, frame_len_field_size);
}

static int no_frame_length_field_dissector(tvbuff_t *tvb, packet_info *pinfo,
                                           proto_tree *tree, void *data _U_) {
    return dissect_rsocket(tvb, pinfo, tree, 0);
}

static int dissect_rsocket(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, gint frame_length_field_size) {

  col_clear(pinfo->cinfo, COL_INFO);
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSOCKET");

  gint offset = 0;
  proto_item *ti =
      proto_tree_add_item(tree, proto_rsocket, tvb, offset, -1, ENC_NA);
  proto_tree *rsocket_tree = proto_item_add_subtree(ti, ett_rsocket);

  guint32 frame_len;

  if(frame_length_field_size > 0) {
    proto_tree_add_item_ret_uint(rsocket_tree, hf_rsocket_frame_len, tvb, offset,
                                 frame_length_field_size, ENC_BIG_ENDIAN,
                                 &frame_len);
    offset += frame_length_field_size;
  } else {
    frame_len = tvb_captured_length(tvb);
  }

  proto_item *rframe;
  proto_tree *rframe_tree = proto_tree_add_subtree(
      rsocket_tree, tvb, offset, frame_len, ett_rframe, &rframe, "Frame");

  proto_tree_add_item(rframe_tree, hf_rsocket_stream_id, tvb, offset, 4,
                      ENC_BIG_ENDIAN);
  offset += 4;

  // Read Frame Type and Ignore/Metadata Flags (8 bits)
  guint64 frame_type;
  proto_tree_add_bits_ret_val(rframe_tree, hf_rsocket_frame_type, tvb,
                              offset * 8, 6, &frame_type, ENC_BIG_ENDIAN);

  proto_tree_add_item(rframe_tree, hf_rsocket_ignore_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);
  guint8 metadata_flag = tvb_get_bits8(tvb, (offset * 8) + 6, 2);
  proto_tree_add_item(rframe_tree, hf_rsocket_metadata_flag, tvb, offset, 2,
                      ENC_BIG_ENDIAN);

  const gchar *frameName = getFrameTypeName(frame_type);

  if (frameName) {
    col_add_str(pinfo->cinfo, COL_INFO, frameName);
  } else {
    col_add_str(pinfo->cinfo, COL_INFO, "UNDEFINED");
  }

  if (frame_type == 0x01) {
    offset = read_rsocket_setup_frame(rframe_tree, tvb, offset);
  } else if (frame_type == 0x03) {
    offset = read_rsocket_keepalive_frame(rframe_tree, tvb, offset);
  } else if (frame_type == 0x04) {
    offset = read_rsocket_req_resp_frame(rframe_tree, tvb, offset);
  } else if (frame_type == 0x05) {
    offset = read_rsocket_fnf_frame(rframe_tree, tvb, offset);
  } else if (frame_type == 0x06) {
    offset = read_rsocket_req_stream_frame(pinfo, rframe_tree, tvb, offset);
  } else if (frame_type == 0x07) {
    offset = read_rsocket_req_channel_frame(rframe_tree, tvb, offset);
  } else if (frame_type == 0x08) {
    offset = read_rsocket_req_n_frame(pinfo, rframe_tree, tvb, offset);
  } else if (frame_type == 0x09) {
    offset = read_rsocket_cancel_frame(offset);
  } else if (frame_type == 0x0A) {
    offset = read_rsocket_payload_frame(rframe_tree, tvb, offset);
  } else if (frame_type == 0x0B) {
    offset = read_rsocket_error_frame(rframe_tree, tvb, offset);
  }

  col_append_fstr(pinfo->cinfo, COL_INFO, " FrameLen=%d", frame_len);

  if (metadata_flag) {
    guint32 mdata_len;
    proto_tree_add_item_ret_uint(rframe_tree, hf_rsocket_mdata_len, tvb, offset,
                                 3, ENC_BIG_ENDIAN, &mdata_len);
    offset += 3;
    proto_tree_add_item(rframe_tree, hf_rsocket_mdata, tvb, offset, mdata_len,
                        ENC_BIG_ENDIAN);
    offset += mdata_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, " MetadataLen=%d", mdata_len);
  }

  guint32 data_len = frame_len + frame_length_field_size - offset;
  if (data_len > 0) {
    proto_tree_add_item(rframe_tree, hf_rsocket_data, tvb, offset, data_len,
                        ENC_BIG_ENDIAN);
    offset += data_len;
    col_append_fstr(pinfo->cinfo, COL_INFO, " DataLen=%d", data_len);
  }

  if ((guint32)offset != frame_len + frame_length_field_size) {
    expert_add_info_format(pinfo, tree, &ei_rsocket_frame_len_mismatch,
                           "Frame Length doesnt match");
  }

  return tvb_captured_length(tvb);
}

void proto_register_rsocket(void) {
  static hf_register_info hf[] = {
      {&hf_rsocket_frame_len,
       {"Frame Length", "rsocket.frame_len", FT_UINT24, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_rsocket_stream_id,
       {"Stream ID", "rsocket.stream_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      {&hf_rsocket_frame_type,
       {"Frame Type", "rsocket.frame_type", FT_UINT8, BASE_DEC,
        VALS(frameTypeNames), 0x0, NULL, HFILL}},
      {&hf_rsocket_mdata_len,
       {"Metadata Length", "rsocket.metadata_len", FT_UINT24, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_rsocket_mdata,
       {"Metadata", "rsocket.metadata", FT_STRING, STR_ASCII, NULL, 0x0, NULL,
        HFILL}},
      {&hf_rsocket_data,
       {"Data", "rsocket.data", FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL}},
      {&hf_rsocket_ignore_flag,
       {"Ignore", "rsocket.flags.ignore", FT_BOOLEAN, 16, NULL, 0x0200, NULL,
        HFILL}},
      {&hf_rsocket_metadata_flag,
       {"Metadata", "rsocket.flags.metadata", FT_BOOLEAN, 16, NULL, 0x0100,
        NULL, HFILL}},
      {&hf_rsocket_resume_flag,
       {"Resume", "rsocket.flags.resume", FT_BOOLEAN, 16, NULL, 0x0080, NULL,
        HFILL}},
      {&hf_rsocket_lease_flag,
       {"Lease", "rsocket.flags.lease", FT_BOOLEAN, 16, NULL, 0x0040, NULL,
        HFILL}},
      {&hf_rsocket_follows_flag,
       {"Follows", "rsocket.flags.follows", FT_BOOLEAN, 16, NULL, 0x0080, NULL,
        HFILL}},
      {&hf_rsocket_complete_flag,
       {"Complete", "rsocket.flags.complete", FT_BOOLEAN, 16, NULL, 0x0040,
        NULL, HFILL}},
      {&hf_rsocket_next_flag,
       {"Next", "rsocket.flags.next", FT_BOOLEAN, 16, NULL, 0x0020, NULL,
        HFILL}},
      {&hf_rsocket_respond_flag,
       {"Respond", "rsocket.flags.respond", FT_BOOLEAN, 16, NULL, 0x0080, NULL,
        HFILL}},
      {&hf_rsocket_major_version,
       {"Major Version", "rsocket.version.major", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_rsocket_minor_version,
       {"Minor Version", "rsocket.version.minor", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_rsocket_keepalive_interval,
       {"Keepalive Interval", "rsocket.keepalive.interval", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_rsocket_max_lifetime,
       {"Max Lifetime", "rsocket.max_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_rsocket_mdata_mime_length,
       {"Metadata MIME Length", "rsocket.mdata_mime_length", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_rsocket_mdata_mime_type,
       {"Metadata MIME Type", "rsocket.mdata_mime_type", FT_STRING, STR_ASCII,
        NULL, 0x0, NULL, HFILL}},
      {&hf_rsocket_data_mime_length,
       {"Data MIME Length", "rsocket.data_mime_length", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_rsocket_data_mime_type,
       {"Data MIME Type", "rsocket.data_mime_type", FT_STRING, STR_ASCII, NULL,
        0x0, NULL, HFILL}},
      {&hf_rsocket_req_n,
       {"Request N", "rsocket.request_n", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      {&hf_rsocket_error_code,
       {"Error Code", "rsocket.error_code", FT_UINT32, BASE_DEC,
        VALS(errorCodeNames), 0x0, NULL, HFILL}},
      {&hf_rsocket_keepalive_last_rcvd_pos,
       {"Keepalive Last Received Position",
        "rsocket.keepalive_last_received_position", FT_UINT64, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_rsocket_resume_token_len,
       {"Resume Token Length", "rsocket.resume.token.len", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_rsocket_resume_token,
       {"Resume Token", "rsocket.resume.token", FT_STRING, STR_ASCII, NULL, 0x0,
        NULL, HFILL}},
  };

  static gint *ett[] = {&ett_rsocket, &ett_rframe};

  proto_rsocket = proto_register_protocol("RSocket Protocol", /* name       */
                                          "RSocket",          /* short name */
                                          "rsocket"           /* abbrev     */
                                          );

  proto_register_field_array(proto_rsocket, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_module_t *expert_rsocket;
  expert_rsocket = expert_register_protocol(proto_rsocket);
  static ei_register_info ei[] = {
      {&ei_rsocket_frame_len_mismatch,
       {"rsocket.frame_len.mismatch", PI_MALFORMED, PI_ERROR,
        "Frame Length is wrong", EXPFILL}},
  };
  expert_register_field_array(expert_rsocket, ei, array_length(ei));

  //Register in preferences
   module_t *rsocket_module = prefs_register_protocol(proto_rsocket, proto_reg_handoff_rsocket);

   prefs_register_uint_preference(rsocket_module, "tcp.port",
                                   "TCP port", "Decode directly over TCP. Set to \"0\" to disable.", 10, &prefs_rsocket_tcp_port);

   prefs_register_uint_preference(rsocket_module, "ws.port",
                                   "Websocket port", "Decode as websocket over TCP. Set to \"0\" to disable.", 10, &prefs_rsocket_websocket_port);

   prefs_register_static_text_preference(rsocket_module,"warning.text","Warning: TCP and websocket port must be different.","" );
}

void proto_reg_handoff_rsocket(void) {

    static gboolean prefs_initialized = FALSE;
    static dissector_handle_t rsocket_handle, websocket_handle;
    static guint current_tcp_port, current_websocket_port;

    rsocket_handle = create_dissector_handle(frame_length_field_dissector, proto_rsocket);
    websocket_handle = create_dissector_handle(no_frame_length_field_dissector, proto_rsocket);

    if (!prefs_initialized) {
        dissector_add_uint("tcp.port", RSOCKET_TCP_PORT, rsocket_handle);
        dissector_add_uint("ws.port", RSOCKET_WEBSOCKET_PORT, websocket_handle);
        prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("tcp.port", current_tcp_port, rsocket_handle);
        dissector_delete_uint("ws.port", current_websocket_port, websocket_handle);
    }
    if(RSOCKET_TCP_PORT!=0) {
        dissector_add_uint("tcp.port", prefs_rsocket_tcp_port, rsocket_handle);
    }
    if(RSOCKET_WEBSOCKET_PORT!=0) {
        dissector_add_uint("ws.port", prefs_rsocket_websocket_port, websocket_handle);
    }

    current_tcp_port =  prefs_rsocket_tcp_port;
    current_websocket_port = prefs_rsocket_websocket_port;
}
