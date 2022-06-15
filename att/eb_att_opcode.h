#ifndef __EB_ATT_OPCODE_H__
#define __EB_ATT_OPCODE_H__

#include <stdint.h>
#include "eb_compile.h"

enum att_opcode {
    ATT_ERROR_RSP                  =  0x01,
    ATT_EXCHANGE_MTU_REQ           =  0x02,
    ATT_EXCHANGE_MTU_RSP           =  0x03,
    ATT_FIND_INFORMATION_REQ       =  0x04,
    ATT_FIND_INFORMATION_RSP       =  0x05,
    ATT_FIND_BY_TYPE_VALUE_REQ     =  0x06,
    ATT_FIND_BY_TYPE_VALUE_RSP     =  0x07,
    ATT_READ_BY_TYPE_REQ           =  0x08,
    ATT_READ_BY_TYPE_RSP           =  0x09,
    ATT_READ_REQ                   =  0x0A,
    ATT_READ_RSP                   =  0x0B,
    ATT_READ_BLOB_REQ              =  0x0C,
    ATT_READ_BLOB_RSP              =  0x0D,
    ATT_READ_MULTIPLE_REQ          =  0x0E,
    ATT_READ_MULTIPLE_RSP          =  0x0F,
    ATT_READ_BY_GROUP_TYPE_REQ     =  0x10,
    ATT_READ_BY_GROUP_TYPE_RSP     =  0x11,
    ATT_WRITE_REQ                  =  0x12,
    ATT_WRITE_RSP                  =  0x13,
    ATT_WRITE_CMD                  =  0x52,
    ATT_PREPARE_WRITE_REQ          =  0x16,
    ATT_PREPARE_WRITE_RSP          =  0x17,
    ATT_EXECUTE_WRITE_REQ          =  0x18,
    ATT_EXECUTE_WRITE_RSP          =  0x19,
    ATT_READ_MULTIPLE_VARIABLE_REQ =  0x20,
    ATT_READ_MULTIPLE_VARIABLE_RSP =  0x21,
    ATT_MULTIPLE_HANDLE_VALUE_NTF  =  0x23,
    ATT_HANDLE_VALUE_NTF           =  0x1B,
    ATT_HANDLE_VALUE_IND           =  0x1D,
    ATT_HANDLE_VALUE_CFM           =  0x1E,
    ATT_SIGNED_WRITE_CMD           =  0xD2,
};

enum att_error {
    // No error
    ATT_ERR_NO_ERROR                       = 0x00,
    // The attribute handle given was not valid on this server.
    ATT_ERR_INVALID_HANDLE                 = 0x01,
    // The attribute cannot be read.
    ATT_ERR_READ_NOT_PERMITTED             = 0x02,
    // The attribute cannot be written.
    ATT_ERR_WRITE_NOT_PERMITTED            = 0x03,
    // The attribute PDU was invalid.
    ATT_ERR_INVALID_PDU                    = 0x04,
    // The attribute requires authentication before it can be read or written.
    ATT_ERR_INSUFFICIENT_AUTHENTICATION    = 0x05,
    // ATT Server does not support the request received from the client.
    ATT_ERR_REQUEST_NOT_SUPPORTED          = 0x06,
    // Offset specified was past the end of the attribute.
    ATT_ERR_INVALID_OFFSET                 = 0x07,
    // The attribute requires authorization before it can be read or written.
    ATT_ERR_INSUFFICIENT_AUTHORIZATION     = 0x08,
    // Too many prepare writes have been queued.
    ATT_ERR_PREPARE_QUEUE_FULL             = 0x09,
    // No attribute found within the given attri- bute handle range
    ATT_ERR_ATTRIBUTE_NOT_FOUND            = 0x0A,
    // The attribute cannot be read using the ATT_READ_BLOB_REQ PDU.
    ATT_ERR_ATTRIBUTE_NOT_LONG             = 0x0B,
    // The Encryption Key Size used for encrypting this link is too short.
    ATT_ERR_ENCRYPTION_KEY_SIZE_TOO_SHORT  = 0x0C,
    // The attribute value length is invalid for the operation.
    ATT_ERR_INVALID_ATTRIBUTE_VALUE_LENGTH = 0x0D,
    // The attribute request that was requested has encountered an error that was unlikely, and therefore could not be completed as requested.
    ATT_ERR_UNLIKELY_ERROR                 = 0x0E,
    // The attribute requires encryption before it can be read or written.
    ATT_ERR_INSUFFICIENT_ENCRYPTION        = 0x0F,
    // The attribute type is not a supported grouping attribute as defined by a higher layer specification.
    ATT_ERR_UNSUPPORTED_GROUP_TYPE         = 0x10,
    // Insufficient Resources to complete the request.
    ATT_ERR_INSUFFICIENT_RESOURCES         = 0x11,
    // The server requests the client to redis- cover the database.
    ATT_ERR_DATABASE_OUT_OF_SYNC           = 0x12,
    // The attribute parameter value was not allowed.
    ATT_ERR_VALUE_NOT_ALLOWED              = 0x13,
    // Application Error 0x80 – 0x9F
    //     Application error code defined by a higher layer specification.  Common Profile and Service
    // Error Codes 0xE0 – 0xFF
    //     Common profile and service error codes defined in [1]
};

enum att_exec_flags {
    ATT_EXEX_FLAGS_CANCEL = 0,
    ATT_EXEX_FLAGS_WRITE  = 1,
};

enum att_format {
    ATT_FORMAT_16_BIT_UUID  = 0x01,
    ATT_FORMAT_128_BIT_UUID = 0x02,
};

struct att_error_rsp {
    uint8_t opcode;
    uint8_t req_opcode;
    uint16_t handle;
    uint8_t error_code; // @ref enum att_error
} __PACKED;

struct att_exchange_mtu_req {
    uint8_t opcode;
    uint16_t mtu;
} __PACKED;

struct att_exchange_mtu_rsp {
    uint8_t opcode;
    uint16_t mtu;
} __PACKED;

struct att_find_information_req {
    uint8_t opcode;
    uint16_t start_handle;
    uint16_t end_handle;
} __PACKED;

struct att_find_information_rsp {
    uint8_t opcode;
    uint8_t format; // @ref enum att_format
    union {
        struct {
            uint16_t handle;
            uint16_t uuid;
        } info_16bit[0] __PACKED;
        struct {
            uint16_t handle;
            uint8_t uuid[16];
        } info_128bit[0] __PACKED;
    } __PACKED;
} __PACKED;

struct att_find_by_type_value_req {
    uint8_t opcode;
    uint16_t start_handle;
    uint16_t end_handle;
    uint16_t att_type;
    uint8_t att_value[0];
} __PACKED;

struct att_find_by_type_value_rsp {
    uint8_t opcode;
    struct {
        uint16_t start_handle;
        uint16_t end_handle;
    } handle_info[0];
} __PACKED;

struct att_read_by_type_req {
    uint8_t opcode;
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t uuid[0]; // 2 or 16 bytes
} __PACKED;

struct att_read_by_type_rsp {
    uint8_t opcode;
    uint8_t length; // The size of each attribute handle value pair
    uint8_t data[0]; // Attribute Handle(2Bytes) + Attribute Value(Length - 2)
} __PACKED;

struct att_read_req {
    uint8_t opcode;
    uint16_t handle;
} __PACKED;

struct att_read_rsp {
    uint8_t opcode;
    uint8_t data[0];
} __PACKED;

struct att_read_blob_req {
    uint8_t opcode;
    uint16_t handle;
    uint16_t offset;
} __PACKED;

struct att_read_blob_rsp {
    uint8_t opcode;
    uint8_t data[0];
} __PACKED;

struct att_read_multiple_req {
    uint8_t opcode;
    uint16_t handle[0];
} __PACKED;

struct att_read_multiple_rsp {
    uint8_t opcode;
    uint8_t data[0];
} __PACKED;

struct att_read_by_group_type_req {
    uint8_t opcode;
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t uuid[0]; // 2 or 16 bytes
} __PACKED;

struct att_list_16bit {
    uint16_t start_handle;
    uint16_t end_handle;
    uint16_t uuid;
} __PACKED;

struct att_list_128bit {
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t uuid[16];
} __PACKED;

struct att_read_by_group_type_rsp {
    uint8_t opcode;
    uint8_t length; // The size of each Attribute Data
    union {
        struct att_list_16bit list_16bit[0];
        struct att_list_128bit list_128bit[0];
    };
} __PACKED;

struct att_write_req {
    uint8_t opcode;
    uint16_t handle;
    uint8_t value[0];
} __PACKED;

struct att_write_rsp {
    uint8_t opcode;
    uint8_t dummy[0];
} __PACKED;

struct att_write_cmd {
    uint8_t opcode;
    uint16_t handle;
    uint8_t value[0];
} __PACKED;

struct att_prepare_write_req {
    uint8_t opcode;
    uint16_t handle;
    uint16_t offset;
    uint8_t value[0];
} __PACKED;

struct att_prepare_write_rsp {
    uint8_t opcode;
    uint16_t handle;
    uint16_t offset;
    uint8_t value[0];
} __PACKED;

struct att_execute_write_req {
    uint8_t opcode;
    uint8_t flags; // @ref att_exec_flags
} __PACKED;

struct att_execute_write_rsp {
    uint8_t opcode;
    uint8_t dummy[0];
} __PACKED;

struct att_read_multiple_variable_req {
    uint8_t opcode;
    uint16_t handle[0];
} __PACKED;

struct att_read_multiple_variable_rsp {
    uint8_t opcode;
    uint8_t data[0]; // need custom parse
} __PACKED;

struct att_multiple_handle_value_ntf {
    uint8_t opcode;
    uint8_t data[0]; // need custom parse
} __PACKED;

struct att_handle_value_ntf {
    uint8_t opcode;
    uint16_t handle;
    uint8_t data[0];
} __PACKED;

struct att_handle_value_ind {
    uint8_t opcode;
    uint16_t handle;
    uint8_t data[0];
} __PACKED;

struct att_handle_value_cfm {
    uint8_t opcode;
    uint8_t dummy[0];
} __PACKED;

struct att_signed_write_cmd {
    uint8_t opcode;
    uint8_t dummy[0]; // Not supported
} __PACKED;

struct att_packet {
    union {
        uint8_t opcode;
        struct att_error_rsp                   error_rsp;
        struct att_exchange_mtu_req            exchange_mtu_req;
        struct att_exchange_mtu_rsp            exchange_mtu_rsp;
        struct att_find_information_req        find_information_req;
        struct att_find_information_rsp        find_information_rsp;
        struct att_find_by_type_value_req      find_by_type_value_req;
        struct att_find_by_type_value_rsp      find_by_type_value_rsp;
        struct att_read_by_type_req            read_by_type_req;
        struct att_read_by_type_rsp            read_by_type_rsp;
        struct att_read_req                    read_req;
        struct att_read_rsp                    read_rsp;
        struct att_read_blob_req               read_blob_req;
        struct att_read_blob_rsp               read_blob_rsp;
        struct att_read_multiple_req           read_multiple_req;
        struct att_read_multiple_rsp           read_multiple_rsp;
        struct att_read_by_group_type_req      read_by_group_type_req;
        struct att_read_by_group_type_rsp      read_by_group_type_rsp;
        struct att_write_req                   write_req;
        struct att_write_rsp                   write_rsp;
        struct att_write_cmd                   write_cmd;
        struct att_prepare_write_req           prepare_write_req;
        struct att_prepare_write_rsp           prepare_write_rsp;
        struct att_execute_write_req           execute_write_req;
        struct att_execute_write_rsp           execute_write_rsp;
        struct att_read_multiple_variable_req  read_multiple_variable_req;
        struct att_read_multiple_variable_rsp  read_multiple_variable_rsp;
        struct att_multiple_handle_value_ntf   multiple_handle_value_ntf;
        struct att_handle_value_ntf            handle_value_ntf;
        struct att_handle_value_ind            handle_value_ind;
        struct att_handle_value_cfm            handle_value_cfm;
        struct att_signed_write_cmd            signed_write_cmd;
    } __PACKED;
} __PACKED;


#endif /* __EB_ATT_OPCODE_H__ */
