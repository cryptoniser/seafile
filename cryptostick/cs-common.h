/*
 * This file is based on OpenSC library
 */

#ifndef CS_COMMON_H
#define CS_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "errors.h"

#define SC_TEST_RET(r, text) do { \
    int _ret = (r); \
    if (_ret < 0) { \
        printf("%s(%d) %s -> %s: %d (%s)\n", __FILE__, __LINE__, __FUNCTION__, \
                               (text), _ret, sc_strerror(_ret)); \
        return _ret; \
    } \
} while(0)

//#define LOG_TEST_RET(r, text) SC_TEST_RET((r), (text)) 
#define LOG_TEST_RET(r, text) if( (r) < 0 ) return (r)

#define SC_FUNC_RETURN(r) do { \
    int _ret = r; \
    if (_ret <= 0) { \
        printf("%s(%d) %s -> returning with: %d (%s)\n", __FILE__, __LINE__, __FUNCTION__, \
                                          _ret, sc_strerror(_ret)); \
    } else { \
        printf("%s(%d) %s -> returning with: %d\n", __FILE__, __LINE__, __FUNCTION__, \
                                     _ret); \
    } \
    return _ret; \
}while(0)

//#define LOG_FUNC_RETURN(r) SC_FUNC_RETURN((r))
#define LOG_FUNC_RETURN(r) return (r)

#define DEBUG 0
#ifdef DEBUG

#define FUNC_CALLED printf("%s\n", __FUNCTION__);

#else
#define FUNC_CALLED
#endif


#ifndef _WIN32
#define msleep(t)   usleep((t) * 1000)
#else
#define msleep(t)   Sleep(t)
#define sleep(t)    Sleep((t) * 1000)
#endif


/* reader flags */
#define SC_READER_CARD_PRESENT      0x00000001
#define SC_READER_CARD_CHANGED      0x00000002
#define SC_READER_CARD_INUSE        0x00000004
#define SC_READER_CARD_EXCLUSIVE    0x00000008
#define SC_READER_HAS_WAITING_AREA  0x00000010

/* reader capabilities */
#define SC_READER_CAP_DISPLAY   0x00000001
#define SC_READER_CAP_PIN_PAD   0x00000002
#define SC_READER_CAP_PACE_EID             0x00000004
#define SC_READER_CAP_PACE_ESIGN           0x00000008
#define SC_READER_CAP_PACE_DESTROY_CHANNEL 0x00000010
#define SC_READER_CAP_PACE_GENERIC         0x00000020


#define SC_PROTO_T0     0x00000001
#define SC_PROTO_T1     0x00000002
#define SC_PROTO_RAW        0x00001000
#define SC_PROTO_ANY        0xFFFFFFFF


/* various maximum values */
#define SC_MAX_CARD_DRIVERS     48
#define SC_MAX_CARD_DRIVER_SNAME_SIZE   16
#define SC_MAX_CARD_APPS        8
#define SC_MAX_APDU_BUFFER_SIZE     261 /* takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
#define SC_MAX_EXT_APDU_BUFFER_SIZE 65538
#define SC_MAX_PIN_SIZE         256 /* OpenPGP card has 254 max */
#define SC_MAX_ATR_SIZE         33
#define SC_MAX_AID_SIZE         16
#define SC_MAX_AID_STRING_SIZE      (SC_MAX_AID_SIZE * 2 + 3)
#define SC_MAX_IIN_SIZE         10
#define SC_MAX_OBJECT_ID_OCTETS     16
#define SC_MAX_PATH_SIZE        16
#define SC_MAX_PATH_STRING_SIZE     (SC_MAX_PATH_SIZE * 2 + 3)
#define SC_MAX_SDO_ACLS         8
#define SC_MAX_CRTS_IN_SE       12
#define SC_MAX_SE_NUM           8

#define SC_PKCS15_PIN_MAGIC     0x31415926
#define SC_PKCS15_MAX_PINS      8
#define SC_PKCS15_MAX_LABEL_SIZE    255
#define SC_PKCS15_MAX_ID_SIZE       25

#define SC_PATH_TYPE_FILE_ID        0
#define SC_PATH_TYPE_DF_NAME        1
#define SC_PATH_TYPE_PATH       2
/* path of a file containing EnvelopedData objects */
#define SC_PATH_TYPE_PATH_PROT      3
#define SC_PATH_TYPE_FROM_CURRENT   4
#define SC_PATH_TYPE_PARENT         5

#define SC_FILE_MAGIC           0x14426950
/* File types */              
#define SC_FILE_TYPE_DF         0x04
#define SC_FILE_TYPE_INTERNAL_EF    0x03
#define SC_FILE_TYPE_WORKING_EF     0x01
#define SC_FILE_TYPE_BSO        0x10
/* EF structures */
#define SC_FILE_EF_UNKNOWN      0x00
#define SC_FILE_EF_TRANSPARENT      0x01
#define SC_FILE_EF_LINEAR_FIXED     0x02
#define SC_FILE_EF_LINEAR_FIXED_TLV 0x03
#define SC_FILE_EF_LINEAR_VARIABLE  0x04
#define SC_FILE_EF_LINEAR_VARIABLE_TLV  0x05
#define SC_FILE_EF_CYCLIC       0x06
#define SC_FILE_EF_CYCLIC_TLV       0x07
/* File status flags */
#define SC_FILE_STATUS_ACTIVATED    0x00
#define SC_FILE_STATUS_INVALIDATED  0x01
#define SC_FILE_STATUS_CREATION     0x02 /* Full access in this state*/


/* This will be the new interface for handling PIN commands.
 *  * It is supposed to support pin pads (with or without display)
 *   * attached to the reader.
 *    */
#define SC_PIN_CMD_VERIFY   0
#define SC_PIN_CMD_CHANGE   1
#define SC_PIN_CMD_UNBLOCK  2
#define SC_PIN_CMD_GET_INFO 3

#define SC_PIN_CMD_USE_PINPAD       0x0001
#define SC_PIN_CMD_NEED_PADDING     0x0002
#define SC_PIN_CMD_IMPLICIT_CHANGE  0x0004
    
#define SC_PIN_ENCODING_ASCII   0
#define SC_PIN_ENCODING_BCD 1
#define SC_PIN_ENCODING_GLP 2 /* Global Platform - Card Specification v2.0.1 */


#define SC_ALGORITHM_RSA        0
#define SC_ALGORITHM_RSA_RAW        0x00000001 
#define SC_ALGORITHM_RSA_PAD_PKCS1  0x00000002
#define SC_ALGORITHM_ONBOARD_KEY_GEN    0x80000000
#define SC_ALGORITHM_RSA_HASH_NONE  0x00000010
/* Card has on-board random number source. */
#define SC_CARD_CAP_RNG         0x00000004


/*              
 *               * Card capabilities
 *                */         
                
/* Card can handle large (> 256 bytes) buffers in calls to
 *  * read_binary, write_binary and update_binary; if not,
 *   * several successive calls to the corresponding function
 *    * is made. */  
#define SC_CARD_CAP_APDU_EXT        0x00000001
                
/* Card has on-board random number source. */
#define SC_CARD_CAP_RNG         0x00000004

/* Use the card's ACs in sc_pkcs15init_authenticate(),
 *  * instead of relying on the ACL info in the profile files. */
#define SC_CARD_CAP_USE_FCI_AC      0x00000010

/* D-TRUST CardOS cards special flags */
#define SC_CARD_CAP_ONLY_RAW_HASH       0x00000040
#define SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED  0x00000080


/* Access Control flags */
#define SC_AC_NONE          0x00000000
#define SC_AC_CHV           0x00000001 /* Card Holder Verif. */
#define SC_AC_TERM          0x00000002 /* Terminal auth. */
#define SC_AC_PRO           0x00000004 /* Secure Messaging */
#define SC_AC_AUT           0x00000008 /* Key auth. */
#define SC_AC_SYMBOLIC          0x00000010 /* internal use only */
#define SC_AC_SEN                       0x00000020 /* Security Environment. */
#define SC_AC_SCB                       0x00000040 /* IAS/ECC SCB byte. */
#define SC_AC_IDA                       0x00000080 /* PKCS#15 authentication ID */

#define SC_AC_UNKNOWN           0xFFFFFFFE
#define SC_AC_NEVER         0xFFFFFFFF


/* Operations relating to access control */
#define SC_AC_OP_SELECT         0
#define SC_AC_OP_LOCK           1
#define SC_AC_OP_DELETE         2
#define SC_AC_OP_CREATE         3
#define SC_AC_OP_REHABILITATE       4
#define SC_AC_OP_INVALIDATE     5
#define SC_AC_OP_LIST_FILES     6
#define SC_AC_OP_CRYPTO         7
#define SC_AC_OP_DELETE_SELF        8
#define SC_AC_OP_PSO_DECRYPT        9
#define SC_AC_OP_PSO_ENCRYPT        10
#define SC_AC_OP_PSO_COMPUTE_SIGNATURE  11
#define SC_AC_OP_PSO_VERIFY_SIGNATURE   12
#define SC_AC_OP_PSO_COMPUTE_CHECKSUM   13
#define SC_AC_OP_PSO_VERIFY_CHECKSUM    14
#define SC_AC_OP_INTERNAL_AUTHENTICATE  15
#define SC_AC_OP_EXTERNAL_AUTHENTICATE  16
#define SC_AC_OP_PIN_DEFINE     17
#define SC_AC_OP_PIN_CHANGE     18
#define SC_AC_OP_PIN_RESET      19
#define SC_AC_OP_ACTIVATE       20
#define SC_AC_OP_DEACTIVATE     21
#define SC_AC_OP_READ           22
#define SC_AC_OP_UPDATE         23
#define SC_AC_OP_WRITE          24
#define SC_AC_OP_RESIZE         25
#define SC_AC_OP_GENERATE       26
#define SC_AC_OP_CREATE_EF      27
#define SC_AC_OP_CREATE_DF      28
#define SC_AC_OP_ADMIN          29
#define SC_AC_OP_PIN_USE        30
/* If you add more OPs here, make sure you increase SC_MAX_AC_OPS*/
#define SC_MAX_AC_OPS           31

/* the use of SC_AC_OP_ERASE is deprecated, SC_AC_OP_DELETE should be used
 *  * instead  */
#define SC_AC_OP_ERASE          SC_AC_OP_DELETE

#define SC_AC_KEY_REF_NONE  0xFFFFFFFF


#define C_ASN1_PUBLIC_KEY_SIZE 2
#define C_ASN1_RSA_PUB_COEFFICIENTS_SIZE 3

typedef unsigned char u8;

typedef struct sc_algorithm_info {
    unsigned int algorithm;
    unsigned int key_length;
    unsigned int flags;
    
    union {
        struct sc_rsa_info {
            unsigned long exponent;
        } _rsa;
        struct sc_ec_info {   
            unsigned ext_flags;
        } _ec;
    } u;
} sc_algorithm_info_t;

/* A large integer, big endian notation */
struct sc_pkcs15_bignum {
    u8 *        data;
    size_t      len;
};
typedef struct sc_pkcs15_bignum sc_pkcs15_bignum_t;

struct sc_pkcs15_pubkey_rsa {
    sc_pkcs15_bignum_t modulus;
    sc_pkcs15_bignum_t exponent;
};


struct sc_pkcs15_id {
    u8 value[SC_PKCS15_MAX_ID_SIZE];
    size_t len;
};
typedef struct sc_pkcs15_id sc_pkcs15_id_t;

struct sc_object_id {
    int value[SC_MAX_OBJECT_ID_OCTETS];
};

struct sc_card_error {
    unsigned int SWs;
    int errorno;
    const char *errorstr;     
};

struct sc_atr {
    unsigned char value[SC_MAX_ATR_SIZE]; 
    size_t len;
};

typedef struct sc_reader {
//    struct sc_context *ctx;   
//    const struct sc_reader_driver *driver;
//    const struct sc_reader_operations *ops;
    void *drv_data;
    
    char *name;

    unsigned long flags, capabilities;
    unsigned int supported_protocols, active_protocol;

    struct sc_atr atr;
    struct _atr_info {
        u8 *hist_bytes;
        size_t hist_bytes_len;
        int Fi, f, Di, N;     
        u8 FI, DI;
    } atr_info;
} sc_reader_t;

/* 'Issuer Identification Number' is a part of ISO/IEC 7812 PAN definition */
struct sc_iin {
    unsigned char mii;              /* industry identifier */      
    unsigned country;               /* country identifier */       
    unsigned long issuer_id;        /* issuer identifier */        
};

/* structure for the card serial number (normally the ICCSN) */
#define SC_MAX_SERIALNR         32
typedef struct sc_serial_number {
    unsigned char value[SC_MAX_SERIALNR];
    size_t len;

    struct sc_iin iin;
} sc_serial_number_t; 


struct sc_version {
    unsigned char hw_major;
    unsigned char hw_minor;

    unsigned char fw_major;
    unsigned char fw_minor;
};

struct sc_aid {
    unsigned char value[SC_MAX_AID_SIZE];
    size_t len;
};

typedef struct sc_path {
    u8 value[SC_MAX_PATH_SIZE];
    size_t len;

    /* The next two fields are used in PKCS15, where
 *      * a Path object can reference a portion of a file -
 *           * count octets starting at offset index.
 *                */
    int index;
    int count;

    int type;

    struct sc_aid aid;
} sc_path_t;


#define SC_MAX_AC_OPS           31
typedef struct sc_file {
    struct sc_path path;      
    unsigned char name[16]; /* DF name */
    size_t namelen; /* length of DF name */

    unsigned int type, ef_structure, status; /* See constant values defined above */
    unsigned int shareable;                  /* true(1), false(0) according to ISO 7816-4:2005 Table 14 */
    size_t size;    /* Size of file (in bytes) */  
    int id;     /* Short file id (2 bytes) */  
    struct sc_acl_entry *acl[SC_MAX_AC_OPS]; /* Access Control List */

    int record_length; /* In case of fixed-length or cyclic EF */
    int record_count;  /* Valid, if not transparent EF or DF */

    unsigned char *sec_attr;    /* security data in proprietary format. tag '86' */
    size_t sec_attr_len;

    unsigned char *prop_attr;   /* proprietary information. tag '85'*/
    size_t prop_attr_len;     

    unsigned char *type_attr;   /* file descriptor data. tag '82'.
                       replaces the file's type information (DF, EF, ...) */
    size_t type_attr_len;

    unsigned char *encoded_content; /* file's content encoded to be used in the file creation command */
    size_t encoded_content_len; /* size of file's encoded content in bytes */

    unsigned int magic;       
} sc_file_t;

/* Control reference template */
struct sc_crt {
    unsigned tag;
    unsigned usage;     /* Usage Qualifier Byte */
    unsigned algo;      /* Algorithm ID */
    unsigned refs[8];   /* Security Object References */
};


typedef struct sc_acl_entry {
    unsigned int method;    /* See SC_AC_* */
    unsigned int key_ref;   /* SC_AC_KEY_REF_NONE or an integer */

    struct sc_crt crts[SC_MAX_CRTS_IN_SE];
    
    struct sc_acl_entry *next;
} sc_acl_entry_t;


struct sc_pin_cmd_pin {
    const char *prompt; /* Prompt to display */

    const u8 *data;     /* PIN, if given by the appliction */
    int len;        /* set to -1 to get pin from pin pad */

    size_t min_length;  /* min/max length of PIN */
    size_t max_length;        
    unsigned int encoding;  /* ASCII-numeric, BCD, etc */  
    size_t pad_length;  /* filled in by the card driver */
    u8 pad_char;
    size_t offset;      /* PIN offset in the APDU */   
    size_t length_offset;   /* Effective PIN length offset in the APDU */

    int max_tries;  /* Used for signaling back from SC_PIN_CMD_GET_INFO */
    int tries_left; /* Used for signaling back from SC_PIN_CMD_GET_INFO */

    struct sc_acl_entry acls[SC_MAX_SDO_ACLS];
};

#include "apdu.h"
struct sc_pin_cmd_data {
    unsigned int cmd;
    unsigned int flags;

    unsigned int pin_type;      /* usually SC_AC_CHV */
    int pin_reference;

    struct sc_pin_cmd_pin pin1, pin2;

    apdu_t *apdu;       /* APDU of the PIN command */
};

u8* ushort2bebytes(u8 *buf, unsigned short x);

void sc_mem_clear(void *ptr, size_t len);
void sc_init_oid(struct sc_object_id *oid);

unsigned short bebytes2ushort(const u8 *buf);

void hex_dump(const u8 * in, size_t count, char *buf, size_t len);
char * dump_hex(const u8 * in, size_t count);
int hex_to_bin(const char *in, u8 *out, size_t *outlen);

void sc_format_path(const char *str, sc_path_t *path);

int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
             unsigned int *tag_out, size_t *taglen);
const u8 *sc_asn1_find_tag( const u8 * buf, size_t buflen, 
        unsigned int tag_in, size_t *taglen_in);


int sc_append_path_id(sc_path_t *dest, const u8 *id, size_t idlen);
int sc_append_file_id(sc_path_t *dest, unsigned int fid);
sc_file_t * sc_file_new(void);
void sc_file_clear_acl_entries(sc_file_t *file, unsigned int operation);
void sc_file_free(sc_file_t *file);
int sc_file_set_prop_attr(sc_file_t *file, const u8 *prop_attr,
             size_t prop_attr_len);
int sc_file_set_sec_attr(sc_file_t *file, const u8 *sec_attr,
             size_t sec_attr_len);
int sc_file_valid(const sc_file_t *file);

int sc_build_pin(u8 *buf, size_t buflen, struct sc_pin_cmd_pin *pin, int pad);

int _sc_parse_atr(sc_reader_t *reader);

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
