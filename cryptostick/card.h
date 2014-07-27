#ifndef CARD_H
#define CARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "cryptostick/cs-common.h"

/*
  * Card flags
  *
  * Used to hint about card specific capabilities and algorithms
  * supported to the card driver. Used in sc_atr_table and
  * card_atr block structures in the configuration file.
  *
  * Unknown, card vendor specific values may exists, but must
  * not conflict with values defined here. All actions defined
  * by the flags must be handled by the card driver themselves.
*/

/* Mask for card vendor specific values */
#define CARD_FLAG_VENDOR_MASK    0xFFFF0000

/* Hint CARD_CAP_RNG */
#define CARD_FLAG_RNG        0x00000002

/*
 *  * Card capabilities
 *   */

/* Card can handle large (> 256 bytes) buffers in calls to
 *  * read_binary, write_binary and update_binary; if not,
 *   * several successive calls to the corresponding function
 *    * is made. */
#define CARD_CAP_APDU_EXT        0x00000001

/* Card has on-board random number source. */
#define CARD_CAP_RNG         0x00000004

/* Use the card's ACs in sc_pkcs15init_authenticate(),
 *  * instead of relying on the ACL info in the profile files. */
#define CARD_CAP_USE_FCI_AC      0x00000010

/* D-TRUST CardOS cards special flags */
#define CARD_CAP_ONLY_RAW_HASH       0x00000040
#define CARD_CAP_ONLY_RAW_HASH_STRIPPED  0x00000080

#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))



typedef struct _card_t {
//    struct sc_context *ctx;
    struct sc_reader *reader;

    struct sc_atr atr;

//    int type;           /* Card type, for card driver internal use */
    unsigned long caps, flags;
    int cla;
    size_t max_send_size; /* Max Lc supported by the card */
    size_t max_recv_size; /* Max Le supported by the card */

//    struct sc_app_info *app[SC_MAX_CARD_APPS];
//    int app_count;
//    struct sc_file *ef_dir;   

//    struct sc_ef_atr *ef_atr; 

    struct sc_algorithm_info *algorithms; 
    int algorithm_count;

//    int lock_count;

//    struct sc_card_driver *driver; 
//    struct sc_card_operations *ops;
    const char *name;         
    void *drv_data;           
    int max_pin_len;

//    struct sc_card_cache cache;    

    struct sc_serial_number serialnr;
    struct sc_version version;

//    void *mutex;
//#ifdef ENABLE_SM
//    struct sm_context sm_ctx;
//#endif 

//    unsigned int magic;       
} card_t;


int card_init(card_t *card);
int connect_card(sc_reader_t *reader, card_t **card_out);


#ifdef __cplusplus
}
#endif

#endif // CARD_H
