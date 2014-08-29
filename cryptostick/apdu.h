/*
 * This file is based on OpenSC library
 */

#ifndef APDU_H
#define APDU_H

/* Different APDU cases */
#define APDU_CASE_NONE       0x00
#define APDU_CASE_1          0x01
#define APDU_CASE_2_SHORT    0x02
#define APDU_CASE_3_SHORT    0x03
#define APDU_CASE_4_SHORT    0x04
#define APDU_SHORT_MASK      0x0f
#define APDU_EXT             0x10
#define APDU_CASE_2_EXT      APDU_CASE_2_SHORT | APDU_EXT 
#define APDU_CASE_3_EXT      APDU_CASE_3_SHORT | APDU_EXT
#define APDU_CASE_4_EXT      APDU_CASE_4_SHORT | APDU_EXT
/* following types let OpenSC decides whether to use short or extended APDUs */
#define APDU_CASE_2          0x22
#define APDU_CASE_3          0x23
#define APDU_CASE_4          0x24
/* use command chaining if the Lc value is greater than normally allowed */
#define APDU_FLAGS_CHAINING      0x00000001UL
/* do not automatically call GET RESPONSE to read all available data */
#define APDU_FLAGS_NO_GET_RESP   0x00000002UL
/* do not automatically try a re-transmit with a new length if the card 
 *  * returns 0x6Cxx (wrong length)
 *   */    
#define APDU_FLAGS_NO_RETRY_WL   0x00000004UL

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "cryptostick/cs-common.h"
#include "errors.h"
#include "card.h"


#define APDU_ALLOCATE_FLAG       0x01
#define APDU_ALLOCATE_FLAG_DATA  0x02
#define APDU_ALLOCATE_FLAG_RESP  0x04

typedef struct _apdu_t {      
    int cse;                        /* APDU case */
    unsigned char cla, ins, p1, p2; /* CLA, INS, P1 and P2 bytes */
    size_t lc, le;                  /* Lc and Le bytes */
    unsigned char *data;            /* S-APDU data */
    size_t datalen;                 /* length of data in S-APDU */     
    unsigned char *resp;            /* R-APDU data buffer */   
    size_t resplen;                 /* in: size of R-APDU buffer,
                                     * out: length of data returned in R-APDU */
    unsigned char control;          /* Set if APDU should go to the reader */
    unsigned allocation_flags;      /* APDU allocation flags */

    unsigned int sw1, sw2;          /* Status words returned in R-APDU */
    unsigned char mac[8];     
    size_t mac_len;

    unsigned long flags;      

//    struct _apdu_t *next;
} apdu_t;


// size_t apdu_get_length(const apdu_t *apdu, unsigned int proto);

// int apdu2bytes(const apdu_t *apdu, unsigned int proto, u8 *out, size_t outlen);

void format_apdu(card_t *card, apdu_t *apdu,
            int cse, int ins, int p1, int p2);

int apdu_set_resp(apdu_t *apdu, const u8 *buf,size_t len);

int apdu_get_octets(const apdu_t *apdu, u8 **buf,
    size_t *len, unsigned int proto);

void apdu_log(const u8 *data, size_t len, int is_out);

// void detect_apdu_cse(const card_t *card, apdu_t *apdu);

// int check_apdu(card_t *card, const apdu_t *apdu);

int check_sw(card_t *card, unsigned int sw1, unsigned int sw2);

// int sm_single_transmit(card_t *card, apdu_t *apdu);

// int single_transmit(card_t *card, apdu_t *apdu);

// int set_le_and_transmit(card_t *card,  apdu_t *apdu, size_t olen);

// int sm_update_apdu_response(card_t *card, unsigned char *resp_data, size_t resp_len,
//        int ref_rv, apdu_t *apdu);

int get_response(card_t *card, apdu_t *apdu, size_t olen);

// int transmit(card_t *card, apdu_t *apdu);

int transmit_apdu(card_t * card, apdu_t *apdu);


#ifdef __cplusplus
}
#endif

#endif // APDU_H
