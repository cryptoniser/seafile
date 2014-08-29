/*
 * This file is part of OpenSC library
 * iso7816.h: ISO-7816 defines
 */

#ifndef ISO7816_H
#define ISO7816_H

#include "cryptostick/cs-common.h"
#include "card.h"

#define ISO7816_FILE_TYPE_TRANSPARENT_EF    0x01
#define ISO7816_FILE_TYPE_DF            0x38

#define ISO7816_TAG_FCI         0x6F

#define ISO7816_TAG_FCP         0x62
#define ISO7816_TAG_FCP_SIZE        0x80
#define ISO7816_TAG_FCP_SIZE_FULL   0x81
#define ISO7816_TAG_FCP_TYPE        0x82
#define ISO7816_TAG_FCP_FID     0x83
#define ISO7816_TAG_FCP_DF_NAME     0x84
#define ISO7816_TAG_FCP_PROP_INFO   0x85
#define ISO7816_TAG_FCP_ACLS        0x86
#define ISO7816_TAG_FCP_LCS     0x8A

/* ISO7816 interindustry data tags */
#define ISO7816_II_CATEGORY_TLV     0x80
#define ISO7816_II_CATEGORY_NOT_TLV 0x00

#define ISO7816_TAG_II_CARD_SERVICE     0x43
#define ISO7816_TAG_II_INITIAL_ACCESS_DATA  0x44
#define ISO7816_TAG_II_CARD_ISSUER_DATA     0x45
#define ISO7816_TAG_II_PRE_ISSUING      0x46
#define ISO7816_TAG_II_CARD_CAPABILITIES    0x47
#define ISO7816_TAG_II_AID          0x4F
#define ISO7816_TAG_II_ALLOCATION_SCHEME        0x78
#define ISO7816_TAG_II_STATUS_LCS       0x81
#define ISO7816_TAG_II_STATUS_SW        0x82
#define ISO7816_TAG_II_STATUS_LCS_SW        0x83

/* Other interindustry data tags */
#define IASECC_TAG_II_IO_BUFFER_SIZES       0xE0


int iso7816_check_sw(unsigned int sw1, unsigned int sw2);

int iso7816_get_response(card_t *card, size_t *count, u8 *buf);

int iso7816_process_fci(card_t *card, struct sc_file *file,
        const unsigned char *buf, size_t buflen);

int iso7816_select_file(card_t *card, const struct sc_path *in_path, struct sc_file **file_out);

int iso7816_pin_cmd(card_t *card, struct sc_pin_cmd_data *data, int *tries_left);

int iso7816_decipher(card_t *card,
        const u8 * crgram, size_t crgram_len,
        u8 * out, size_t outlen);

#endif // ISO7816_H
