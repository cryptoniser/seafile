/*
 * NOTICE: This file is a modified version of the original OpenSC iso7816.c
 *
 * iso7816.c: Functions specified by the ISO 7816 standard
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptostick/cs-common.h"
#include "card.h"
#include "apdu.h"
#include "iso7816.h"
#include "pcsc-wrapper.h"

static const struct sc_card_error iso7816_errors[] = {
    { 0x6200, SC_ERROR_CARD_CMD_FAILED, "Warning: no information given, non-volatile memory is unchanged" },
    { 0x6281, SC_ERROR_CORRUPTED_DATA,  "Part of returned data may be corrupted" },
    { 0x6282, SC_ERROR_FILE_END_REACHED,    "End of file/record reached before reading Le bytes" },
    { 0x6283, SC_ERROR_CARD_CMD_FAILED, "Selected file invalidated" },
    { 0x6284, SC_ERROR_CARD_CMD_FAILED, "FCI not formatted according to ISO 7816-4" },

    { 0x6300, SC_ERROR_CARD_CMD_FAILED, "Warning: no information given, non-volatile memory has changed" },
    { 0x6381, SC_ERROR_CARD_CMD_FAILED, "Warning: file filled up by last write" },

    { 0x6581, SC_ERROR_MEMORY_FAILURE,  "Memory failure" },

    { 0x6700, SC_ERROR_WRONG_LENGTH,    "Wrong length" },

    { 0x6800, SC_ERROR_NO_CARD_SUPPORT, "Functions in CLA not supported" },
    { 0x6881, SC_ERROR_NO_CARD_SUPPORT, "Logical channel not supported" },
    { 0x6882, SC_ERROR_NO_CARD_SUPPORT, "Secure messaging not supported" },

    { 0x6900, SC_ERROR_NOT_ALLOWED,     "Command not allowed" },
    { 0x6981, SC_ERROR_CARD_CMD_FAILED, "Command incompatible with file structure" },
    { 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied" },
    { 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED, "Authentication method blocked" },
    { 0x6984, SC_ERROR_REF_DATA_NOT_USABLE, "Referenced data not usable" },
    { 0x6985, SC_ERROR_NOT_ALLOWED,     "Conditions of use not satisfied" },
    { 0x6986, SC_ERROR_NOT_ALLOWED,     "Command not allowed (no current EF)" },
    { 0x6987, SC_ERROR_INCORRECT_PARAMETERS,"Expected SM data objects missing" },
    { 0x6988, SC_ERROR_INCORRECT_PARAMETERS,"SM data objects incorrect" },

    { 0x6A00, SC_ERROR_INCORRECT_PARAMETERS,"Wrong parameter(s) P1-P2" },
    { 0x6A80, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters in the data field" },
    { 0x6A81, SC_ERROR_NO_CARD_SUPPORT, "Function not supported" },
    { 0x6A82, SC_ERROR_FILE_NOT_FOUND,  "File not found" },
    { 0x6A83, SC_ERROR_RECORD_NOT_FOUND,    "Record not found" },
    { 0x6A84, SC_ERROR_NOT_ENOUGH_MEMORY,   "Not enough memory space in the file" },
    { 0x6A85, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with TLV structure" },
    { 0x6A86, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters P1-P2" },
    { 0x6A87, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with P1-P2" },
    { 0x6A88, SC_ERROR_DATA_OBJECT_NOT_FOUND,"Referenced data not found" },
    { 0x6A89, SC_ERROR_FILE_ALREADY_EXISTS,  "File already exists"},
    { 0x6A8A, SC_ERROR_FILE_ALREADY_EXISTS,  "DF name already exists"},

    { 0x6B00, SC_ERROR_INCORRECT_PARAMETERS,"Wrong parameter(s) P1-P2" },
    { 0x6D00, SC_ERROR_INS_NOT_SUPPORTED,   "Instruction code not supported or invalid" },
    { 0x6E00, SC_ERROR_CLASS_NOT_SUPPORTED, "Class not supported" },
    { 0x6F00, SC_ERROR_CARD_CMD_FAILED, "No precise diagnosis" },
};

int iso7816_get_response(card_t *card, size_t *count, u8 *buf);


int iso7816_check_sw(unsigned int sw1, unsigned int sw2)                                                                                                                                                             
{
    const int err_count = sizeof(iso7816_errors)/sizeof(iso7816_errors[0]);                                                                                                                                                            
    int i;

    /* Handle special cases here */
    if (sw1 == 0x6C) {
        printf("Wrong length; correct length is %d", sw2);                                                                                                                                                                  
        return SC_ERROR_WRONG_LENGTH;                                                                                                                                                                                                  
    }  
    if (sw1 == 0x90)
        return SC_SUCCESS;
    if (sw1 == 0x63U && (sw2 & ~0x0fU) == 0xc0U ) {
         printf("Verification failed (remaining tries: %d)", (sw2 & 0x0f));                                                                                                                                             
         return SC_ERROR_PIN_CODE_INCORRECT;                                                                                                                                                                                       
    }
    for (i = 0; i < err_count; i++)   {
        if (iso7816_errors[i].SWs == ((sw1 << 8) | sw2)) {
            printf("%s", iso7816_errors[i].errorstr);
            return iso7816_errors[i].errorno;                                                                                                                                                                                          
        }
    }

    printf("Unknown SWs; SW1=%02X, SW2=%02X", sw1, sw2);                                                                                                                                                                    
    return SC_ERROR_CARD_CMD_FAILED;                                                                                                                                                                                                   
}

int iso7816_get_response(card_t *card, size_t *count, u8 *buf)
{
FUNC_CALLED
    apdu_t apdu;
    int r;
    size_t rlen;

    /* request at most max_recv_size bytes */
    if (card->max_recv_size > 0 && *count > card->max_recv_size)
        rlen = card->max_recv_size;
    else
        rlen = *count;

    format_apdu(card, &apdu, APDU_CASE_2_SHORT, 0xC0, 0x00, 0x00);
    apdu.le      = rlen;
    apdu.resplen = rlen;
    apdu.resp    = buf;
    /* don't call GET RESPONSE recursively */
    apdu.flags  |= APDU_FLAGS_NO_GET_RESP;

    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");
    if (apdu.resplen == 0) {
        printf("End of iso7816_get_response\n");
        LOG_FUNC_RETURN(check_sw(card, apdu.sw1, apdu.sw2));
    }

    *count = apdu.resplen;

    if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
        r = 0;                  /* no more data to read */
    else if (apdu.sw1 == 0x61)
        r = apdu.sw2 == 0 ? 256 : apdu.sw2; /* more data to read    */
    else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82)
        r = 0; /* Le not reached but file/record ended */
    else
        r = check_sw(card, apdu.sw1, apdu.sw2);
printf("End of iso7816_get_response\n");
    return r;
}

int iso7816_process_fci(card_t *card, struct sc_file *file,
        const unsigned char *buf, size_t buflen)                                                                                                                                                                                       
{
    size_t taglen, len = buflen;   
    const unsigned char *tag = NULL, *p = buf;                                                                                                                                                                                         

    printf("processing FCI bytes\n"); 
    tag = sc_asn1_find_tag(p, len, 0x83, &taglen);
    if (tag != NULL && taglen == 2) {  
        file->id = (tag[0] << 8) | tag[1];
        printf("  file identifier: 0x%02X%02X\n", tag[0], tag[1]);                                                                                                                                                                  
    }  

    tag = sc_asn1_find_tag(p, len, 0x80, &taglen);                                                                                                                                                                                
    if (tag == NULL) {
        tag = sc_asn1_find_tag(p, len, 0x81, &taglen);                                                                                                                                                                            
    }  
    if (tag != NULL && taglen > 0 && taglen < 3) {
        file->size = tag[0];  
        if (taglen == 2)
            file->size = (file->size << 8) + tag[1];
        printf("  bytes in file: %lu\n", file->size);                                                                                                                                                                                
    } else {
        file->size = 0;
    }  

    tag = sc_asn1_find_tag(p, len, 0x82, &taglen);                                                                                                                                                                                
    if (tag != NULL) {
        if (taglen > 0) {
            unsigned char byte = tag[0];   
            const char *type; 

            file->shareable = byte & 0x40 ? 1 : 0;
            printf("  shareable: %s\n", (byte & 0x40) ? "yes" : "no");
            file->ef_structure = byte & 0x07;
            switch ((byte >> 3) & 7) {     
            case 0:
                type = "working EF";           
                file->type = SC_FILE_TYPE_WORKING_EF;                                                                                                                                                                                  
                break;
            case 1:
                type = "internal EF";          
                file->type = SC_FILE_TYPE_INTERNAL_EF;                                                                                                                                                                                 
                break;
            case 7:
                type = "DF";
                file->type = SC_FILE_TYPE_DF;  
                break;
            default:
                type = "unknown";              
                break;
            }
            printf("  type: %s\n", type);
            printf("  EF structure: %d\n", byte & 0x07);                                                                                                                                                                            
        }
    }  

    tag = sc_asn1_find_tag(p, len, 0x84, &taglen);
    if (tag != NULL && taglen > 0 && taglen <= 16) {
        char tbuf[128];

        memcpy(file->name, tag, taglen);
        file->namelen = taglen;
        hex_dump(file->name, file->namelen, tbuf, sizeof(tbuf));
        printf("  File name: %s\n", tbuf);
        if (!file->type)
            file->type = SC_FILE_TYPE_DF;
    }

    tag = sc_asn1_find_tag( p, len, 0x85, &taglen);
    if (tag != NULL && taglen)
        sc_file_set_prop_attr(file, tag, taglen);
    else
        file->prop_attr_len = 0;

    tag = sc_asn1_find_tag(p, len, 0xA5, &taglen);
    if (tag != NULL && taglen)
        sc_file_set_prop_attr(file, tag, taglen);

    tag = sc_asn1_find_tag(p, len, 0x86, &taglen);
    if (tag != NULL && taglen)
        sc_file_set_sec_attr(file, tag, taglen);

    tag = sc_asn1_find_tag(p, len, 0x8A, &taglen);
    if (tag != NULL && taglen==1) {
        if (tag[0] == 0x01)
            file->status = SC_FILE_STATUS_CREATION;
        else if (tag[0] == 0x07 || tag[0] == 0x05)
            file->status = SC_FILE_STATUS_ACTIVATED;
        else if (tag[0] == 0x06 || tag[0] == 0x04)
            file->status = SC_FILE_STATUS_INVALIDATED;
    }

    file->magic = SC_FILE_MAGIC;
    return SC_SUCCESS;
}


int iso7816_select_file(card_t *card, const struct sc_path *in_path, struct sc_file **file_out)
{
    apdu_t apdu;
    unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
    unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;                                                                                                                                                                          
    int r, pathlen;
    struct sc_file *file = NULL;                                                                                                                                                                                                       

    memcpy(path, in_path->value, in_path->len);
    pathlen = in_path->len;

    format_apdu(card, &apdu, APDU_CASE_4_SHORT, 0xA4, 0, 0);                                                                                                                                                                     

    switch (in_path->type) {  
    case SC_PATH_TYPE_FILE_ID:
        apdu.p1 = 0;
        if (pathlen != 2)
            return SC_ERROR_INVALID_ARGUMENTS;                                                                                                                                                                                         
        break;
    case SC_PATH_TYPE_DF_NAME:
        apdu.p1 = 4;
        break;
    case SC_PATH_TYPE_PATH:
        apdu.p1 = 8;
        if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
            if (pathlen == 2) { /* only 3F00 supplied */ 
                apdu.p1 = 0;
                break;
            }
            path += 2;
            pathlen -= 2;
        }
        break;
    case SC_PATH_TYPE_FROM_CURRENT:    
        apdu.p1 = 9;
        break;
    case SC_PATH_TYPE_PARENT:
        apdu.p1 = 3;
        pathlen = 0;
        apdu.cse = APDU_CASE_2_SHORT;
        break;
    default:
        LOG_FUNC_RETURN(SC_ERROR_INVALID_ARGUMENTS);                                                                                                                                                                              
    }
    apdu.lc = pathlen;
    apdu.data = path;
    apdu.datalen = pathlen;

    if (file_out != NULL) {
        apdu.p2 = 0;        /* first record, return FCI */                                                                                                                                                                             
        apdu.resp = buf;
        apdu.resplen = sizeof(buf);    
        apdu.le = card->max_recv_size > 0 ? card->max_recv_size : 256;                                                                                                                                                                 
        printf("%s:(%d) %lu\n", __FILE__, __LINE__, apdu.le);
    }
    else {
        apdu.p2 = 0x0C;     /* first record, return nothing */
        apdu.cse = (apdu.lc == 0) ? APDU_CASE_1 : APDU_CASE_3_SHORT;                                                                                                                                                             
    }
    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET( r, "APDU transmit failed");
    if (file_out == NULL) {
        /* For some cards 'SELECT' can be only with request to return FCI/FCP. */
        r = check_sw(card, apdu.sw1, apdu.sw2);
        if (apdu.sw1 == 0x6A && apdu.sw2 == 0x86)   {
            apdu.p2 = 0x00;
            if (transmit_apdu(card, &apdu) == SC_SUCCESS)
                r = check_sw(card, apdu.sw1, apdu.sw2);
        }
        if (apdu.sw1 == 0x61)
            LOG_FUNC_RETURN( SC_SUCCESS);
        LOG_FUNC_RETURN( r);
    }

    r = check_sw(card, apdu.sw1, apdu.sw2);
    if (r)
        LOG_FUNC_RETURN( r);

    if (apdu.resplen < 2)
        LOG_FUNC_RETURN( SC_ERROR_UNKNOWN_DATA_RECEIVED);
    switch (apdu.resp[0]) {
    case ISO7816_TAG_FCI:
    case ISO7816_TAG_FCP:
        file = sc_file_new();
        if (file == NULL)
            LOG_FUNC_RETURN( SC_ERROR_OUT_OF_MEMORY);
        file->path = *in_path;
        if ((size_t)apdu.resp[1] + 2 <= apdu.resplen)
            iso7816_process_fci(card, file, apdu.resp+2, apdu.resp[1]);
        *file_out = file;
        break;
    case 0x00: /* proprietary coding */
        LOG_FUNC_RETURN( SC_ERROR_UNKNOWN_DATA_RECEIVED);
    default:
        LOG_FUNC_RETURN( SC_ERROR_UNKNOWN_DATA_RECEIVED);
    }

    return SC_SUCCESS;
}

static int
iso7816_build_pin_apdu(card_t *card, apdu_t *apdu,
        struct sc_pin_cmd_data *data, u8 *buf, size_t buf_len)                                                                                                                                                                         
{
    FUNC_CALLED
    int r, len = 0, pad = 0, use_pin_pad = 0, ins, p1 = 0;                                                                                                                                                                             

    if (data->flags & SC_PIN_CMD_NEED_PADDING)
        pad = 1;
    if (data->flags & SC_PIN_CMD_USE_PINPAD)
        use_pin_pad = 1;

    data->pin1.offset = 5;

    switch (data->cmd) {
    case SC_PIN_CMD_VERIFY:   
        ins = 0x20;
        if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)                                                                                                                                                                    
            return r;
        len = r;
        break;
    case SC_PIN_CMD_CHANGE:
        ins = 0x24;
        if (data->pin1.len != 0 || use_pin_pad) { 
            if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)                                                                                                                                                                
                return r;
            len += r;
        }
        else {
            /* implicit test */            
            p1 = 1;
        }

        data->pin2.offset = data->pin1.offset + len;
        if ((r = sc_build_pin(buf+len, buf_len-len, &data->pin2, pad)) < 0)                                                                                                                                                            
            return r;
        /* Special case - where provided the old PIN on the command line
         * but expect the new one to be entered on the keypad.                                                                                                                                                                         
         */
        if (data->pin1.len && data->pin2.len == 0) {
            printf("Special case - initial pin provided - but new pin asked on keypad\n");
            data->flags |= SC_PIN_CMD_IMPLICIT_CHANGE;                                                                                                                                                                                 
        }
        len += r;
        break;
    case SC_PIN_CMD_UNBLOCK:
        ins = 0x2C;
        if (data->pin1.len != 0 || use_pin_pad) { 
            if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)                                                                                                                                                                
                return r;
            len += r;
        } else {
            p1 |= 0x02;
        }
        if (data->pin2.len != 0 || use_pin_pad) {
            data->pin2.offset = data->pin1.offset + len;
            if ((r = sc_build_pin(buf+len, buf_len-len, &data->pin2, pad)) < 0)
                return r;
            len += r;
        } else {
            p1 |= 0x01;
        }
        break;
    default:
        return SC_ERROR_NOT_SUPPORTED;
    }

    format_apdu(card, apdu, APDU_CASE_3_SHORT, ins, p1, data->pin_reference);
    apdu->lc = len;
    apdu->datalen = len;
    apdu->data = buf;
    apdu->resplen = 0;

    return 0;
}

int iso7816_pin_cmd(card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
    FUNC_CALLED
	apdu_t local_apdu, *apdu;
	int r;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	if (tries_left)
		*tries_left = -1;

	/* See if we've been called from another card driver, which is
	 * passing an APDU to us (this allows to write card drivers
	 * whose PIN functions behave "mostly like ISO" except in some
	 * special circumstances.
	 */
    r = iso7816_build_pin_apdu(card, &local_apdu, data, sbuf, sizeof(sbuf));
    if (r < 0)
        return r;
    data->apdu = &local_apdu;

	apdu = data->apdu;

    r = transmit_apdu(card,apdu);
    sc_mem_clear(sbuf, sizeof(sbuf));

    if(data->apdu == &local_apdu)
        data->apdu = NULL;

    LOG_TEST_RET(r, "APDU transmit failed");
    if (apdu->sw1 == 0x63) {
        if ((apdu->sw2 & 0x0F) == 0xC0 && tries_left != NULL)
            *tries_left = apdu->sw2 & 0x0F;
        return SC_ERROR_PIN_CODE_INCORRECT;
    }
    return check_sw(card, apdu->sw1, apdu->sw2);
}

int iso7816_decipher(card_t *card,
        const u8 * crgram, size_t crgram_len,
        u8 * out, size_t outlen)       
{
    int       r;
    apdu_t apdu;
    u8        *sbuf = NULL;   

    sbuf = (u8*)malloc(crgram_len + 1); 
    if (sbuf == NULL)
        return SC_ERROR_OUT_OF_MEMORY; 

    /* INS: 0x2A  PERFORM SECURITY OPERATION
     * P1:  0x80  Resp: Plain value
     * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
    format_apdu(card, &apdu, APDU_CASE_4, 0x2A, 0x80, 0x86);
    apdu.resp    = out;
    apdu.resplen = outlen;
    /* if less than 256 bytes are expected than set Le to 0x00
     * to tell the card the we want everything available (note: we
     * always have Le <= crgram_len) */
    apdu.le      = (outlen >= 256 && crgram_len < 256) ? 256 : outlen;
    /* Use APDU chaining with 2048bit RSA keys if the card does not do extended APDU-s */
    if ((crgram_len+1 > 255) && !(card->caps & CARD_CAP_APDU_EXT))
        apdu.flags |= APDU_FLAGS_CHAINING;

    sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
    memcpy(sbuf + 1, crgram, crgram_len);
    apdu.data = sbuf;
    apdu.lc = crgram_len + 1;
    apdu.datalen = crgram_len + 1; 
    r = transmit_apdu(card, &apdu); 
printf("%s:(%d)\n", __FILE__, __LINE__);
    sc_mem_clear(sbuf, crgram_len + 1);
    free(sbuf);
    LOG_TEST_RET(r, "APDU transmit failed");

    if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
        LOG_FUNC_RETURN(apdu.resplen);
    else
        LOG_FUNC_RETURN(check_sw(card, apdu.sw1, apdu.sw2));
}
