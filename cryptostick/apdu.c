#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptostick/cs-common.h"
#include "apdu.h"
#include "errors.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "iso7816.h"

// #include "asn1.h"

/* Calculates the length of the encoded APDU in octets.
  *  @param  apdu   the APDU
  *  @param  proto  the desired protocol
  *  @return length of the encoded APDU
  */
static size_t apdu_get_length(const apdu_t *apdu, unsigned int proto)
{
    size_t ret = 4;

    switch (apdu->cse) {
    case APDU_CASE_1:
        if (proto == SC_PROTO_T0)
            ret++;
        break;
    case APDU_CASE_2_SHORT:
        ret++;
        break;
    case APDU_CASE_2_EXT:
        ret += (proto == SC_PROTO_T0 ? 1 : 3);
        break;
    case APDU_CASE_3_SHORT:
        ret += 1 + apdu->lc;
        break;
    case APDU_CASE_3_EXT:
        ret += apdu->lc + (proto == SC_PROTO_T0 ? 1 : 3);
        break;
    case APDU_CASE_4_SHORT:
        ret += apdu->lc + (proto != SC_PROTO_T0 ? 2 : 1);
        break;
    case APDU_CASE_4_EXT:
        ret += apdu->lc + (proto == SC_PROTO_T0 ? 1 : 5);
        break;
    default:
        return 0;
    }
    return ret;
}

/* Encodes a APDU as an octet string
  *  @param  apdu    APDU to be encoded as an octet string
  *  @param  proto   protocol version to be used
  *  @param  out     output buffer of size outlen.
  *  @param  outlen  size of hte output buffer
  *  @return SC_SUCCESS on success and an error code otherwise
*/
static int apdu2bytes(const apdu_t *apdu,
    unsigned int proto, u8 *out, size_t outlen)
{
    u8     *p = out;

    size_t len = apdu_get_length(apdu, proto);

    if (out == NULL || outlen < len)
        return SC_ERROR_INVALID_ARGUMENTS;
    /* CLA, INS, P1 and P2 */
    *p++ = apdu->cla;
    *p++ = apdu->ins;
    *p++ = apdu->p1;
    *p++ = apdu->p2;
    /* case depend part */
    switch (apdu->cse) {
    case APDU_CASE_1:
        /* T0 needs an additional 0x00 byte */
        if (proto == SC_PROTO_T0)
            *p = (u8)0x00;
        break;
    case APDU_CASE_2_SHORT:
        *p = (u8)apdu->le;
        break;
    case APDU_CASE_2_EXT:
        if (proto == SC_PROTO_T0)
            /* T0 extended APDUs look just like short APDUs */
            *p = (u8)apdu->le;
        else {
            /* in case of T1 always use 3 bytes for length */
            *p++ = (u8)0x00;
            *p++ = (u8)(apdu->le >> 8);
            *p = (u8)apdu->le;
        }
        break;
    case APDU_CASE_3_SHORT:
        *p++ = (u8)apdu->lc;
        memcpy(p, apdu->data, apdu->lc);
        break;
    case APDU_CASE_3_EXT:
        if (proto == SC_PROTO_T0) {
            /* in case of T0 the command is transmitted in chunks
             * < 255 using the ENVELOPE command ... */
            if (apdu->lc > 255) {
                /* ... so if Lc is greater than 255 bytes
                 * an error has occurred on a higher level */
                printf("invalid Lc length for CASE 3 extended APDU (need ENVELOPE)\n");
                return SC_ERROR_INVALID_ARGUMENTS;
            }
        }
        else {
            /* in case of T1 always use 3 bytes for length */
            *p++ = (u8)0x00;
            *p++ = (u8)(apdu->lc >> 8);
            *p++ = (u8)apdu->lc;
        }
        memcpy(p, apdu->data, apdu->lc);
        break;
    case APDU_CASE_4_SHORT:
        *p++ = (u8)apdu->lc;
        memcpy(p, apdu->data, apdu->lc);
        p += apdu->lc;
        /* in case of T0 no Le byte is added */
        if (proto != SC_PROTO_T0)
            *p = (u8)apdu->le;
        break;
    case APDU_CASE_4_EXT:
        if (proto == SC_PROTO_T0) {
            /* again a T0 extended case 4 APDU looks just
             * like a short APDU, the additional data is
             * transferred using ENVELOPE and GET RESPONSE */
            *p++ = (u8)apdu->lc;
            memcpy(p, apdu->data, apdu->lc);
        }
        else {
            *p++ = (u8)0x00;
            *p++ = (u8)(apdu->lc >> 8);
            *p++ = (u8)apdu->lc;
            memcpy(p, apdu->data, apdu->lc);
            p += apdu->lc;
            /* only 2 bytes are use to specify the length of the
             * expected data */
            *p++ = (u8)(apdu->le >> 8);
            *p = (u8)apdu->le;
        }
        break;
    }

    return SC_SUCCESS;
}

void format_apdu(card_t *card, apdu_t *apdu,
            int cse, int ins, int p1, int p2)                                                                                                                                                                                          
{
    memset(apdu, 0, sizeof(*apdu));
    apdu->cla = (u8) card->cla;    
    apdu->cse = cse;
    apdu->ins = (u8) ins;
    apdu->p1 = (u8) p1;
    apdu->p2 = (u8) p2;       
}


int apdu_set_resp(apdu_t *apdu, const u8 *buf,
    size_t len)
{
    if (len < 2) {
        /* no SW1 SW2 ... something went terrible wrong */
        printf ("invalid response: SW1 SW2 missing\n");
        return SC_ERROR_INTERNAL;      
    }  
    /* set the SW1 and SW2 status bytes (the last two bytes of
     * the response */
    apdu->sw1 = (unsigned int)buf[len - 2];
    apdu->sw2 = (unsigned int)buf[len - 1];
    len -= 2;
    /* set output length and copy the returned data if necessary */
    if (len <= apdu->resplen) 
        apdu->resplen = len;

    if (apdu->resplen != 0)
        memcpy(apdu->resp, buf, apdu->resplen);

    return SC_SUCCESS;
}

int apdu_get_octets(const apdu_t *apdu, u8 **buf,
    size_t *len, unsigned int proto)
{
    size_t  nlen;
    u8  *nbuf;

    if (apdu == NULL || buf == NULL || len == NULL) 
        return SC_ERROR_INVALID_ARGUMENTS;

    /* get the estimated length of encoded APDU */
    nlen = apdu_get_length(apdu, proto);
    if (nlen == 0)
        return SC_ERROR_INTERNAL;      
    nbuf = (u8*)malloc(nlen);
    if (nbuf == NULL)         
        return SC_ERROR_OUT_OF_MEMORY; 
    /* encode the APDU in the buffer */
    if (apdu2bytes( apdu, proto, nbuf, nlen) != SC_SUCCESS)
        return SC_ERROR_INTERNAL;      
    *buf = nbuf;
    *len = nlen;

    return SC_SUCCESS;        
}

void apdu_log(const u8 *data, size_t len, int is_out)
{
    size_t blen = len * 5 + 128;   
    char   *buf = (char*)malloc(blen);    
    if (buf == NULL)          
        return;

    hex_dump(data, len, buf, blen);

    printf("\n%s APDU data [%lu bytes] =====================================\n%s======================================================================\n",
        is_out != 0 ? "Outgoing" : "Incoming", len,
        buf);
    free(buf);
}

/* Tries to determine the APDU type (short or extended) of the supplied
 *  APDU if one of the APDU_CASE_? types is used.
 *  @param  apdu  APDU object
*/
static void detect_apdu_cse(const card_t *card, apdu_t *apdu)
{
    if (apdu->cse == APDU_CASE_2 || apdu->cse == APDU_CASE_3 ||
        apdu->cse == APDU_CASE_4) {
        int btype = apdu->cse & APDU_SHORT_MASK;
       /* if either Lc or Le is bigger than the maximun for
        * short APDUs and the card supports extended APDUs
        * use extended APDUs (unless Lc is greater than
        * 255 and command chaining is activated) */
        if ((apdu->le > 256 || (apdu->lc > 255 && (apdu->flags & APDU_FLAGS_CHAINING) == 0)) &&
            (card->caps & CARD_CAP_APDU_EXT) != 0)
            btype |= APDU_EXT;
        apdu->cse = btype;
    }
}

/* basic consistency check of the sc_apdu_t object
 *  @param  ctx   sc_context_t object for error messages
 *  @param  apdu  sc_apdu_t object to check
 *  @return SC_SUCCESS on success and an error code otherwise
 */    
static int check_apdu(card_t *card, const apdu_t *apdu)
{
    if ((apdu->cse & ~APDU_SHORT_MASK) == 0) { 
        /* length check for short APDU    */
        if (apdu->le > 256 || (apdu->lc > 255 && (apdu->flags & APDU_FLAGS_CHAINING) == 0)) {
            goto error;
        }
    }  
    else if ((apdu->cse & APDU_EXT) != 0) {
        /* check if the card supports extended APDUs */
        if ((card->caps & CARD_CAP_APDU_EXT) == 0) {
            goto error;
        }
        /* length check for extended APDU */
        if (apdu->le > 65536 || apdu->lc > 65535) {
            goto error;
        }
    }  
    else   {
        goto error;           
    }  

    switch (apdu->cse & APDU_SHORT_MASK) {
    case APDU_CASE_1:
        /* no data is sent or received */
        if (apdu->datalen != 0 || apdu->lc != 0 || apdu->le != 0)
            goto error;       
        break;
    case APDU_CASE_2_SHORT:
        /* no data is sent        */   
        if (apdu->datalen != 0 || apdu->lc != 0)
            goto error;       
        /* data is expected       */   
        if (apdu->resplen == 0 || apdu->resp == NULL)
            goto error;
        /* return buffer to small */
        if ((apdu->le == 0 && apdu->resplen < SC_MAX_APDU_BUFFER_SIZE-2)
                || (apdu->resplen < apdu->le))
            goto error;
        break;
    case APDU_CASE_3_SHORT:
        /* data is sent           */
        if (apdu->datalen == 0 || apdu->data == NULL || apdu->lc == 0)
            goto error;
        /* no data is expected    */
        if (apdu->le != 0)
            goto error;
        /* inconsistent datalen   */
        if (apdu->datalen != apdu->lc)
            goto error;
        break;
    case APDU_CASE_4_SHORT:
        /* data is sent           */
        if (apdu->datalen == 0 || apdu->data == NULL || apdu->lc == 0)
            goto error;
        /* data is expected       */
        if (apdu->resplen == 0 || apdu->resp == NULL)
            goto error;
        /* return buffer to small */
        if ((apdu->le == 0 && apdu->resplen < SC_MAX_APDU_BUFFER_SIZE-2)
                || (apdu->resplen < apdu->le))
            goto error;
        /* inconsistent datalen   */
        if (apdu->datalen != apdu->lc)
            goto error;
        break;
    default:
        printf("Invalid APDU case %d", apdu->cse);
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    return SC_SUCCESS;
error:
    printf("Invalid Case %d %s APDU:\n cse=%02x cla=%02x ins=%02x p1=%02x p2=%02x lc=%lu le=%lu\n resp=%p resplen=%lu data=%p datalen=%lu",
        apdu->cse & APDU_SHORT_MASK,
        (apdu->cse & APDU_EXT) != 0 ? "extended" : "short",
        apdu->cse, apdu->cla, apdu->ins, apdu->p1, apdu->p2,
        (unsigned long) apdu->lc, (unsigned long) apdu->le,
        apdu->resp, (unsigned long) apdu->resplen,
        apdu->data, (unsigned long) apdu->datalen);
    return SC_ERROR_INVALID_ARGUMENTS;
}

int check_sw(card_t *card, unsigned int sw1, unsigned int sw2)
{
    FUNC_CALLED
    return iso7816_check_sw(sw1, sw2);
}

static int single_transmit(card_t *card, apdu_t *apdu)
{
    int rv;

//    printf("CLA:%X, INS:%X, P1:%X, P2:%X, data(%lu) %p\n",
//            apdu->cla, apdu->ins, apdu->p1, apdu->p2, apdu->datalen, apdu->data);
#ifdef ENABLE_SM
    if (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT)
        return sm_single_transmit(card, apdu);
#endif

    /* send APDU to the reader driver */
    rv = pcsc_transmit(card->reader, apdu);
    LOG_TEST_RET(rv, "unable to transmit APDU");

    LOG_FUNC_RETURN(rv);
}

static int set_le_and_transmit(card_t *card, apdu_t *apdu, size_t olen)
{
    size_t nlen = apdu->sw2 ? (size_t)apdu->sw2 : 256;
    int rv;

    /* we cannot re-transmit the APDU with the demanded Le value
     * as the buffer is too small => error */
    if (olen < nlen)          
        LOG_TEST_RET(SC_ERROR_WRONG_LENGTH, "wrong length: required length exceeds resplen");

    /* don't try again if it doesn't work this time */
    apdu->flags  |= APDU_FLAGS_NO_GET_RESP;  
    /* set the new expected length */
    apdu->resplen = olen;
    apdu->le      = nlen;

    /* re-transmit the APDU with new Le length */
    rv = single_transmit(card, apdu);
    LOG_TEST_RET(rv, "cannot re-transmit APDU");

    LOG_FUNC_RETURN(rv); 
}

int get_response(card_t *card, apdu_t *apdu, size_t olen)
{
FUNC_CALLED
    size_t le, minlen, buflen;
    unsigned char *buf;       
    int rv;

    if (apdu->le == 0) {      
        // no data is requested => change return value to 0x9000 and ignore the remaining data
        apdu->sw1 = 0x90;     
        apdu->sw2 = 0x00;     
        return SC_SUCCESS;    
    }  

    /* call GET RESPONSE until we have read all data requested or until the card retuns 0x9000,                                                                                                                                        
     * whatever happens first. */                                                                                                                                                                                                      

    /* if there are already data in response append a new data to the end of the buffer */                                                                                                                                             
    buf = apdu->resp + apdu->resplen;                                                                                                                                                                                                  
    /* read as much data as fits in apdu->resp (i.e. min(apdu->resplen, amount of data available)). */                                                                                                                                 
    buflen = olen - apdu->resplen;                                                                                                                                                                                                     

    /* 0x6100 means at least 256 more bytes to read */ 
    le = apdu->sw2 != 0 ? (size_t)apdu->sw2 : 256;
    /* we try to read at least as much as bytes as promised in the response bytes */                                                                                                                                                   
    minlen = le;

printf("------------------------------------------------------------ buf = %p, le=%lu, buflen=%lu\n",buf, le, buflen);
    do {
        unsigned char resp[256];       
        size_t resp_len = le; 

        /* call GET RESPONSE to get more date from the card;
         * note: GET RESPONSE returns the left amount of data (== SW2) */                                                                                                                                                              
        memset(resp, 0, sizeof(resp)); 
        rv = iso7816_get_response(card, &resp_len, resp);                                                                                                                                                                           
        if (rv < 0)   {
            LOG_TEST_RET(rv, "GET RESPONSE error");                                                                                                                                                                               
        }

        le = resp_len;
        /* copy as much as will fit in requested buffer */                                                                                                                                                                             
        if (buflen < le)      
            le = buflen;

        memcpy(buf, resp, le);
        buf    += le;
        buflen -= le;
printf("------------------------------------------------------------ buf = %p, le=%lu, buflen=%lu\n",buf, le, buflen);
        /* we have all the data the caller requested even if the card has more data */                                                                                                                                                 
        if (buflen == 0)      
            break;

        minlen -= le;
        if (rv != 0)
            le = minlen = (size_t)rv;
        else
            /* if the card has returned 0x9000 but we still expect data ask for more
             * until we have read enough bytes */
            le = minlen;
    } while (rv != 0 || minlen != 0);

    /* we've read all data, let's return 0x9000 */
    apdu->resplen = buf - apdu->resp;
    apdu->sw1 = 0x90;
    apdu->sw2 = 0x00;

    LOG_FUNC_RETURN(SC_SUCCESS);
}

/** Sends a single APDU to the card reader and calls GET RESPONSE to get the return data if necessary.
 *  @param  card  card_t object for the smartcard
 *  @param  apdu  APDU to be sent
 *  @return SC_SUCCESS on success and an error value otherwise
*/    
static int transmit(card_t *card, apdu_t *apdu)
{
    size_t       olen  = apdu->resplen;
    int          r;

    r = single_transmit(card, apdu);
    LOG_TEST_RET(r, "transmit APDU failed");

    /* ok, the APDU was successfully transmitted. Now we have two special cases:
     * 1. the card returned 0x6Cxx: in this case APDU will be re-trasmitted with Le set to SW2
     * (possible only if response buffer size is larger than new Le = SW2)
     */
    if (apdu->sw1 == 0x6C && (apdu->flags & APDU_FLAGS_NO_RETRY_WL) == 0)
        r = set_le_and_transmit(card, apdu, olen);
    LOG_TEST_RET(r, "cannot re-transmit APDU ");

    /* 2. the card returned 0x61xx: more data can be read from the card
     *    using the GET RESPONSE command (mostly used in the T0 protocol).
     *    Unless the APDU_FLAGS_NO_GET_RESP is set we try to read as
     *    much data as possible using GET RESPONSE.
     */
    if (apdu->sw1 == 0x61 && (apdu->flags & APDU_FLAGS_NO_GET_RESP) == 0) {
//        printf("----------------------------------------------- 0x61!\n");
        r = get_response(card, apdu, olen);
    }
    LOG_TEST_RET(r, "cannot get all data with 'GET RESPONSE'");

    LOG_FUNC_RETURN(SC_SUCCESS);
}

int transmit_apdu(card_t *card, apdu_t *apdu)                                                                                                                                                                                 
{
    int r = SC_SUCCESS;       

    if (apdu == NULL) {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    /* determine the APDU type if necessary, i.e. to use
     * short or extended APDUs  */ 
    detect_apdu_cse(card, apdu);
    /* basic APDU consistency check */ 
    r = check_apdu(card, apdu); 
    if (r != SC_SUCCESS) {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    if ((apdu->flags & APDU_FLAGS_CHAINING) != 0) {
        /* divide et impera: transmit APDU in chunks with Lc <= max_send_size                                                                                                                                                          
         * bytes using command chaining */
        size_t    len  = apdu->datalen;
        const u8  *buf = apdu->data;   
        size_t    max_send_size = card->max_send_size > 0 ? card->max_send_size : 255;                                                                                                                                                 

        while (len != 0) {    
            size_t    plen;
            apdu_t tapdu;
            int       last = 0;                                                                                                                                                                                                        

            tapdu = *apdu;
            /* clear chaining flag */      
            tapdu.flags &= ~APDU_FLAGS_CHAINING;
            if (len > max_send_size) {         
                /* adjust APDU case: in case of CASE 4 APDU
                 * the intermediate APDU are of CASE 3 */
                if ((tapdu.cse & APDU_SHORT_MASK) == APDU_CASE_4_SHORT)                                                                                                                                                          
                    tapdu.cse--;               
                plen          = max_send_size; 
                tapdu.cla    |= 0x10;          
                tapdu.le      = 0;             
                /* the intermediate APDU don't expect data */
                tapdu.lc      = 0;             
                tapdu.resplen = 0;             
                tapdu.resp    = NULL;      
            } else {          
                plen = len;   
                last = 1;     
            }
            tapdu.data    = (unsigned char*)buf;           
            tapdu.datalen = tapdu.lc = plen;                                                                                                                                                                                           

            r = check_apdu(card, &tapdu);
            if (r != SC_SUCCESS) {
                printf("inconsistent APDU while chaining");                                                                                                                                                                 
                break;
            }

            r = transmit(card, &tapdu);
            if (r != SC_SUCCESS)
                break;
            if (last != 0) {
                /* in case of the last APDU set the SW1
                 * and SW2 bytes in the original APDU */
                apdu->sw1 = tapdu.sw1;
                apdu->sw2 = tapdu.sw2;
                apdu->resplen = tapdu.resplen;
            } else {
                /* otherwise check the status bytes */
                r = check_sw(card, tapdu.sw1, tapdu.sw2);
                if (r != SC_SUCCESS)
                    break;
            }
            len -= plen;
            buf += plen;
        }
    } else 
        /* transmit single APDU */
        r = transmit(card, apdu);

    return r;
}
