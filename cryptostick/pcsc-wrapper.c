/*
 * This file is based on OpenSC library
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else  
#include <arpa/inet.h>
#endif 

#ifdef OS_LINUX
#include "winscard.h"
#elif defined (OS_MAC)
#include "PCSC/winscard.h"
#include "PCSC/wintypes.h"
#endif

#include "cryptostick/cs-common.h"
#include "apdu.h"
#include "reader.h"
#include "pcsc-wrapper.h"

static int pcsc_to_opensc_error(LONG rv)
{
    switch (rv) {
    case SCARD_S_SUCCESS:     
        return SC_SUCCESS;
    case SCARD_W_REMOVED_CARD:
        return SC_ERROR_CARD_REMOVED;
    case SCARD_E_NOT_TRANSACTED:       
        return SC_ERROR_TRANSMIT_FAILED;
    case SCARD_W_UNRESPONSIVE_CARD:    
        return SC_ERROR_CARD_UNRESPONSIVE;
    case SCARD_W_UNPOWERED_CARD:       
        return SC_ERROR_CARD_UNRESPONSIVE;
    case SCARD_E_SHARING_VIOLATION:    
        return SC_ERROR_READER_LOCKED;
#ifdef SCARD_E_NO_READERS_AVAILABLE /* Older pcsc-lite does not have it */
    case SCARD_E_NO_READERS_AVAILABLE: 
        return SC_ERROR_NO_READERS_FOUND;
#endif 
    case SCARD_E_NO_SERVICE:  
        /* If the service is (auto)started, there could be readers later */
        return SC_ERROR_NO_READERS_FOUND;
    case SCARD_E_NO_SMARTCARD:
        return SC_ERROR_CARD_NOT_PRESENT;
    case SCARD_E_PROTO_MISMATCH: /* Should not happen */
        return SC_ERROR_READER;    
    default:
        return SC_ERROR_UNKNOWN;   
    }  
}

static unsigned int pcsc_proto_to_opensc(DWORD proto)
{
    switch (proto) {
    case SCARD_PROTOCOL_T0:   
        return SC_PROTO_T0;
    case SCARD_PROTOCOL_T1:   
        return SC_PROTO_T1;
    case SCARD_PROTOCOL_RAW:
        return SC_PROTO_RAW;  
    default:
        return 0;             
    }
}

static DWORD opensc_proto_to_pcsc(unsigned int proto)
{
    switch (proto) {
    case SC_PROTO_T0:         
        return SCARD_PROTOCOL_T0;      
    case SC_PROTO_T1:
        return SCARD_PROTOCOL_T1;      
    case SC_PROTO_RAW:        
        return SCARD_PROTOCOL_RAW;     
    default:
        return 0;             
    }  
}

int pcsc_detect_card_presence(sc_reader_t *reader)
{
    int rv;

    rv = refresh_attributes(reader);
    if (rv != SC_SUCCESS)
        SC_FUNC_RETURN(rv); 
    SC_FUNC_RETURN(reader->flags);
}

int refresh_attributes(sc_reader_t *reader)
{
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader); 
    int old_flags = reader->flags; 
    DWORD state, prev_state;
    LONG rv;

    if (priv->reader_state.szReader == NULL) {
        priv->reader_state.szReader = reader->name;
        priv->reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
        priv->reader_state.dwEventState = SCARD_STATE_UNAWARE;
    } else {
        priv->reader_state.dwCurrentState = priv->reader_state.dwEventState;
    }

    rv = SCardGetStatusChange(priv->gpriv->pcsc_ctx, 0, &priv->reader_state, 1);

    if (rv != SCARD_S_SUCCESS) {   
        if (rv == (LONG)SCARD_E_TIMEOUT) {
            /* Timeout, no change from previous recorded state. Make sure that changed flag is not set. */
            reader->flags &= ~SC_READER_CARD_CHANGED;
            SC_FUNC_RETURN(SC_SUCCESS);
        }
        return pcsc_to_opensc_error(rv);
    }  
    state = priv->reader_state.dwEventState;
    prev_state = priv->reader_state.dwCurrentState;

    if (state & SCARD_STATE_UNKNOWN) {
        /* State means "reader unknown", but we have listed it at least once.
         * There can be no cards in this reader.
         * XXX: We'll hit it again, as no readers are removed currently.
        */
        reader->flags &= ~(SC_READER_CARD_PRESENT);
        return SC_ERROR_READER_DETACHED;
    }  

    reader->flags &= ~(SC_READER_CARD_CHANGED|SC_READER_CARD_INUSE|SC_READER_CARD_EXCLUSIVE);

    if (state & SCARD_STATE_PRESENT) {
        reader->flags |= SC_READER_CARD_PRESENT;

        if (priv->reader_state.cbAtr > SC_MAX_ATR_SIZE)
            return SC_ERROR_INTERNAL;      

        /* Some cards have a different cold (after a powerup) and warm (after a reset) ATR  */
        if (memcmp(priv->reader_state.rgbAtr, reader->atr.value, priv->reader_state.cbAtr) != 0) {
            reader->atr.len = priv->reader_state.cbAtr;
            memcpy(reader->atr.value, priv->reader_state.rgbAtr, reader->atr.len);
        }

        /* Is the reader in use by some other application ? */
        if (state & SCARD_STATE_INUSE) 
            reader->flags |= SC_READER_CARD_INUSE;
        if (state & SCARD_STATE_EXCLUSIVE)
            reader->flags |= SC_READER_CARD_EXCLUSIVE;
        if (old_flags & SC_READER_CARD_PRESENT) {
            /* Requires pcsc-lite 1.6.5+ to function properly */
            if ((state & 0xFFFF0000) != (prev_state & 0xFFFF0000)) {
                reader->flags |= SC_READER_CARD_CHANGED;
            } else {
                /* Check if the card handle is still valid. If the card changed,
                 * the handle will be invalid. */
                DWORD readers_len = 0, cstate, prot, atr_len = SC_MAX_ATR_SIZE;
                unsigned char atr[SC_MAX_ATR_SIZE];
                rv = SCardStatus(priv->pcsc_card, NULL, &readers_len, &cstate, &prot, atr, &atr_len);
                if (rv == (LONG)SCARD_W_REMOVED_CARD)
                    reader->flags |= SC_READER_CARD_CHANGED;
            }
        } else {
            reader->flags |= SC_READER_CARD_CHANGED;
        }
    } else {
        reader->flags &= ~SC_READER_CARD_PRESENT;
        if (old_flags & SC_READER_CARD_PRESENT)
            reader->flags |= SC_READER_CARD_CHANGED;
    }
    
    return SC_SUCCESS;
}

int pcsc_internal_transmit(sc_reader_t *reader,
             const u8 *sendbuf, size_t sendsize,
             u8 *recvbuf, size_t *recvsize, 
             unsigned long control)                                                                                                
{
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
    SCARD_IO_REQUEST sSendPci, sRecvPci; 
    DWORD dwSendLength, dwRecvLength;
    LONG rv;
    SCARDHANDLE card;

    card = priv->pcsc_card;

    sSendPci.dwProtocol = opensc_proto_to_pcsc(reader->active_protocol);
    sSendPci.cbPciLength = sizeof(sSendPci);
    sRecvPci.dwProtocol = opensc_proto_to_pcsc(reader->active_protocol);
    sRecvPci.cbPciLength = sizeof(sRecvPci);                                                                                       

    dwSendLength = sendsize;
    dwRecvLength = *recvsize;

    if (!control) {
        rv = SCardTransmit(card, &sSendPci, sendbuf, dwSendLength,
                   &sRecvPci, recvbuf, &dwRecvLength);
        printf("PCSC error: %s\n",pcsc_stringify_error(rv) );;
    } else {
            rv = SCardControl(card, (DWORD) control, sendbuf, dwSendLength,                                                                                                                                               
                  recvbuf, dwRecvLength, &dwRecvLength);                                                                           
    }  

    if (rv != SCARD_S_SUCCESS) {
        switch (rv) {         
        case SCARD_W_REMOVED_CARD:         
            return SC_ERROR_CARD_REMOVED;
        default:
            /* Translate strange errors from card removal to a proper return code */                                               
            // pcsc_detect_card_presence(reader);
            if (!(pcsc_detect_card_presence(reader) & SC_READER_CARD_PRESENT))                                                     
                return SC_ERROR_CARD_REMOVED;
            return SC_ERROR_TRANSMIT_FAILED;                                                                                       
        }
    }  
    if (!control && dwRecvLength < 2)  
        return SC_ERROR_UNKNOWN_DATA_RECEIVED; 
    *recvsize = dwRecvLength; 

    return SC_SUCCESS;
}


int pcsc_transmit(sc_reader_t *reader, apdu_t *apdu)
{
    size_t       ssize, rsize, rbuflen = 0;     
    u8           *sbuf = NULL, *rbuf = NULL;    
    int          r;

    /* we always use a at least 258 byte size big return buffer
     * to mimic the behaviour of the old implementation (some readers
     * seems to require a larger than necessary return buffer).
     * The buffer for the returned data needs to be at least 2 bytes
     * larger than the expected data length to store SW1 and SW2. */
    rsize = rbuflen = apdu->resplen <= 256 ? 258 : apdu->resplen + 2;
    rbuf     = (u8*)malloc(rbuflen);    
    if (rbuf == NULL) {
        r = SC_ERROR_OUT_OF_MEMORY;    
        goto out;
    }  
    /* encode and log the APDU */  
    r = apdu_get_octets(apdu, &sbuf, &ssize, reader->active_protocol);
    if (r != SC_SUCCESS)
        goto out;
//    if (reader->name)
//        printf("reader '%s'\n", reader->name); 
    apdu_log(sbuf, ssize, 1);

    r = pcsc_internal_transmit(reader, sbuf, ssize,
                rbuf, &rsize, apdu->control); 
    if (r < 0) {
        /* unable to transmit ... most likely a reader problem */
        printf("unable to transmit\n");
        goto out;
    }  
    apdu_log(rbuf, rsize, 0);
    /* set response */
    r = apdu_set_resp(apdu, rbuf, rsize);
out:   
    if (sbuf != NULL) {
        sc_mem_clear(sbuf, ssize);     
        free(sbuf);
    }  
    if (rbuf != NULL) {
        sc_mem_clear(rbuf, rbuflen);   
        free(rbuf);
    }  

    return r;
}


int pcsc_init(sc_reader_t* reader, SCARDCONTEXT cardctx)
{
    struct pcsc_global_private_data *gpriv;
    int ret = SC_ERROR_INTERNAL;


    gpriv = (struct pcsc_global_private_data*)calloc(1, sizeof(struct pcsc_global_private_data));
    if (gpriv == NULL) {
        ret = SC_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    /* Defaults */
    gpriv->connect_exclusive = 0;
    gpriv->disconnect_action = SCARD_RESET_CARD;
    gpriv->transaction_end_action = SCARD_LEAVE_CARD;
    gpriv->reconnect_action = SCARD_LEAVE_CARD;
    gpriv->enable_pinpad = 1;
    gpriv->enable_pace = 1;
    gpriv->pcsc_ctx = cardctx;
    gpriv->pcsc_wait_ctx = -1;

    ((struct pcsc_private_data*)(reader->drv_data))->gpriv = gpriv;

    gpriv = NULL;
    ret = SC_SUCCESS;

out:
/*    if (gpriv != NULL) {
        if (gpriv->dlhandle != NULL)
            sc_dlclose(gpriv->dlhandle);
        free(gpriv);
    }
*/
    return ret;
}

void detect_reader_features(sc_reader_t *reader, SCARDHANDLE card_handle) {

    struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
    u8 feature_buf[256], rbuf[SC_MAX_APDU_BUFFER_SIZE];
    DWORD rcount, feature_len, i;  
    PCSC_TLV_STRUCTURE *pcsc_tlv;  
    LONG rv;
    const char *log_disabled = "but it's disabled in configuration file";
    const char *broken_readers[] = {"HP USB Smart Card Keyboard"};

    rv = SCardControl(card_handle, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, feature_buf, sizeof(feature_buf), &feature_len);
    if (rv != (LONG)SCARD_S_SUCCESS) { 
        printf("SCardControl failed, error: %s\n", pcsc_stringify_error(rv));
        return;
    }

    if ((feature_len % sizeof(PCSC_TLV_STRUCTURE)) != 0) {
        printf("Inconsistent TLV from reader!\n");
        return;
    }   

    /* get the number of elements instead of the complete size */
    feature_len /= sizeof(PCSC_TLV_STRUCTURE);

    pcsc_tlv = (PCSC_TLV_STRUCTURE *)feature_buf;
    for (i = 0; i < feature_len; i++) {
        printf( "Reader feature %02x found\n", pcsc_tlv[i].tag);
        if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_DIRECT) {
            priv->verify_ioctl = ntohl(pcsc_tlv[i].value);
        } else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_START) {
            priv->verify_ioctl_start = ntohl(pcsc_tlv[i].value);
        } else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_FINISH) {
            priv->verify_ioctl_finish = ntohl(pcsc_tlv[i].value); 
        } else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_DIRECT) {
            priv->modify_ioctl = ntohl(pcsc_tlv[i].value);
        } else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_START) {
            priv->modify_ioctl_start = ntohl(pcsc_tlv[i].value);
        } else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_FINISH) {
            priv->modify_ioctl_finish = ntohl(pcsc_tlv[i].value); 
        } else if (pcsc_tlv[i].tag == FEATURE_IFD_PIN_PROPERTIES) {
            priv->pin_properties_ioctl = ntohl(pcsc_tlv[i].value);
        } else if (pcsc_tlv[i].tag == FEATURE_GET_TLV_PROPERTIES)  {
            priv->get_tlv_properties = ntohl(pcsc_tlv[i].value);
        } else if (pcsc_tlv[i].tag == FEATURE_EXECUTE_PACE) { 
            priv->pace_ioctl = ntohl(pcsc_tlv[i].value);
        } else {
            printf("Reader feature %02x is not supported\n", pcsc_tlv[i].tag);
        }
    }  

    /* Set reader capabilities based on detected IOCTLs */
    if (priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish)) {
        const char *log_text = "Reader supports pinpad PIN verification";
        if (priv->gpriv->enable_pinpad) {  
            printf("%s", log_text);
            reader->capabilities |= SC_READER_CAP_PIN_PAD;
        } else {
            printf("%s %s\n", log_text, log_disabled);
        }
    }

    if (priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish)) {
        const char *log_text = "Reader supports pinpad PIN modification";
        if (priv->gpriv->enable_pinpad) {
            printf("%s\n",(log_text));
            reader->capabilities |= SC_READER_CAP_PIN_PAD;
        } else {
            printf( "%s %s\n", log_text, log_disabled);
        }
    }

    /* Ignore advertised pinpad capability on readers known to be broken. Trac #340 */
    for (i = 0; i < sizeof(broken_readers)/sizeof(broken_readers[0]); i++) {
        if (strstr(reader->name, broken_readers[i]) && (reader->capabilities & SC_READER_CAP_PIN_PAD)) {
            printf("%s has a broken pinpad, ignoring\n", reader->name);
            reader->capabilities &= ~SC_READER_CAP_PIN_PAD;
        }
    }

    /* Detect display */
    if (priv->pin_properties_ioctl) {
        rcount = sizeof(rbuf);
        rv = SCardControl(card_handle, priv->pin_properties_ioctl, NULL, 0, rbuf, sizeof(rbuf), &rcount);
        if (rv == SCARD_S_SUCCESS) {
#ifdef PIN_PROPERTIES_v5
            if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE_v5)) {
                PIN_PROPERTIES_STRUCTURE_v5 *caps = (PIN_PROPERTIES_STRUCTURE_v5 *)rbuf;
                if (caps->wLcdLayout > 0) {
                    printf("Reader has a display: %04X\n", caps->wLcdLayout);
                    reader->capabilities |= SC_READER_CAP_DISPLAY;
                } else
                    printf("Reader does not have a display.\n");
            }
#endif
            if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE)) {
                PIN_PROPERTIES_STRUCTURE *caps = (PIN_PROPERTIES_STRUCTURE *)rbuf;
                if (caps->wLcdLayout > 0) {
                    printf("Reader has a display: %04X\n", caps->wLcdLayout);
                    reader->capabilities |= SC_READER_CAP_DISPLAY;
                } else
                    printf("Reader does not have a display.\n");
            } else
                printf("Returned PIN properties structure has bad length (%lu/%lu)\n", rcount, sizeof(PIN_PROPERTIES_STRUCTURE));
        }
    }
}

int pcsc_connect(sc_reader_t *reader)                                                                                                                                                                                           
{
    DWORD active_proto, tmp, protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;                                                                                                                                                         
    SCARDHANDLE card_handle;  
    LONG rv;
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader);                                                                                                                                                                            
    int r;

    
    r = refresh_attributes(reader);
    if (r != SC_SUCCESS)
        return r;

    if (!(reader->flags & SC_READER_CARD_PRESENT))
        return SC_ERROR_CARD_NOT_PRESENT;

    rv = SCardConnect(priv->gpriv->pcsc_ctx, reader->name,
              priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,                                                                                                                                             
              protocol, &card_handle, &active_proto);                                                                                                                                                                                  
#ifdef __APPLE__
    if (rv == (LONG)SCARD_E_SHARING_VIOLATION) { 
        sleep(1); /* Try again to compete with Tokend probes */
        rv = SCardConnect(priv->gpriv->pcsc_ctx, reader->name, 
              priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,                                                                                                                                             
              protocol, &card_handle, &active_proto);                                                                                                                                                                                  
    }  
#endif 
    if (rv != SCARD_S_SUCCESS) {       
        printf("SCardConnect failed\n");
        return pcsc_to_opensc_error(rv);                                                                                                                                                                                               
    }  

    reader->active_protocol = pcsc_proto_to_opensc(active_proto);                                                                                                                                                                      
    priv->pcsc_card = card_handle;                                                                                                                                                                                                     

    printf("Initial protocol: %s\n", reader->active_protocol == SC_PROTO_T1 ? "T=1" : "T=0");                                                                                                        

    /* Check if we need a specific protocol. refresh_attributes above already sets the ATR */
/*    if (check_forced_protocol(reader->ctx, &reader->atr, &tmp)) {                                                                                                                                                                      
        if (active_proto != tmp) {         
            printf("Reconnecting to force protocol\n");
            r = pcsc_reconnect(reader, SCARD_UNPOWER_CARD);
            if (r != SC_SUCCESS) {             
                printf("pcsc_reconnect (to force protocol) failed\n", r);
                return r;
            }
        }
        printf("Final protocol: %s\n", reader->active_protocol == SC_PROTO_T1 ? "T=1" : "T=0");                                                                                                      
    }  
*/

    SCardBeginTransaction(priv->gpriv->pcsc_ctx);

    return SC_SUCCESS;
}

int pcsc_reconnect(sc_reader_t * reader, DWORD action)
{
    DWORD active_proto = opensc_proto_to_pcsc(reader->active_protocol),
          tmp, protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    LONG rv;
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
    int r;

    printf("Reconnecting to the card...\n");

    r = refresh_attributes(reader);
    if (r!= SC_SUCCESS)
        return r;

    if (!(reader->flags & SC_READER_CARD_PRESENT))
        return SC_ERROR_CARD_NOT_PRESENT;

    /* Check if we need a specific protocol. refresh_attributes above already sets the ATR */
//    if (check_forced_protocol( &reader->atr, &tmp))
//        protocol = tmp;

    rv = SCardReconnect(priv->pcsc_card,
                priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
                protocol, action, &active_proto);

    if (rv != SCARD_S_SUCCESS) {
        return pcsc_to_opensc_error(rv);
    }

    reader->active_protocol = pcsc_proto_to_opensc(active_proto);
    return pcsc_to_opensc_error(rv);
}


int pcsc_disconnect(sc_reader_t * reader)
{
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

    SCardEndTransaction(priv->pcsc_card, priv->gpriv->transaction_end_action);
    SCardDisconnect(priv->pcsc_card, priv->gpriv->disconnect_action);
    reader->flags = 0;
    return SC_SUCCESS;
}


int pcsc_detect_readers(reader_list* readerList)
{
    SCARDCONTEXT cardCtx;
    SCARDHANDLE card_handle;
    const char* mszGroups = NULL;
    DWORD reader_buf_size = 0;
    DWORD active_proto;
    char* reader_buf = NULL;
    char* reader_name;
    struct pcsc_private_data* priv;
    sc_reader_t* reader;

    reader_list_node* currReaderNode;
    reader_list_node* prevReaderNode;
    readerList->readerNum = 0;

    int r;
    int i;
    int ret = SC_SUCCESS;

    r = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &cardCtx);
    if (!r==SCARD_S_SUCCESS) {        
        printf("SCardEstablishContext failed\n");
        ret = pcsc_to_opensc_error(r);
        goto out;
    }  

    r = SCardListReaders(cardCtx, NULL, NULL, (LPDWORD) &reader_buf_size);
    if (!r==SCARD_S_SUCCESS) {
        printf("SCardListReaders failed\n");
        ret = SC_ERROR_NO_READERS_FOUND;
        goto out;
    }  

    reader_buf = (char*)malloc(sizeof(char) * reader_buf_size);
    if (!reader_buf) {
        printf("Lack of memory\n");    
        ret = SC_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    r = SCardListReaders(cardCtx, mszGroups, reader_buf, (LPDWORD) &reader_buf_size);
    if (!r==SCARD_S_SUCCESS) {
        printf("SCardListReaders failed\n");
        ret = pcsc_to_opensc_error(r);
        goto out;
    }

    i=0;
    for (reader_name = reader_buf; *reader_name != '\x0'; reader_name += strlen(reader_name) + 1)
    {
        printf("i= %d\n",i);
        i++;

        if ((reader = (sc_reader_t*)calloc(1, sizeof(sc_reader_t))) == NULL) {
            ret = SC_ERROR_OUT_OF_MEMORY;  
            goto err1;
        }
        if ((priv = (struct pcsc_private_data*)calloc(1, sizeof(struct pcsc_private_data))) == NULL) {
            printf("Lack of memory\n");
            ret = SC_ERROR_OUT_OF_MEMORY;  
            goto err1;
        }
        reader->drv_data = priv;
        if( (reader->name = strdup(reader_name)) == NULL) {
            printf("Lack of memory\n");
            ret = SC_ERROR_OUT_OF_MEMORY;  
            goto err1;
        }

        if(readerList->readerNum == 0) {
            readerList->root = (reader_list_node*)calloc(1,sizeof(reader_list_node));
            currReaderNode = readerList->root;
            prevReaderNode = currReaderNode;
        }
        else {
            currReaderNode = (reader_list_node*)calloc(1, sizeof(reader_list_node));
            prevReaderNode->next = currReaderNode;
            prevReaderNode = prevReaderNode->next;
        }

        currReaderNode->reader = reader;
//       currReaderNode = currReaderNode->next;
        readerList->readerNum++;
        
        pcsc_init(reader, cardCtx);
        refresh_attributes(reader);

        r = SCARD_E_SHARING_VIOLATION;
        /* Use DIRECT mode only if there is no card in the reader */  
        if (!(reader->flags & SC_READER_CARD_PRESENT)) {
#ifndef _WIN32  /* Apple 10.5.7 and pcsc-lite previous to v1.5.5 do not support 0 as protocol identifier */
            r = SCardConnect(priv->gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &(priv->pcsc_card), &active_proto);
#else
            r = SCardConnect(priv->gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, 0, &(priv->pcsc_card), &active_proto);
#endif
        }
        if (r == (LONG)SCARD_E_SHARING_VIOLATION) { /* Assume that there is a card in the reader in shared mode if direct communcation failed */
            r = SCardConnect(priv->gpriv->pcsc_ctx, reader->name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &(priv->pcsc_card), &active_proto);
        }

        if (r == SCARD_S_SUCCESS) {
            detect_reader_features(reader, priv->pcsc_card);
            r = SCardDisconnect(priv->pcsc_card, SCARD_LEAVE_CARD);
        }

        continue;

    err1:
        if (priv != NULL) {
            free(priv);
        }
        if (reader != NULL) {
            if (reader->name)
                free(reader->name);
            free(reader);
        }
        goto out;
    }

out:

    if (reader_buf != NULL)
        free (reader_buf);

    return ret;
}

/* Find a given PCSC v2 part 10 property */
static int
part10_find_property_by_tag(unsigned char buffer[], int length,
    int tag_searched)
{
    unsigned char *p;
    int found = 0, len, value = -1;

    p = buffer;
    while (p-buffer < length)
    {
        if (*p++ == tag_searched)
        {
            found = 1;
            break;
        }

        /* go to next tag */
        len = *p++;
        p += len;
    }

    if (found)
    {
        len = *p++;

        switch(len)
        {
            case 1:
                value = *p;
                break;
            case 2:
                value = *p + (*(p+1)<<8);
                break;
            case 4:
                value = *p + (*(p+1)<<8) + (*(p+2)<<16) + (*(p+3)<<24);
                break;
            default:
                value = -1;
        }
    }

    return value;
}

/* Make sure the pin min and max are supported by the reader
 *  * and fix the values if needed */
static int part10_check_pin_min_max(sc_reader_t *reader, struct sc_pin_cmd_data *data)                                                                                                                                                            
{
    int r;
    unsigned char buffer[256];
    size_t length = sizeof buffer; 
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
    struct sc_pin_cmd_pin *pin_ref =   
        data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 
        &data->pin1 : &data->pin2;                                                                                                                                                                                                     

    r = pcsc_internal_transmit(reader, NULL, 0, buffer, &length,
        priv->get_tlv_properties); 
    SC_TEST_RET(r,"PC/SC v2 part 10: Get TLV properties failed!");                                                                                                                                                                               

    /* minimum pin size */
    r = part10_find_property_by_tag(buffer, length,
        PCSCv2_PART10_PROPERTY_bMinPINSize);
    if (r >= 0)
    {  
        unsigned int value = r;                                                                                                                                                                                                        

        if (pin_ref->min_length < value)   
            pin_ref->min_length = r;        
    }  

    /* maximum pin size */
    r = part10_find_property_by_tag(buffer, length,
        PCSCv2_PART10_PROPERTY_bMaxPINSize);
    if (r >= 0)
    {  
        unsigned int value = r;                                                                                                                                                                                                        

        if (pin_ref->max_length > value)   
            pin_ref->max_length = r;                                                                                                                                                                                                   
    }  

    return 0;
}

/*
 *  * Pinpad support, based on PC/SC v2 Part 10 interface
 *   * Similar to CCID in spirit.
 *    */

/* Local definitions */
#define SC_CCID_PIN_TIMEOUT 30

/* CCID definitions */
#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80


/* Build a PIN verification block + APDU */
static int part10_build_verify_pin_block(struct sc_reader *reader, u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
{
    int offset = 0, count = 0;
    apdu_t *apdu = data->apdu;  
    u8 tmp;
    unsigned int tmp16;
    PIN_VERIFY_STRUCTURE *pin_verify  = (PIN_VERIFY_STRUCTURE *)buf;                                                                                                                                                                   

    /* PIN verification control message */
    pin_verify->bTimerOut = SC_CCID_PIN_TIMEOUT;
    pin_verify->bTimerOut2 = SC_CCID_PIN_TIMEOUT;                                                                                                                                                                                      

    /* bmFormatString */
    tmp = 0x00;
    if (data->pin1.encoding == SC_PIN_ENCODING_ASCII) {
        tmp |= SC_CCID_PIN_ENCODING_ASCII;                                                                                                                                                                                             

        /* if the effective PIN length offset is specified, use it */ 
        if (data->pin1.length_offset > 4) {
            tmp |= SC_CCID_PIN_UNITS_BYTES;
            tmp |= (data->pin1.length_offset - 5) << 3;                                                                                                                                                                                
        }
    } else if (data->pin1.encoding == SC_PIN_ENCODING_BCD) {
        tmp |= SC_CCID_PIN_ENCODING_BCD;
        tmp |= SC_CCID_PIN_UNITS_BYTES;
    } else if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
        /* see comment about GLP PINs in sec.c */
        tmp |= SC_CCID_PIN_ENCODING_BCD;
        tmp |= 0x08 << 3;
    } else
        return SC_ERROR_NOT_SUPPORTED;                                                                                                                                                                                                 

    pin_verify->bmFormatString = tmp;                                                                                                                                                                                                  

    /* bmPINBlockString */
    tmp = 0x00;
    if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
        /* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */                                                                                                                                                     
        tmp |= 0x40 | 0x08;   
    } else if (data->pin1.encoding == SC_PIN_ENCODING_ASCII && data->flags & SC_PIN_CMD_NEED_PADDING) {                                                                                                                                
        tmp |= data->pin1.pad_length;                                                                                                                                                                                                  
    }
    pin_verify->bmPINBlockString = tmp;                                                                                                                                                                                                

    /* bmPINLengthFormat */
    tmp = 0x00;
    if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
        /* GLP PINs expect the effective PIN length from bit 4 */                                                                                                                                                                      
        tmp |= 0x04;
    }
    pin_verify->bmPINLengthFormat = tmp;    /* bmPINLengthFormat */                                                                                                                                                                    

    if (!data->pin1.min_length || !data->pin1.max_length)
        return SC_ERROR_INVALID_ARGUMENTS;                                                                                                                                                                                             

    tmp16 = (data->pin1.min_length << 8 ) + data->pin1.max_length; 
    pin_verify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */                                                                                                                                                              

    pin_verify->bEntryValidationCondition = 0x02; /* Keypress only */ 

    if (reader->capabilities & SC_READER_CAP_DISPLAY)
        pin_verify->bNumberMessage = 0xFF; /* Default message */
    else
        pin_verify->bNumberMessage = 0x00; /* No messages */

    /* Ignore language and T=1 parameters. */
    pin_verify->wLangId = HOST_TO_CCID_16(0x0000);
    pin_verify->bMsgIndex = 0x00;
    pin_verify->bTeoPrologue[0] = 0x00;
    pin_verify->bTeoPrologue[1] = 0x00;
    pin_verify->bTeoPrologue[2] = 0x00;

    /* APDU itself */
    pin_verify->abData[offset++] = apdu->cla;
    pin_verify->abData[offset++] = apdu->ins;
    pin_verify->abData[offset++] = apdu->p1;
    pin_verify->abData[offset++] = apdu->p2;

    /* Copy data if not Case 1 */
    if (data->pin1.length_offset != 4) {
        pin_verify->abData[offset++] = apdu->lc;
        memcpy(&pin_verify->abData[offset], apdu->data, apdu->datalen);
        offset += apdu->datalen;
    }

    pin_verify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */

    count = sizeof(PIN_VERIFY_STRUCTURE) + offset;
    *size = count;
    return SC_SUCCESS;
}


int pcsc_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
    struct pcsc_private_data *priv = GET_PRIV_DATA(reader); 
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE]; 
    /* sbuf holds a pin verification/modification structure plus an APDU. */
    u8 sbuf[sizeof(PIN_VERIFY_STRUCTURE)>sizeof(PIN_MODIFY_STRUCTURE)?
        sizeof(PIN_VERIFY_STRUCTURE)+SC_MAX_APDU_BUFFER_SIZE:
        sizeof(PIN_MODIFY_STRUCTURE)+SC_MAX_APDU_BUFFER_SIZE];
    size_t rcount = sizeof(rbuf), scount = 0;
    int r;
    DWORD ioctl = 0;         
    apdu_t *apdu;          

    /* The APDU must be provided by the card driver */
    if (!data->apdu) {
        printf("No APDU provided for PC/SC v2 pinpad verification!\n");
        return SC_ERROR_NOT_SUPPORTED; 
    }  

    apdu = data->apdu;
    part10_check_pin_min_max(reader, data);
    r = part10_build_verify_pin_block(reader, sbuf, &scount, data);
    if(r == SC_SUCCESS)
    ioctl = priv->verify_ioctl ? priv->verify_ioctl : priv->verify_ioctl_start;

    /* If PIN block building failed, we fail too */
    SC_TEST_RET( r, "PC/SC v2 pinpad block building failed!");
    /* If not, debug it, just for fun */
    printf("PC/SC v2 pinpad block: %s\n", dump_hex(sbuf, scount));

    r = pcsc_internal_transmit(reader, sbuf, scount, rbuf, &rcount, ioctl);

    SC_TEST_RET(r, "PC/SC v2 pinpad: block transmit failed!");
    /* finish the call if it was a two-phase operation */
    if ((ioctl == priv->verify_ioctl_start)
        || (ioctl == priv->modify_ioctl_start)) {
        if (rcount != 0) {
            SC_FUNC_RETURN( SC_ERROR_UNKNOWN_DATA_RECEIVED);
        }
        ioctl = (ioctl == priv->verify_ioctl_start) ? priv->verify_ioctl_finish : priv->modify_ioctl_finish;

        rcount = sizeof(rbuf);
        r = pcsc_internal_transmit(reader, sbuf, 0, rbuf, &rcount, ioctl);
        SC_TEST_RET( r, "PC/SC v2 pinpad: finish operation failed!");
    }

    /* We expect only two bytes of result data (SW1 and SW2) */
    if (rcount != 2) {
        SC_FUNC_RETURN( SC_ERROR_UNKNOWN_DATA_RECEIVED);
    }

    /* Extract the SWs for the result APDU */
    apdu->sw1 = (unsigned int) rbuf[rcount - 2];
    apdu->sw2 = (unsigned int) rbuf[rcount - 1];

    r = SC_SUCCESS;
    switch (((unsigned int) apdu->sw1 << 8) | apdu->sw2) {
    case 0x6400: /* Input timed out */
        r = SC_ERROR_KEYPAD_TIMEOUT;
        break;
    case 0x6401: /* Input cancelled */
        r = SC_ERROR_KEYPAD_CANCELLED;
        break;
    case 0x6402: /* PINs don't match */
        r = SC_ERROR_KEYPAD_PIN_MISMATCH;
        break;
    case 0x6403: /* Entered PIN is not in length limits */
        r = SC_ERROR_INVALID_PIN_LENGTH; /* XXX: designed to be returned when PIN is in API call */
        break;
    case 0x6B80: /* Wrong data in the buffer, rejected by firmware */
        r = SC_ERROR_READER;
        break;
    }

    SC_TEST_RET(r, "PIN command failed");

    /* PIN command completed, all is good */
    return SC_SUCCESS;
}

