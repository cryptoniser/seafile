/*
 * This file is based on OpenSC library
 */

#ifndef PCSC_WRAPPER_H
#define PCSC_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <config.h>

#ifdef OS_LINUX
#include "winscard.h"
#elif defined (OS_MAC)
#include "PCSC/winscard.h"
#include "PCSC/wintypes.h"
#endif

#include "apdu.h"
#include "cryptostick/cs-common.h"
#include "winscard.h"

#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)

typedef LONG (PCSC_API *SCardEstablishContext_t)(DWORD dwScope, LPCVOID pvReserved1,
    LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
typedef LONG (PCSC_API *SCardReleaseContext_t)(SCARDCONTEXT hContext);
typedef LONG (PCSC_API *SCardConnect_t)(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
    DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
typedef LONG (PCSC_API *SCardReconnect_t)(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols,
    DWORD dwInitialization, LPDWORD pdwActiveProtocol);
typedef LONG (PCSC_API *SCardDisconnect_t)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (PCSC_API *SCardBeginTransaction_t)(SCARDHANDLE hCard);
typedef LONG (PCSC_API *SCardEndTransaction_t)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (PCSC_API *SCardStatus_t)(SCARDHANDLE hCard, LPSTR mszReaderNames, LPDWORD pcchReaderLen,
    LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);
typedef LONG (PCSC_API *SCardGetStatusChange_t)(SCARDCONTEXT hContext, DWORD dwTimeout,
    SCARD_READERSTATE *rgReaderStates, DWORD cReaders);                                                                                                                                                                                
typedef LONG (PCSC_API *SCardCancel_t)(SCARDCONTEXT hContext);
typedef LONG (PCSC_API *SCardControlOLD_t)(SCARDHANDLE hCard, LPCVOID pbSendBuffer, DWORD cbSendLength,
    LPVOID pbRecvBuffer, LPDWORD lpBytesReturned);
typedef LONG (PCSC_API *SCardControl_t)(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
    DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
    LPDWORD lpBytesReturned);
typedef LONG (PCSC_API *SCardTransmit_t)(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,                                                                                                                                            
    LPCBYTE pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci,
    LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);                                                                                                                                                                                       
typedef LONG (PCSC_API *SCardListReaders_t)(SCARDCONTEXT hContext, LPCSTR mszGroups,
    LPSTR mszReaders, LPDWORD pcchReaders);
typedef LONG (PCSC_API *SCardGetAttrib_t)(SCARDHANDLE hCard, DWORD dwAttrId,\
    LPBYTE pbAttr, LPDWORD pcbAttrLen);

struct pcsc_global_private_data {  
    SCARDCONTEXT pcsc_ctx;
    SCARDCONTEXT pcsc_wait_ctx;    
    int enable_pinpad;
    int enable_pace;
    int connect_exclusive;    
    DWORD disconnect_action;
    DWORD transaction_end_action;  
    DWORD reconnect_action;
    const char *provider_library;  
    void *dlhandle;
    SCardEstablishContext_t SCardEstablishContext;
    SCardReleaseContext_t SCardReleaseContext;
    SCardConnect_t SCardConnect;   
    SCardReconnect_t SCardReconnect;
    SCardDisconnect_t SCardDisconnect;
    SCardBeginTransaction_t SCardBeginTransaction;
    SCardEndTransaction_t SCardEndTransaction;
    SCardStatus_t SCardStatus;
    SCardGetStatusChange_t SCardGetStatusChange; 
    SCardCancel_t SCardCancel;
    SCardControlOLD_t SCardControlOLD;
    SCardControl_t SCardControl;   
    SCardTransmit_t SCardTransmit; 
    SCardListReaders_t SCardListReaders;
    SCardGetAttrib_t SCardGetAttrib;                                                                                                                                                                                                   
};

struct pcsc_private_data {
    struct pcsc_global_private_data *gpriv;
    SCARDHANDLE pcsc_card;
    SCARD_READERSTATE reader_state;
    DWORD verify_ioctl;
    DWORD verify_ioctl_start;
    DWORD verify_ioctl_finish;

    DWORD modify_ioctl;
    DWORD modify_ioctl_start;
    DWORD modify_ioctl_finish;

    DWORD pace_ioctl;

    DWORD pin_properties_ioctl;                                                                                                                                                                                                        

    DWORD get_tlv_properties;

//    int locked;
};

typedef struct _reader_list_node {
    sc_reader_t* reader;
    struct _reader_list_node* next;
}reader_list_node;

typedef struct _reader_list {
    reader_list_node* root;
    unsigned int readerNum;

} reader_list;

int pcsc_detect_card_presence(sc_reader_t *reader);

int refresh_attributes(sc_reader_t *reader);

int pcsc_internal_transmit(sc_reader_t *reader,
             const u8 *sendbuf, size_t sendsize,
             u8 *recvbuf, size_t *recvsize, 
             unsigned long control);

int pcsc_transmit(sc_reader_t *reader, apdu_t *apdu);

int pcsc_init(sc_reader_t* reader, SCARDCONTEXT cardctx);

void detect_reader_features(sc_reader_t *reader, SCARDHANDLE card_handle);

int pcsc_connect(sc_reader_t *reader);

int pcsc_reconnect(sc_reader_t * reader, DWORD action);

int pcsc_disconnect(sc_reader_t * reader);

// TODO: Return the list of readers, not the last one
int pcsc_detect_readers(reader_list* readerList);

int pcsc_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data);

#ifdef __cplusplus
}
#endif

#endif // PCSC_WRAPPER_H
