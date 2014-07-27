#ifndef CRYPOSTICK_H
#define CRYPOSTICK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cryptostick/cs-common.h"
#include "pcsc-wrapper.h"
#include "card.h"

typedef struct _cs_list_node {
    card_t* card;
    struct _cs_list_node* next;
} cs_list_node;

typedef struct cs_list {
    cs_list_node* root;
    size_t numOfNodes;
} cs_list;

int csListDevices(cs_list* cryptosticks);

int csGetSerialNo(card_t *card, unsigned char serialno[9]);

int csGetPublicKey(card_t *card, 
                    unsigned char** publicModulus, size_t* publicModulusLength,
                    unsigned char** publicExponent, size_t* publicExponentLength);

int csVerifyPIN(card_t *card, unsigned char* pin, int pinLength);

int csDecipher(card_t *card, unsigned char* input, size_t in_length, 
                unsigned char* output, size_t out_len);

int csEncrypt(card_t* card, unsigned char* input, unsigned inputLength,
                            unsigned char** encrypted, unsigned* encryptedLength);

int csHashPublicKey(card_t *card, unsigned char hashedKey[65]);

int csFindCard(unsigned char serial_no[9], card_t* card);

#ifdef __cplusplus
}
#endif

#endif // CRYPOSTICK_H

