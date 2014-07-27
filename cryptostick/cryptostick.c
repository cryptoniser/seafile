#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "cryptostick/cs-common.h"
#include "openpgp.h"
#include "iso7816.h"

#include "cryptostick.h"

int csListDevices(cs_list* cryptosticks)
{
    int r;

    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));

    r = pcsc_detect_readers(readerList);
    if ( ! r == SC_SUCCESS) {
        free(readerList);
        return r;
    }

    
    int i;
    cryptosticks->numOfNodes = 0;
    cs_list_node* csCurrentNode;
    cs_list_node* previousNode;
    reader_list_node* readerCurrentNode = readerList->root;

    for( i=0; i<readerList->readerNum; i++)
    {   
        csCurrentNode = (cs_list_node*)malloc(sizeof(cs_list_node));
        r = connect_card(readerCurrentNode->reader, &(csCurrentNode->card));
        if(! r == SC_SUCCESS)
            continue;

        r = card_init(csCurrentNode->card);
        if(! r == SC_SUCCESS)
            continue;

        if(i == 0) {
            cryptosticks->root = csCurrentNode;
            previousNode = cryptosticks->root;
        } else {
            previousNode->next = csCurrentNode;
            previousNode = previousNode->next;
        }
        cryptosticks->numOfNodes++;
        

        if(i != readerList->readerNum -1) {
            readerCurrentNode = readerCurrentNode->next;
        }
    }

    return SC_SUCCESS;
}

int csGetSerialNo(card_t *card, unsigned char serialno[9])
{
    int i;
    for(i=0;i<4;i++)
        sprintf( serialno + i*2 ,"%02X", card->serialnr.value[2+i]);
    serialno[8] = '\0';

//    memcpy(serialno, &(card->serialnr.value[2]), 4);
//    serialno[4]='\0';
    return 0;
}

int csGetPublicKey(card_t *card, 
                    unsigned char** publicModulus, size_t* publicModulusLength,
                    unsigned char** publicExponent, size_t* publicExponentLength)
{
    int r,i;

    apdu_t apdu;

    u8 idbuf[2];
    unsigned tag = 0xb800; // Control reference template for confidentiality (CT)
    size_t buf_len=500;
    u8* buf;
    buf = (u8*)malloc((buf_len)*sizeof(u8));

    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;         
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.resp = buf;          
    apdu.resplen = buf_len;   


    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error");
    
    unsigned int cla;
    size_t taglen;
    sc_asn1_read_tag((const u8**)(&buf), buf_len, &cla, &tag, &taglen);
    if( cla != 0x60 || tag != 0x1f49)
        return -1;

    // Get modulus from response
    sc_asn1_read_tag((const u8**)(&buf), buf_len, &cla, &tag, &taglen);
    if( cla != 0x80 ||  tag != 0x01)
        return -1;
    *publicModulusLength = taglen;
    *publicModulus = (unsigned char*)malloc((taglen+1)*sizeof(unsigned char));
    memcpy(*publicModulus, buf, taglen);
    publicModulus[taglen]='\0';
    buf+=taglen;
    
    // Get exponent from response
    sc_asn1_read_tag((const u8**)(&buf), buf_len, &cla, &tag, &taglen);
    *publicExponent = (unsigned char*)malloc(taglen*sizeof(unsigned char));
    if( cla != 0x80 || tag != 0x02)
        return -1;
    *publicExponentLength = taglen;
    *publicExponent = (unsigned char*)malloc(taglen*sizeof(unsigned char));
    memcpy(*publicExponent, buf, taglen);
    buf+=taglen;

    return 0;
}

int csVerifyPIN(card_t *card, unsigned char* pin, int pinLength)
{
    int r;

    struct sc_pin_cmd_data pin_data;
    pin_data.cmd = SC_PIN_CMD_VERIFY;
    pin_data.pin_reference = 2;

    pin_data.pin1.data = (const u8*)pin ;
    pin_data.pin1.len = pinLength;
    pin_data.pin1.min_length = 6;
    pin_data.pin1.max_length = 32;
    pin_data.pin1.encoding = SC_PIN_ENCODING_ASCII;

    int tries_left;
    pgp_pin_cmd(card, &pin_data, &tries_left);

    return 0;
}

int csDecipher(card_t *card, unsigned char* input, size_t in_len,
                unsigned char* output, size_t out_len)
{
    return iso7816_decipher(card, input, in_len, output, out_len);
}

int csEncrypt(card_t* card, unsigned char* input, unsigned inputLength,
                            unsigned char** encrypted, unsigned* encryptedLength)
{
    int r,i;

    // Get public key
    unsigned char* modulus;
    unsigned char* exponent;
    size_t modlen, explen;
    r = csGetPublicKey(card, &modulus, &modlen, &exponent, &explen);

    RSA* rsa = NULL;
    *encryptedLength = inputLength % 256 == 0 ? inputLength : (inputLength/256 +1)*256;
    *encrypted = (unsigned char*)malloc(sizeof(unsigned char)*(*encryptedLength));
    unsigned char* n_hex;
    unsigned char* e_hex;
    
    n_hex = (unsigned char*)malloc(sizeof(unsigned char*)*modlen*2);
    for(i=0;i<modlen;i++)
        sprintf((char*)(n_hex + (i * 2)), "%02x", modulus[i]);

    e_hex = (unsigned char*)malloc(sizeof(unsigned char*)*explen*2);
    for(i=0;i<explen;i++)
        sprintf((char*)(e_hex + (i * 2)), "%02x", exponent[i]);
    
    ERR_load_crypto_strings();
    rsa = RSA_new();

    if(!BN_hex2bn(&rsa->n, (const char*)n_hex)) {
        printf("modulo parsing error\n");
        return -1;
    }

    if (!BN_hex2bn(&rsa->e, (const char*)e_hex)) {
        printf("exponent parsing error\n");
        return -1;
    }

    int enc_length = RSA_public_encrypt(6, input, *encrypted, rsa, RSA_PKCS1_PADDING);
    *encryptedLength = enc_length;
    printf("encrypted: \n");
    for(i=0;i<*encryptedLength;i++)
        printf("%.2x ", (*encrypted)[i]);
    printf("\n\n\n\n\n\n");

    if(enc_length == -1) {
        char error[400];
        ERR_error_string(ERR_get_error(), error);
        printf("Public key encrypt failed with error: %s \n", error );
        return -1;
    }

    return 0;
}

int csHashPublicKey(card_t *card, unsigned char hashedKey[65])
{
    int r;

    // Get public key   
    unsigned char* modulus;
    unsigned char* exponent;
    size_t modlen, explen;
    r = csGetPublicKey(card, &modulus, &modlen, &exponent, &explen);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (const char*)modulus, strlen((const char*)modulus));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf((char*)(hashedKey + (i * 2)), "%02x", hash[i]);
    }
    hashedKey[64] = '\0';
}
