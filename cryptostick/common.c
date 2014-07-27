#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "errors.h"
#include "cryptostick/cs-common.h"
#include "asn1.h"

u8* ushort2bebytes(u8 *buf, unsigned short x)
{
    if (buf != NULL) {
        buf[1] = (u8) (x & 0xff);      
        buf[0] = (u8) ((x >> 8) & 0xff);
    }  
    return buf;    
}

void sc_mem_clear(void *ptr, size_t len)
{
#ifdef ENABLE_OPENSSL         
    /* FIXME: Bug in 1.0.0-beta series crashes with 0 length */
    if (len > 0)
        OPENSSL_cleanse(ptr, len);
#else  
    memset(ptr, 0, len);      
#endif 
}

void sc_init_oid(struct sc_object_id *oid)
{
    int ii;

    if (!oid)
        return;
    for (ii=0; ii<SC_MAX_OBJECT_ID_OCTETS; ii++)
        oid->value[ii] = -1;
}

unsigned short bebytes2ushort(const u8 *buf)
{
    if (buf == NULL)
        return 0U;
    return (unsigned short) (buf[0] << 8 | buf[1]);
}

/* Although not used, we need this for consistent exports */
void hex_dump(const u8 * in, size_t count, char *buf, size_t len)
{
    char *p = buf;
    int lines = 0;

    buf[0] = 0;
    if ((count * 5) > len)
        return;
    while (count) {
        char ascbuf[17];
        size_t i;

        for (i = 0; i < count && i < 16; i++) {
            sprintf(p, "%02X ", *in);      
            if (isprint(*in))
                ascbuf[i] = *in;           
            else
                ascbuf[i] = '.';           
            p += 3;
            in++;
        }
        count -= i;
        ascbuf[i] = 0;
        for (; i < 16 && lines; i++) {     
            strcat(p, "   ");
            p += 3;
        }
        strcat(p, ascbuf);
        p += strlen(p);
        sprintf(p, "\n");
        p++;
        lines++;
    }
}


char* dump_hex(const u8 * in, size_t count)   
{
    static char dump_buf[0x1000];  
    size_t ii, size = sizeof(dump_buf) - 0x10; 
    size_t offs = 0;

    memset(dump_buf, 0, sizeof(dump_buf));
    if (in == NULL)           
        return dump_buf;

    for (ii=0; ii<count; ii++) {       
        if (ii && !(ii%16))   {            
            if (!(ii%48))     
                snprintf(dump_buf + offs, size - offs, "\n");
            else
                snprintf(dump_buf + offs, size - offs, " ");
            offs = strlen(dump_buf);   
        }

        snprintf(dump_buf + offs, size - offs, "%02X", *(in + ii));
        offs += 2;

        if (offs > size)      
            break;
    }  

    if (ii<count)             
        snprintf(dump_buf + offs, sizeof(dump_buf) - offs, "....\n");

    return dump_buf;          
}

int hex_to_bin(const char *in, u8 *out, size_t *outlen)
{
    int err = 0;
    size_t left, count = 0;

    left = *outlen;

    while (*in != '\0') {
        int byte = 0, nybbles = 2;

        while (nybbles-- && *in && *in != ':' && *in != ' ') {
            char c;
            byte <<= 4;
            c = *in++;
            if ('0' <= c && c <= '9')
                c -= '0';
            else
            if ('a' <= c && c <= 'f')
                c = c - 'a' + 10;
            else
            if ('A' <= c && c <= 'F')
                c = c - 'A' + 10;
            else {
                err = SC_ERROR_INVALID_ARGUMENTS;
                goto out;
            }
            byte |= c;
        }
        if (*in == ':' || *in == ' ')
            in++;
        if (left <= 0) {
            err = SC_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        out[count++] = (u8) byte;
        left--;
    }

out:
    *outlen = count;
    return err;
}

void sc_format_path(const char *str, sc_path_t *path)
{
    int type = SC_PATH_TYPE_PATH;  

    memset(path, 0, sizeof(*path));
    if (*str == 'i' || *str == 'I') { 
        type = SC_PATH_TYPE_FILE_ID;   
        str++;
    }  
    path->len = sizeof(path->value);
    if (hex_to_bin(str, path->value, &path->len) >= 0) {
        path->type = type;
    }  
    path->count = -1;         
    return;
}

int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
             unsigned int *tag_out, size_t *taglen)                                                                                                                                                                                    
{
    const u8 *p = *buf;
    size_t left = buflen, len;
    unsigned int cla, tag, i; 

    if (left < 2)
        return SC_ERROR_INVALID_ASN1_OBJECT;
    *buf = NULL;
    if (*p == 0xff || *p == 0)
        /* end of data reached */      
        return SC_SUCCESS;    
    /* parse tag byte(s) */   
    cla = (*p & SC_ASN1_TAG_CLASS) | (*p & SC_ASN1_TAG_CONSTRUCTED);                                                                                                                                                                   
    tag = *p & SC_ASN1_TAG_PRIMITIVE;
    p++;
    left--;
    if (tag == SC_ASN1_TAG_PRIMITIVE) {
        /* high tag number */ 
        size_t n = sizeof(int) - 1;    
        /* search the last tag octet */
        while (left-- != 0 && n != 0) {    
            tag <<= 8;        
            tag |= *p;        
            if ((*p++ & 0x80) == 0)            
                break;
            n--;              
        }
        if (left == 0 || n == 0)           
            /* either an invalid tag or it doesn't fit in
 *              * unsigned int */
            return SC_ERROR_INVALID_ASN1_OBJECT;                                                                                                                                                                                       

    }  
    if (left == 0)
        return SC_ERROR_INVALID_ASN1_OBJECT;
    /* parse length byte(s) */
    len = *p & 0x7f;          
    if (*p++ & 0x80) {
        unsigned int a = 0;   
        if (len > 4 || len > left)         
            return SC_ERROR_INVALID_ASN1_OBJECT;
        left -= len;
        for (i = 0; i < len; i++) {        
            a <<= 8;
            a |= *p;
            p++;
        }
        len = a;
    }  
    if (len > left)
        return SC_ERROR_INVALID_ASN1_OBJECT;
    *cla_out = cla;
    *tag_out = tag;
    *taglen = len;
    *buf = p;
    return SC_SUCCESS;
}

const u8 *sc_asn1_find_tag( const u8 * buf, size_t buflen, 
        unsigned int tag_in, size_t *taglen_in)
{
    size_t left = buflen, taglen;  
    const u8 *p = buf;        

    *taglen_in = 0;
    while (left >= 2) {       
        unsigned int cla, tag, mask = 0xff00;                                                                                                                                                                                          

        buf = p;
        /* read a tag */      
        if (sc_asn1_read_tag(&p, left, &cla, &tag, &taglen) != SC_SUCCESS)                                                                                                                                                             
            return NULL;
        if (left < (size_t)(p - buf)) {    
            printf("invalid TLV object\n");                                                                                                                                                                  
            return NULL;
        }
        left -= (p - buf);    
        /* we need to shift the class byte to the leftmost
 *          * byte of the tag */
        while ((tag & mask) != 0) {        
            cla  <<= 8;       
            mask <<= 8;       
        }
        /* compare the read tag with the given tag */
        if ((tag | cla) == tag_in) {       
            /* we have a match => return length and value part */                                                                                                                                                                      
            if (taglen > left)
                return NULL;
            *taglen_in = taglen;           
            return p;
        }
        /* otherwise continue reading tags */
        if (left < taglen) {
            printf("invalid TLV object\n");                                                                                                                                                                  
            return NULL;
        }
        left -= taglen;       
        p += taglen;
    }  
    return NULL;
}

int sc_append_path_id(sc_path_t *dest, const u8 *id, size_t idlen)
{
    if (dest->len + idlen > SC_MAX_PATH_SIZE)
        return SC_ERROR_INVALID_ARGUMENTS;
    memcpy(dest->value + dest->len, id, idlen);
    dest->len += idlen;       
    return 0;
}

int sc_append_file_id(sc_path_t *dest, unsigned int fid)
{
    u8 id[2] = { fid >> 8, fid & 0xff };

    return sc_append_path_id(dest, id, 2);
}

sc_file_t * sc_file_new(void) 
{
    sc_file_t *file = (sc_file_t *)calloc(1, sizeof(sc_file_t));
    if (file == NULL)         
        return NULL;          

    file->magic = SC_FILE_MAGIC;   
    return file;
}

void sc_file_clear_acl_entries(sc_file_t *file, unsigned int operation) 
{
    sc_acl_entry_t *e;        

    e = file->acl[operation]; 
    if (e == (sc_acl_entry_t *) 1 ||
        e == (sc_acl_entry_t *) 2 ||   
        e == (sc_acl_entry_t *) 3) {   
        file->acl[operation] = NULL;   
        return;
    }  

    while (e != NULL) {
        sc_acl_entry_t *tmp = e->next; 
        free(e);
        e = tmp;
    }  
    file->acl[operation] = NULL;   
}

void sc_file_free(sc_file_t *file)     
{
    unsigned int i;           
    file->magic = 0;          
    for (i = 0; i < SC_MAX_AC_OPS; i++)
        sc_file_clear_acl_entries(file, i);
    if (file->sec_attr)       
        free(file->sec_attr); 
    if (file->prop_attr)      
        free(file->prop_attr);
    if (file->type_attr)      
        free(file->type_attr);
    if (file->encoded_content)
        free(file->encoded_content);
    free(file);
}

int sc_file_set_prop_attr(sc_file_t *file, const u8 *prop_attr,
             size_t prop_attr_len)     
{
    u8 *tmp;
    if (prop_attr == NULL) {  
        if (file->prop_attr != NULL)       
            free(file->prop_attr);     
        file->prop_attr = NULL;        
        file->prop_attr_len = 0;       
        return 0;
     } 
    tmp = (u8 *) realloc(file->prop_attr, prop_attr_len);
    if (!tmp) {
        if (file->prop_attr)  
            free(file->prop_attr);     
        file->prop_attr = NULL;        
        file->prop_attr_len = 0;       
        return SC_ERROR_OUT_OF_MEMORY;
    }  
    file->prop_attr = tmp;    
    memcpy(file->prop_attr, prop_attr, prop_attr_len); 
    file->prop_attr_len = prop_attr_len;

    return 0;
}

int sc_file_set_sec_attr(sc_file_t *file, const u8 *sec_attr,
             size_t sec_attr_len)           
{
    u8 *tmp;
    if (sec_attr == NULL) {   
        if (file->sec_attr != NULL)    
            free(file->sec_attr);          
        file->sec_attr = NULL;
        file->sec_attr_len = 0;        
        return 0;
     } 
    tmp = (u8 *) realloc(file->sec_attr, sec_attr_len);
    if (!tmp) {
        if (file->sec_attr)   
            free(file->sec_attr);          
        file->sec_attr     = NULL;     
        file->sec_attr_len = 0;        
        return SC_ERROR_OUT_OF_MEMORY; 
    }  
    file->sec_attr = tmp;
    memcpy(file->sec_attr, sec_attr, sec_attr_len);
    file->sec_attr_len = sec_attr_len;

    return 0;
}

int sc_file_valid(const sc_file_t *file) {
    return file->magic == SC_FILE_MAGIC;
}

/*
  * This function will copy a PIN, convert and pad it as required
  *
  * Note about the SC_PIN_ENCODING_GLP encoding:
  * PIN buffers are allways 16 nibbles (8 bytes) and look like this:
  *   0x2 + len + pin_in_BCD + paddingnibbles
  * in which the paddingnibble = 0xF
  * E.g. if PIN = 12345, then sbuf = {0x24, 0x12, 0x34, 0x5F, 0xFF, 0xFF, 0xFF, 0xFF}
  * E.g. if PIN = 123456789012, then sbuf = {0x2C, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xFF}
  * Reference: Global Platform - Card Specification - version 2.0.1' - April 7, 2000
*/
int sc_build_pin(u8 *buf, size_t buflen, struct sc_pin_cmd_pin *pin, int pad)                                                                                                                                                          
{
    size_t i = 0, j, pin_len = pin->len;                                                                                                                                                                                               

    if (pin->max_length && pin_len > pin->max_length)
        return SC_ERROR_INVALID_ARGUMENTS;                                                                                                                                                                                             

    if (pin->encoding == SC_PIN_ENCODING_GLP) {
        while (pin_len > 0 && pin->data[pin_len - 1] == 0xFF)                                                                                                                                                                          
            pin_len--;
        if (pin_len > 12)
            return SC_ERROR_INVALID_ARGUMENTS;
        for (i = 0; i < pin_len; i++) {    
            if (pin->data[i] < '0' || pin->data[i] > '9')
                return SC_ERROR_INVALID_ARGUMENTS;                                                                                                                                                                                     
        }
        buf[0] = 0x20 | pin_len;       
        buf++;
        buflen--;
    }  

    /* PIN given by application, encode if required */
    if (pin->encoding == SC_PIN_ENCODING_ASCII) {
        if (pin_len > buflen)
            return SC_ERROR_BUFFER_TOO_SMALL;
        memcpy(buf, pin->data, pin_len); 
        i = pin_len;
    } else if (pin->encoding == SC_PIN_ENCODING_BCD || pin->encoding == SC_PIN_ENCODING_GLP) {                                                                                                                                         
        if (pin_len > 2 * buflen)          
            return SC_ERROR_BUFFER_TOO_SMALL; 
        for (i = j = 0; j < pin_len; j++) {
            buf[i] <<= 4;
            buf[i] |= pin->data[j] & 0xf;  
            if (j & 1)
                i++;          
        }
        if (j & 1) {
            buf[i] <<= 4;
            buf[i] |= pin->pad_char & 0xf; 
            i++;              
        }
    }  

    /* Pad to maximum PIN length if requested */
    if (pad || pin->encoding == SC_PIN_ENCODING_GLP) {
        size_t pad_length = pin->pad_length;  
        u8     pad_char   = pin->encoding == SC_PIN_ENCODING_GLP ? 0xFF : pin->pad_char;                                                                                                                                               

        if (pin->encoding == SC_PIN_ENCODING_BCD)
            pad_length >>= 1;
        if (pin->encoding == SC_PIN_ENCODING_GLP)
            pad_length = 8;

        if (pad_length > buflen)           
            return SC_ERROR_BUFFER_TOO_SMALL;                                                                                                                                                                                          

        if (pad_length && i < pad_length) {
            memset(buf + i, pad_char, pad_length - i);
            i = pad_length;
        }
    }

    return i;
}


int _sc_parse_atr(sc_reader_t *reader)                                                                                                                                                                                                 
{
    u8 *p = reader->atr.value;
    int atr_len = (int) reader->atr.len;
    int n_hist, x;
    int tx[4] = {-1, -1, -1, -1};  
    int i, FI, DI;
    const int Fi_table[] = {
        372, 372, 558, 744, 1116, 1488, 1860, -1,
        -1, 512, 768, 1024, 1536, 2048, -1, -1 };
    const int f_table[] = {
        40, 50, 60, 80, 120, 160, 200, -1, 
        -1, 50, 75, 100, 150, 200, -1, -1 }; 
    const int Di_table[] = {
        -1, 1, 2, 4, 8, 16, 32, -1,    
        12, 20, -1, -1, -1, -1, -1, -1 };                                                                                                                                                                                              

    reader->atr_info.hist_bytes_len = 0;
    reader->atr_info.hist_bytes = NULL;                                                                                                                                                                                                

    if (atr_len == 0) {
        printf("empty ATR - card not present?\n");
        return SC_ERROR_INTERNAL;  
    }  

    if (p[0] != 0x3B && p[0] != 0x3F) {
        printf("invalid sync byte in ATR: 0x%02X\n", p[0]);                                                                                                                                                               
        return SC_ERROR_INTERNAL;  
    }  
    n_hist = p[1] & 0x0F;
    x = p[1] >> 4;
    p += 2;
    atr_len -= 2;
    for (i = 0; i < 4 && atr_len > 0; i++) {   
                if (x & (1 << i)) {                    
                        tx[i] = *p;                    
                        p++;  
                        atr_len--;             
                } else
                        tx[i] = -1;    
        }
    if (tx[0] >= 0) {
        reader->atr_info.FI = FI = tx[0] >> 4;
        reader->atr_info.DI = DI = tx[0] & 0x0F;
        reader->atr_info.Fi = Fi_table[FI];
        reader->atr_info.f = f_table[FI];
        reader->atr_info.Di = Di_table[DI];                                                                                                                                                                                            
    } else {
        reader->atr_info.Fi = -1;      
        reader->atr_info.f = -1;       
        reader->atr_info.Di = -1;  
    }  
    if (tx[2] >= 0)
        reader->atr_info.N = tx[3];
    else
        reader->atr_info.N = -1;   
    while (tx[3] > 0 && tx[3] & 0xF0 && atr_len > 0) {                                                                                                                                                                                 
        x = tx[3] >> 4;
        for (i = 0; i < 4 && atr_len > 0; i++) {   
                    if (x & (1 << i)) {                    
                            tx[i] = *p;
                            p++;
                            atr_len--;
                    } else
                            tx[i] = -1;
        }
    }
    if (atr_len <= 0)
        return 0;
    if (n_hist > atr_len)
        n_hist = atr_len;
    reader->atr_info.hist_bytes_len = n_hist;
    reader->atr_info.hist_bytes = p;
    return 0;
}

