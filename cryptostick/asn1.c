#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "cryptostick/cs-common.h"


static int asn1_encode_entry(const struct sc_asn1_entry *entry,
                 u8 **obj, size_t *objlen, int depth)
{
    void *parm = entry->parm;
    int (*callback_func)(void *arg, u8 **nobj,
                 size_t *nobjlen, int ndepth);
    const size_t *len = (const size_t *) entry->arg;
    int r = 0;
    u8 * buf = NULL;
    size_t buflen = 0;

    callback_func = parm;

    printf("%*.*sencoding '%s'%s\n",
            depth, depth, "", entry->name,
        (entry->flags & SC_ASN1_PRESENT)? "" : " (not present)");
    if (!(entry->flags & SC_ASN1_PRESENT))
        goto no_object;
    printf( "%*.*stype=%d, tag=0x%02x, parm=%p, len=%u\n",
        depth, depth, "",
        entry->type, entry->tag, parm, len? *len : 0);

    if (entry->type == SC_ASN1_CHOICE) {
        const struct sc_asn1_entry *list, *choice = NULL;

        list = (const struct sc_asn1_entry *) parm;
        while (list->name != NULL) {
            if (list->flags & SC_ASN1_PRESENT) {
                if (choice) {
                    printf("ASN.1 problem: more than "
                        "one CHOICE when encoding %s: "
                        "%s and %s both present\n",
                        entry->name,
                        choice->name,
                        list->name);
                    return SC_ERROR_INVALID_ASN1_OBJECT;
                }
                choice = list;
            }
            list++;
        }
        if (choice == NULL)
            goto no_object;
        return asn1_encode_entry(choice, obj, objlen, depth + 1);
    }

    if (entry->type != SC_ASN1_NULL && parm == NULL) {
        printf("unexpected parm == NULL\n");
        return SC_ERROR_INVALID_ASN1_OBJECT;
    }

    switch (entry->type) {
    case SC_ASN1_STRUCT:
        r = asn1_encode( (const struct sc_asn1_entry *) parm, &buf,
                &buflen, depth + 1);
        break;
    case SC_ASN1_NULL:
        buf = NULL;
        buflen = 0;
        break;
    case SC_ASN1_BOOLEAN:
        buf = malloc(1);
        if (buf == NULL) {
            r = SC_ERROR_OUT_OF_MEMORY;
            break;
        }
        buf[0] = *((int *) parm) ? 0xFF : 0;
        buflen = 1;
        break;
    case SC_ASN1_INTEGER:
    case SC_ASN1_ENUMERATED:
        r = asn1_encode_integer(*((int *) entry->parm), &buf, &buflen);
        break;
    case SC_ASN1_BIT_STRING_NI:
    case SC_ASN1_BIT_STRING:
        assert(len != NULL);
        if (entry->type == SC_ASN1_BIT_STRING)
            r = encode_bit_string((const u8 *) parm, *len, &buf, &buflen, 1);
        else
            r = encode_bit_string((const u8 *) parm, *len, &buf, &buflen, 0);
        break;
    case SC_ASN1_BIT_FIELD:
        assert(len != NULL);
        r = encode_bit_field((const u8 *) parm, *len, &buf, &buflen);
        break;
    case SC_ASN1_PRINTABLESTRING:
    case SC_ASN1_OCTET_STRING:
    case SC_ASN1_UTF8STRING:
        assert(len != NULL);
        buf = malloc(*len + 1);
        if (buf == NULL) {
            r = SC_ERROR_OUT_OF_MEMORY;
            break;
        }
        buflen = 0;
        /* If the integer is supposed to be unsigned, insert
 *          * a padding byte if the MSB is one */
        if ((entry->flags & SC_ASN1_UNSIGNED)
         && (((u8 *) parm)[0] & 0x80)) {
            buf[buflen++] = 0x00;
        }
        memcpy(buf + buflen, parm, *len);
        buflen += *len;
        break;
    case SC_ASN1_GENERALIZEDTIME:
        assert(len != NULL);
        buf = malloc(*len);
        if (buf == NULL) {
            r = SC_ERROR_OUT_OF_MEMORY;
            break;
        }
        memcpy(buf, parm, *len);
        buflen = *len;
        break;
    case SC_ASN1_OBJECT:
        r = sc_asn1_encode_object_id(&buf, &buflen, (struct sc_object_id *) parm);
        break;
    case SC_ASN1_PATH:
        r = asn1_encode_path((const sc_path_t *) parm, &buf, &buflen, depth, entry->flags);
        break;
    case SC_ASN1_PKCS15_ID:
        {
            const struct sc_pkcs15_id *id = (const struct sc_pkcs15_id *) parm;

            buf = malloc(id->len);
            if (buf == NULL) {
                r = SC_ERROR_OUT_OF_MEMORY;
                break;
            }
            memcpy(buf, id->value, id->len);
            buflen = id->len;
        }
        break;
    case SC_ASN1_PKCS15_OBJECT:
        r = asn1_encode_p15_object( (const struct sc_asn1_pkcs15_object *) parm, &buf, &buflen, depth);
        break;
    case SC_ASN1_ALGORITHM_ID:
        r = sc_asn1_encode_algorithm_id( &buf, &buflen, (const struct sc_algorithm_id *) parm, depth);
        break;
    case SC_ASN1_SE_INFO:
        if (!len)
            return SC_ERROR_INVALID_ASN1_OBJECT;
        r = asn1_encode_se_info( (struct sc_pkcs15_sec_env_info **)parm, *len, &buf, &buflen, depth);
        break;
    case SC_ASN1_CALLBACK:
        r = callback_func( entry->arg, &buf, &buflen, depth);
        break;
    default:
        sc_debug( SC_LOG_DEBUG_ASN1, "invalid ASN.1 type: %d\n", entry->type);
        return SC_ERROR_INVALID_ASN1_OBJECT;
    }
    if (r) {
        sc_debug(SC_LOG_DEBUG_ASN1, "encoding of ASN.1 object '%s' failed: %s\n", entry->name,
              sc_strerror(r));
        if (buf)
            free(buf);
        return r;
    }

    /* Treatment of OPTIONAL elements:
     *  -   if the encoding has 0 length, and the element is OPTIONAL,
     *  we don't write anything (unless it's an ASN1 NULL and the
     *      SC_ASN1_PRESENT flag is set).
     *  -   if the encoding has 0 length, but the element is non-OPTIONAL,
     *  constructed, we write a empty element (e.g. a SEQUENCE of
     *      length 0). In case of an ASN1 NULL just write the tag and
     *      length (i.e. 0x05,0x00).
     *  -   any other empty objects are considered bogus
     */
no_object:
    if (!buflen && entry->flags & SC_ASN1_OPTIONAL && !(entry->flags & SC_ASN1_PRESENT)) {
        /* This happens when we try to encode e.g. the
 *          * subClassAttributes, which may be empty */
        *obj = NULL;
        *objlen = 0;
        r = 0;
    } else if (!buflen && (entry->flags & SC_ASN1_EMPTY_ALLOWED)) {
        *obj = NULL;
        *objlen = 0;
        r = asn1_write_element(entry->tag, buf, buflen, obj, objlen);
        if (r)
            printf("error writing ASN.1 tag and length: %s\n", sc_strerror(r));
    } else if (buflen || entry->type == SC_ASN1_NULL || entry->tag & SC_ASN1_CONS) {
        r = asn1_write_element(entry->tag, buf, buflen, obj, objlen);
        if (r)
            printf( "error writing ASN.1 tag and length: %s\n",
                    sc_strerror(r));
    } else if (!(entry->flags & SC_ASN1_PRESENT)) {
        printf("cannot encode non-optional ASN.1 object: not given by caller\n");
        r = SC_ERROR_INVALID_ASN1_OBJECT;
    } else {
        printf("cannot encode empty non-optional ASN.1 object\n");
        r = SC_ERROR_INVALID_ASN1_OBJECT;
    }
    if (buf)
        free(buf);
    if (r >= 0)
        printf( "%*.*slength of encoded item=%u\n", depth, depth, "", *objlen);
    return r;
}

int asn1_encode(const struct sc_asn1_entry *asn1,
              u8 **ptr, size_t *size, int depth)
{
    int r, idx = 0;
    u8 *obj = NULL, *buf = NULL, *tmp;
    size_t total = 0, objsize;

    for (idx = 0; asn1[idx].name != NULL; idx++) {
        r = asn1_encode_entry(&asn1[idx], &obj, &objsize, depth);
        if (r) {
            if (obj)
                free(obj);
            if (buf)
                free(buf);
            return r;
        }
        /* in case of an empty (optional) element continue with
 *          * the next asn1 element */
        if (!objsize)
            continue;
        tmp = (u8 *) realloc(buf, total + objsize);
        if (!tmp) {
            if (obj)
                free(obj);
            if (buf)
                free(buf);
            return SC_ERROR_OUT_OF_MEMORY;
        }
        buf = tmp;
        memcpy(buf + total, obj, objsize);
        free(obj);
        obj = NULL;
        total += objsize;
    }
    *ptr = buf;
    *size = total;
    return 0;
}


int sc_asn1_decode_integer(const u8 * inbuf, size_t inlen, int *out) 
{
    int    a = 0;
    size_t i;

    if (inlen > sizeof(int))
        return SC_ERROR_INVALID_ASN1_OBJECT;
    if (inbuf[0] & 0x80)      
        a = -1;
    for (i = 0; i < inlen; i++) {  
        a <<= 8;
        a |= *inbuf++;        
    }  
    *out = a;
    return 0;
}

int sc_asn1_decode_utf8string(const u8 *inbuf, size_t inlen,
                  u8 *out, size_t *outlen)
{
    if (inlen+1 > *outlen)
        return SC_ERROR_BUFFER_TOO_SMALL;
    *outlen = inlen+1;
    memcpy(out, inbuf, inlen);
    out[inlen] = 0;
    return 0;
}

int sc_asn1_decode_object_id(const u8 *inbuf, size_t inlen, struct sc_object_id *id)
{
    int a;
    const u8 *p = inbuf;
    int *octet;

    if (inlen == 0 || inbuf == NULL || id == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;

    sc_init_oid(id);
    octet = id->value;

    a = *p;
    *octet++ = a / 40;
    *octet++ = a % 40;
    inlen--;

    while (inlen) {
        p++;
        a = *p & 0x7F;
        inlen--;
        while (inlen && *p & 0x80) {
            p++;
            a <<= 7;
            a |= *p & 0x7F;
            inlen--;
        }
        *octet++ = a;
        if (octet - id->value >= SC_MAX_OBJECT_ID_OCTETS)   {
            sc_init_oid(id);
            return SC_ERROR_INVALID_ASN1_OBJECT;
        }
    };

    return 0;
}

/*
 *  * Bitfields are just bit strings, stored in an unsigned int
 *   * (taking endianness into account)
 *    */    
int decode_bit_field(const u8 * inbuf, size_t inlen, void *outbuf, size_t outlen)
{
    u8      data[sizeof(unsigned int)];    
    unsigned int    field = 0;
    int     i, n;

    if (outlen != sizeof(data))    
        return SC_ERROR_BUFFER_TOO_SMALL;

    n = decode_bit_string(inbuf, inlen, data, sizeof(data), 1); 
    if (n < 0)
        return n;

    for (i = 0; i < n; i += 8) {   
        field |= (data[i/8] << i);     
    }  
    memcpy(outbuf, &field, outlen);
    return 0;
}

int decode_bit_string(const u8 * inbuf, size_t inlen, void *outbuf,                                                                                                                                                             
                 size_t outlen, int invert)                                                                                                                                                                                            
{
    const u8 *in = inbuf;
    u8 *out = (u8 *) outbuf;  
    int zero_bits = *in & 0x07;    
    size_t octets_left = inlen - 1;
    int i, count = 0;

    memset(outbuf, 0, outlen);
    in++;
    if (outlen < octets_left)
        return SC_ERROR_BUFFER_TOO_SMALL;
    if (inlen < 1)
        return SC_ERROR_INVALID_ASN1_OBJECT;
    while (octets_left) {
        /* 1st octet of input:  ABCDEFGH, where A is the MSB */
        /* 1st octet of output: HGFEDCBA, where A is the LSB */
        /* first bit in bit string is the LSB in first resulting octet */                                                                                                                                                              
        int bits_to_go;

        *out = 0;
        if (octets_left == 1)
            bits_to_go = 8 - zero_bits;
        else
            bits_to_go = 8;   
        if (invert)
            for (i = 0; i < bits_to_go; i++) { 
                *out |= ((*in >> (7 - i)) & 1) << i;                                                                                                                                                                                   
            }
        else {
            *out = *in;
        }
        out++;
        in++;
        octets_left--;
        count++;
    }  
    return (count * 8) - zero_bits;                                                                                                                                                                                                    
}

void format_asn1_entry(struct sc_asn1_entry *entry, void *parm, void *arg, 
              int set_present)
{
    entry->parm = parm;       
    entry->arg  = arg;
    if (set_present)
        entry->flags |= SC_ASN1_PRESENT;
}

void copy_asn1_entry(const struct sc_asn1_entry *src,
            struct sc_asn1_entry *dest)
{
    while (src->name != NULL) {
        *dest = *src;
        dest++;
        src++;
    }
    dest->name = NULL;
}

int asn1_decode_entry(struct sc_asn1_entry *entry,
                 const u8 *obj, size_t objlen, int depth)
{
    void *parm = entry->parm;
    int (*callback_func)(void *arg, const u8 *nobj,
                 size_t nobjlen, int ndepth);
    size_t *len = (size_t *) entry->arg;
    int r = 0;

    callback_func =(int (*)(void*, const u8*, size_t, int)) parm;

    printf("%*.*sdecoding '%s'\n", depth, depth, "", entry->name);

    switch (entry->type) {
    case SC_ASN1_STRUCT:
        if (parm != NULL)
            r = asn1_decode( (struct sc_asn1_entry *) parm, obj,
                       objlen, NULL, NULL, 0, depth + 1);
        break;
    case SC_ASN1_NULL:
        break;
    case SC_ASN1_BOOLEAN:
        if (parm != NULL) {
            if (objlen != 1) {
                printf("invalid ASN.1 object length: %lu\n", objlen);
                r = SC_ERROR_INVALID_ASN1_OBJECT;
            } else
                *((int *) parm) = obj[0] ? 1 : 0;
        }
        break;
    case SC_ASN1_INTEGER:
    case SC_ASN1_ENUMERATED:
        if (parm != NULL) {
            r = sc_asn1_decode_integer(obj, objlen, (int *) entry->parm);
            printf("%*.*sdecoding '%s' returned %d\n", depth, depth, "",
                    entry->name, *((int *) entry->parm));
        }
        break;
    case SC_ASN1_BIT_STRING_NI:
    case SC_ASN1_BIT_STRING:
        if (parm != NULL) {
            int invert = entry->type == SC_ASN1_BIT_STRING ? 1 : 0;
            if (objlen < 1) {
                r = SC_ERROR_INVALID_ASN1_OBJECT;
                break;
            }
            if (entry->flags & SC_ASN1_ALLOC) {
                u8 **buf = (u8 **) parm;
                *buf = (u8*)malloc(objlen-1);
                if (*buf == NULL) {
                    r = SC_ERROR_OUT_OF_MEMORY;
                    break;
                }
                *len = objlen-1;
                parm = *buf;
            }
            r = decode_bit_string(obj, objlen, (u8 *) parm, *len, invert);
            if (r >= 0) {
                *len = r;
                r = 0;
            }
        }
        break;
case SC_ASN1_BIT_FIELD:
        if (parm != NULL)
            r = decode_bit_field(obj, objlen, (u8 *) parm, *len);
        break;
    case SC_ASN1_OCTET_STRING:
        if (parm != NULL) {
            size_t c;

            /* Strip off padding zero */
            if ((entry->flags & SC_ASN1_UNSIGNED)
             && obj[0] == 0x00 && objlen > 1) {
                objlen--;
                obj++;
            }

            /* Allocate buffer if needed */
            if (entry->flags & SC_ASN1_ALLOC) {
                u8 **buf = (u8 **) parm;
                *buf = (u8*)malloc(objlen);
                if (*buf == NULL) {
                    r = SC_ERROR_OUT_OF_MEMORY;
                    break;
                }
                c = *len = objlen;
                parm = *buf;
            } else
                c = objlen > *len ? *len : objlen;
            memcpy(parm, obj, c);
            *len = c;
        }
        break;
    case SC_ASN1_GENERALIZEDTIME:
        if (parm != NULL) {
            size_t c;
            if (entry->flags & SC_ASN1_ALLOC) {
                u8 **buf = (u8 **) parm;
                *buf = (u8*)malloc(objlen);
                if (*buf == NULL) {
                    r = SC_ERROR_OUT_OF_MEMORY;
                    break;
                }
                c = *len = objlen;
                parm = *buf;
            } else
                c = objlen > *len ? *len : objlen;

            memcpy(parm, obj, c);
            *len = c;
        }
        break;
    case SC_ASN1_OBJECT:
        if (parm != NULL)
            r = sc_asn1_decode_object_id(obj, objlen, (struct sc_object_id *) parm);
        break;
    case SC_ASN1_PRINTABLESTRING:
    case SC_ASN1_UTF8STRING:
        if (parm != NULL) {
            if (entry->flags & SC_ASN1_ALLOC) {
                u8 **buf = (u8 **) parm;
                *buf = (u8*)malloc(objlen+1);
                if (*buf == NULL) {
                    r = SC_ERROR_OUT_OF_MEMORY;
                    break;
                }
                *len = objlen+1;
                parm = *buf;
            }
            r = sc_asn1_decode_utf8string(obj, objlen, (u8 *) parm, len);
            if (entry->flags & SC_ASN1_ALLOC) {
                *len -= 1;
            }
        }
        break;
    case SC_ASN1_PATH:
        if (entry->parm != NULL)
            r = asn1_decode_path(obj, objlen, (sc_path_t *) parm, depth);
        break;
    case SC_ASN1_PKCS15_ID:
        if (entry->parm != NULL) {
            struct sc_pkcs15_id *id = (struct sc_pkcs15_id *) parm;
            size_t c = objlen > sizeof(id->value) ? sizeof(id->value) : objlen;
            memcpy(id->value, obj, c);
            id->len = c;
        }
        break;
    case SC_ASN1_PKCS15_OBJECT:
        if (entry->parm != NULL)
            r = asn1_decode_p15_object( obj, objlen, (struct sc_asn1_pkcs15_object *) parm, depth);
        break;
    case SC_ASN1_ALGORITHM_ID:
        if (entry->parm != NULL)
            r = sc_asn1_decode_algorithm_id( obj, objlen, (struct sc_algorithm_id *) parm, depth);
        break;
    case SC_ASN1_SE_INFO:
        if (entry->parm != NULL)
            r = asn1_decode_se_info( obj, objlen, (sc_pkcs15_sec_env_info_t ***)entry->parm, len, depth);
        break;
    case SC_ASN1_CALLBACK:
        if (entry->parm != NULL)
            r = callback_func( entry->arg, obj, objlen, depth);
        break;
    default:
        printf("invalid ASN.1 type: %d\n", entry->type);
        return SC_ERROR_INVALID_ASN1_OBJECT;
    }
    if (r) {
        printf("decoding of ASN.1 object '%s' failed: %s\n", entry->name,
              sc_strerror(r));
        return r;
    }
    entry->flags |= SC_ASN1_PRESENT;
    return 0;
}

int asn1_decode(struct sc_asn1_entry *asn1,
                const u8 *in, size_t len, const u8 **newp, size_t *len_left,
                int choice, int depth)
{
    int r, idx = 0;           
    const u8 *p = in, *obj;   
    struct sc_asn1_entry *entry = asn1;
    size_t left = len, objlen;

    printf("%*.*scalled, left=%lu, depth %d\n",                                                                                                                                                             
                    depth, depth, "",          
                left, depth);                                                                                                                                                                                             

    if (left < 2) {           
        while (asn1->name && (asn1->flags & SC_ASN1_OPTIONAL))                                                                                                                                                                         
            asn1++;
        /* If all elements were optional, there's nothing
 *          * to complain about */        
        if (asn1->name == NULL)            
            return 0;         
        printf("End of ASN.1 stream, non-optional field \"%s\" not found\n",
                  asn1->name);
        return SC_ERROR_ASN1_OBJECT_NOT_FOUND;                                                                                                                                                                                         
    }  
    if (p[0] == 0 || p[0] == 0xFF || len == 0)
        return SC_ERROR_ASN1_END_OF_CONTENTS;                                                                                                                                                                                          

    for (idx = 0; asn1[idx].name != NULL; idx++) {
        entry = &asn1[idx];

        printf("Looking for '%s', tag 0x%x%s%s\n",
            entry->name, entry->tag, choice? ", CHOICE" : "",
            (entry->flags & SC_ASN1_OPTIONAL)? ", OPTIONAL": "");                                                                                                                                                                      

        /* Special case CHOICE has no tag */
        if (entry->type == SC_ASN1_CHOICE) { 
            r = asn1_decode( (struct sc_asn1_entry *) entry->parm,
                p, left, &p, &left, 1, depth + 1);
            if (r >= 0)
                r = 0;
            goto decode_ok;   
        }

        obj = sc_asn1_skip_tag( &p, &left, entry->tag, &objlen);                                                                                                                                                                   
        if (obj == NULL) {
            printf("not present\n");                                                                                                                                                                         
            if (choice)       
                continue;
            if (entry->flags & SC_ASN1_OPTIONAL)
                continue;     
            printf("mandatory ASN.1 object '%s' not found\n", entry->name);
            if (left) {
                u8 line[128], *linep = line;   
                size_t i;

                line[0] = 0;  
                for (i = 0; i < 10 && i < left; i++) {
                    sprintf((char *) linep, "%02X ", p[i]); 
                    linep += 3;                
                }
                printf("next tag: %s\n", line);
            }
            SC_FUNC_RETURN(SC_ERROR_ASN1_OBJECT_NOT_FOUND);
        }
        r = asn1_decode_entry( entry, obj, objlen, depth);

decode_ok:
        if (r)
            return r;
        if (choice)
            break;
    }
    if (choice && asn1[idx].name == NULL) /* No match */
        SC_FUNC_RETURN(SC_ERROR_ASN1_OBJECT_NOT_FOUND);
    if (newp != NULL)
        *newp = p;
    if (len_left != NULL)
        *len_left = left;
    if (choice)
        SC_FUNC_RETURN(idx);
    SC_FUNC_RETURN(0);
}

int asn1_decode_path(const u8 *in, size_t len,
                sc_path_t *path, int depth)                                                                                                                                                                                            
{
    int idx, count, r;
    struct sc_asn1_entry asn1_path_ext[3], asn1_path[5];
    unsigned char path_value[SC_MAX_PATH_SIZE], aid_value[SC_MAX_AID_SIZE];
    size_t path_len = sizeof(path_value), aid_len = sizeof(aid_value);                                                                                                                                                                 

    memset(path, 0, sizeof(struct sc_path));                                                                                                                                                                                           

    sc_copy_asn1_entry(c_asn1_path_ext, asn1_path_ext);
    sc_copy_asn1_entry(c_asn1_path, asn1_path);                                                                                                                                                                                        

    sc_format_asn1_entry(asn1_path_ext + 0, aid_value, &aid_len, 0);
    sc_format_asn1_entry(asn1_path_ext + 1, path_value, &path_len, 0);                                                                                                                                                                 

    sc_format_asn1_entry(asn1_path + 0, path_value, &path_len, 0);
    sc_format_asn1_entry(asn1_path + 1, &idx, NULL, 0);
    sc_format_asn1_entry(asn1_path + 2, &count, NULL, 0);
    sc_format_asn1_entry(asn1_path + 3, asn1_path_ext, NULL, 0);                                                                                                                                                                       

    r = asn1_decode(asn1_path, in, len, NULL, NULL, 0, depth + 1);                                                                                                                                                                
    if (r)
        return r;

    if (asn1_path[3].flags & SC_ASN1_PRESENT)   {
        /* extended path present: set 'path' and 'aid' */
        memcpy(path->aid.value, aid_value, aid_len); 
        path->aid.len = aid_len;                                                                                                                                                                                                       

        memcpy(path->value, path_value, path_len); 
        path->len = path_len; 
    }  
    else if (asn1_path[0].flags & SC_ASN1_PRESENT)   {
        /* path present: set 'path' */ 
        memcpy(path->value, path_value, path_len); 
        path->len = path_len; 
    }  
    else   {
        /* failed if both 'path' and 'pathExtended' are absent */
        return SC_ERROR_ASN1_OBJECT_NOT_FOUND;                                                                                                                                                                                         
    }  

    if (path->len == 2)
        path->type = SC_PATH_TYPE_FILE_ID;
    else   if (path->aid.len && path->len > 2)
        path->type = SC_PATH_TYPE_FROM_CURRENT;                                                                                                                                                                                        
    else
        path->type = SC_PATH_TYPE_PATH;                                                                                                                                                                                                

    if ((asn1_path[1].flags & SC_ASN1_PRESENT) && (asn1_path[2].flags & SC_ASN1_PRESENT)) {                                                                                                                                            
        path->index = idx;    
        path->count = count;  
    }  
    else {
        path->index = 0;      
        path->count = -1;
    }

    return SC_SUCCESS;
}

int asn1_decode_p15_object(const u8 *in,
                  size_t len, struct sc_asn1_pkcs15_object *obj,                                                                                                                                                                       
                  int depth)  
{
    struct sc_pkcs15_object *p15_obj = obj->p15_obj;
    struct sc_asn1_entry asn1_c_attr[6], asn1_p15_obj[5];
    struct sc_asn1_entry asn1_ac_rules[SC_PKCS15_MAX_ACCESS_RULES + 1], asn1_ac_rule[SC_PKCS15_MAX_ACCESS_RULES][3];                                                                                                                   
    size_t flags_len = sizeof(p15_obj->flags);
    size_t label_len = sizeof(p15_obj->label);
    size_t access_mode_len = sizeof(p15_obj->access_rules[0].access_mode);                                                                                                                                                             
    int r, ii;

    for (ii=0; ii<SC_PKCS15_MAX_ACCESS_RULES; ii++)
        sc_copy_asn1_entry(c_asn1_access_control_rule, asn1_ac_rule[ii]);
    sc_copy_asn1_entry(c_asn1_access_control_rules, asn1_ac_rules);                                                                                                                                                                    


    sc_copy_asn1_entry(c_asn1_com_obj_attr, asn1_c_attr);
    sc_copy_asn1_entry(c_asn1_p15_obj, asn1_p15_obj);
    sc_format_asn1_entry(asn1_c_attr + 0, p15_obj->label, &label_len, 0);
    sc_format_asn1_entry(asn1_c_attr + 1, &p15_obj->flags, &flags_len, 0);
    sc_format_asn1_entry(asn1_c_attr + 2, &p15_obj->auth_id, NULL, 0);
    sc_format_asn1_entry(asn1_c_attr + 3, &p15_obj->user_consent, NULL, 0);                                                                                                                                                            

    for (ii=0; ii<SC_PKCS15_MAX_ACCESS_RULES; ii++)   {
        sc_format_asn1_entry(asn1_ac_rule[ii] + 0, &p15_obj->access_rules[ii].access_mode, &access_mode_len, 0);
        sc_format_asn1_entry(asn1_ac_rule[ii] + 1, &p15_obj->access_rules[ii].auth_id, NULL, 0);
        sc_format_asn1_entry(asn1_ac_rules + ii, asn1_ac_rule[ii], NULL, 0);                                                                                                                                                           
    }  
    sc_format_asn1_entry(asn1_c_attr + 4, asn1_ac_rules, NULL, 0);                                                                                                                                                                     

    sc_format_asn1_entry(asn1_p15_obj + 0, asn1_c_attr, NULL, 0);
    sc_format_asn1_entry(asn1_p15_obj + 1, obj->asn1_class_attr, NULL, 0);
    sc_format_asn1_entry(asn1_p15_obj + 2, obj->asn1_subclass_attr, NULL, 0);
    sc_format_asn1_entry(asn1_p15_obj + 3, obj->asn1_type_attr, NULL, 0);                                                                                                                                                              

    r = asn1_decode( asn1_p15_obj, in, len, NULL, NULL, 0, depth + 1);                                                                                                                                                             
    return r;
}

