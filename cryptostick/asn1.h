/*
 * NOTICE: This file is a modified version of the original OpenSC apdu.c
 *
 * asn1.h: ASN.1 header file
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


#ifndef ASN1_H
#define ASN1_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "cryptostick/cs-common.h"

#define SC_ASN1_CLASS_MASK      0x30000000
#define SC_ASN1_UNI         0x00000000 /* Universal */
#define SC_ASN1_APP         0x10000000 /* Application */
#define SC_ASN1_CTX         0x20000000 /* Context */
#define SC_ASN1_PRV         0x30000000 /* Private */
#define SC_ASN1_CONS            0x01000000

#define SC_ASN1_TAG_MASK        0x00FFFFFF

#define SC_ASN1_PRESENT         0x00000001
#define SC_ASN1_OPTIONAL        0x00000002
#define SC_ASN1_ALLOC           0x00000004
#define SC_ASN1_UNSIGNED        0x00000008
#define SC_ASN1_EMPTY_ALLOWED           0x00000010

#define SC_ASN1_BOOLEAN                 1
#define SC_ASN1_INTEGER                 2
#define SC_ASN1_BIT_STRING              3
#define SC_ASN1_BIT_STRING_NI           128
#define SC_ASN1_OCTET_STRING            4
#define SC_ASN1_NULL                    5
#define SC_ASN1_OBJECT                  6
#define SC_ASN1_ENUMERATED              10
#define SC_ASN1_UTF8STRING              12
#define SC_ASN1_SEQUENCE                16
#define SC_ASN1_SET                     17
#define SC_ASN1_PRINTABLESTRING         19
#define SC_ASN1_UTCTIME                 23
#define SC_ASN1_GENERALIZEDTIME         24

/* internal structures */
#define SC_ASN1_STRUCT          129
#define SC_ASN1_CHOICE          130
#define SC_ASN1_BIT_FIELD       131 /* bit string as integer */

/* 'complex' structures */
#define SC_ASN1_PATH            256
#define SC_ASN1_PKCS15_ID       257
#define SC_ASN1_PKCS15_OBJECT       258
#define SC_ASN1_ALGORITHM_ID        259
#define SC_ASN1_SE_INFO         260

/* use callback function */
#define SC_ASN1_CALLBACK        384

#define SC_ASN1_TAG_CLASS       0xC0
#define SC_ASN1_TAG_UNIVERSAL       0x00
#define SC_ASN1_TAG_APPLICATION     0x40
#define SC_ASN1_TAG_CONTEXT     0x80
#define SC_ASN1_TAG_PRIVATE     0xC0

#define SC_ASN1_TAG_CONSTRUCTED     0x20
#define SC_ASN1_TAG_PRIMITIVE       0x1F

#define SC_ASN1_TAG_EOC         0
#define SC_ASN1_TAG_BOOLEAN     1
#define SC_ASN1_TAG_INTEGER     2
#define SC_ASN1_TAG_BIT_STRING      3
#define SC_ASN1_TAG_OCTET_STRING    4
#define SC_ASN1_TAG_NULL        5
#define SC_ASN1_TAG_OBJECT      6
#define SC_ASN1_TAG_OBJECT_DESCRIPTOR   7
#define SC_ASN1_TAG_EXTERNAL        8
#define SC_ASN1_TAG_REAL        9
#define SC_ASN1_TAG_ENUMERATED      10
#define SC_ASN1_TAG_UTF8STRING      12
#define SC_ASN1_TAG_SEQUENCE        16
#define SC_ASN1_TAG_SET         17
#define SC_ASN1_TAG_NUMERICSTRING   18
#define SC_ASN1_TAG_PRINTABLESTRING 19
#define SC_ASN1_TAG_T61STRING       20
#define SC_ASN1_TAG_TELETEXSTRING   20
#define SC_ASN1_TAG_VIDEOTEXSTRING  21
#define SC_ASN1_TAG_IA5STRING       22
#define SC_ASN1_TAG_UTCTIME     23
#define SC_ASN1_TAG_GENERALIZEDTIME 24
#define SC_ASN1_TAG_GRAPHICSTRING   25
#define SC_ASN1_TAG_ISO64STRING     26
#define SC_ASN1_TAG_VISIBLESTRING   26
#define SC_ASN1_TAG_GENERALSTRING   27
#define SC_ASN1_TAG_UNIVERSALSTRING 28
#define SC_ASN1_TAG_BMPSTRING       30


struct sc_asn1_entry {
    const char *name;
    unsigned int type;
    unsigned int tag;
    unsigned int flags;
    void *parm;
    void *arg;
};

/*
int sc_asn1_decode_integer(const u8 * inbuf, size_t inlen, int *out);

int sc_asn1_decode_utf8string(const u8 *inbuf, size_t inlen,
                  u8 *out, size_t *outlen);

int sc_asn1_decode_object_id(const u8 *inbuf, size_t inlen, struct sc_object_id *id);

int decode_bit_field(const u8 * inbuf, size_t inlen, void *outbuf, size_t outlen);

int decode_bit_string(const u8 * inbuf, size_t inlen, void *outbuf,                                                                                                                                                             
                 size_t outlen, int invert);
*/

int asn1_encode(const struct sc_asn1_entry *asn1,
              u8 **ptr, size_t *size, int depth);

void format_asn1_entry(struct sc_asn1_entry *entry, void *parm, void *arg, 
              int set_present);


void copy_asn1_entry(const struct sc_asn1_entry *src,
            struct sc_asn1_entry *dest);

/*
int asn1_decode_entry(struct sc_asn1_entry *entry,
                 const u8 *obj, size_t objlen, int depth);

int asn1_decode(struct sc_asn1_entry *asn1,
                const u8 *in, size_t len, const u8 **newp, size_t *len_left,
                int choice, int depth);

int asn1_decode_path(const u8 *in, size_t len,
                sc_path_t *path, int depth);

int asn1_decode_p15_object(const u8 *in,
                  size_t len, struct sc_asn1_pkcs15_object *obj,                                                                                                                                                                       
                  int depth);
*/

#ifdef __cplusplus
}
#endif

#endif // ASN1_H
