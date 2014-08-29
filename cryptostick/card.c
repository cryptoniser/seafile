/*
 * NOTICE: This file is a modified version of the original OpenSC card.c

 * card.c: General smart card functions
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
#include "iso7816.h"
#include "openpgp.h"
#include "pcsc-wrapper.h"
#include "card.h"

/* ABI: initialize driver */
int card_init(card_t *card)
{
    struct pgp_priv_data *priv;  
    sc_path_t   aid;
    sc_file_t   *file = NULL;
    int r;
    priv = (struct pgp_priv_data*)calloc (1, sizeof(struct pgp_priv_data));
    if (!priv)
        return SC_ERROR_OUT_OF_MEMORY;

    card->drv_data = priv;
    card->cla = 0x00;

    sc_format_path("D276:0001:2401", &aid);
    aid.type = SC_PATH_TYPE_DF_NAME;
    if ((r = iso7816_select_file(card, &aid, &file)) < 0) {
        LOG_FUNC_RETURN(r);
        pgp_finish(card);
        return r;
    }

    /* read information from AID */
    if (file && file->namelen == 16) {
        /* OpenPGP card spec 1.1 & 2.0, section 4.2.1 & 4.1.2.1 */
        priv->bcd_version = bebytes2ushort(file->name + 6);
        /* kludge: get card's serial number from manufacturer ID + serial number */
        memcpy(card->serialnr.value, file->name + 8, 6);
        card->serialnr.len = 6;
    }

    return SC_SUCCESS;
}


static card_t * card_new()
{
    card_t *card;

    card = (card_t*)calloc(1, sizeof(card_t));
    if (card == NULL)
        return NULL;

    return card;
}

static void card_free(card_t *card)                                                                                                                                                                                              
{
    sc_mem_clear(card, sizeof(*card));
    free(card);
}


int connect_card(sc_reader_t *reader, card_t **card_out)                                                                                                                                                                         
{
    card_t *card;
    struct sc_card_driver *driver; 
    int i, r = 0, idx, connected = 0;                                                                                                                                                                                                  

    if (card_out == NULL || reader == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;

    printf("%s %d\n",__FILE__, __LINE__);
    card = card_new();
    if (card == NULL)
        LOG_FUNC_RETURN(SC_ERROR_OUT_OF_MEMORY);

    r = pcsc_connect(reader); 
    if (r!=SC_SUCCESS)
        goto err;

    connected = 1;
    card->reader = reader;

    memcpy(&card->atr, &reader->atr, sizeof(card->atr));                                                                                                                                                                               

    _sc_parse_atr(reader);

    /* See if the ATR matches any ATR specified in the config file */
/*    if ((driver = ctx->forced_driver) == NULL) {
        printf("matching configured ATRs");
        for (i = 0; ctx->card_drivers[i] != NULL; i++) {
            driver = ctx->card_drivers[i];                                                                                                                                                                                             

            if (driver->atr_map == NULL ||     
                !strcmp(driver->short_name, "default")) {
                driver = NULL;
                continue;
            }
            printf("trying driver '%s'", driver->short_name);
            idx = _sc_match_atr(card, driver->atr_map, NULL);                                                                                                                                                                          
            if (idx >= 0) {
                struct sc_atr_table *src = &driver->atr_map[idx];                                                                                                                                                                      

                printf("matched driver '%s'", driver->name);
                /* It's up to card driver to notice these correctly */                                                                                                                                                                 
  /*              card->name = src->name;        
                card->type = src->type;        
                card->flags = src->flags;      
                break;
            }
            driver = NULL;
        }
    }
*/
//    if (driver != NULL) {
        /* Forced driver, or matched via ATR mapping from                                                                                                                                                                              
 *          * config file */
//        card->driver = driver;
        r = pgp_init(card);     
        if (r) {
            printf("pgp_init() failed: %s\n", sc_strerror(r));
            goto err;
        }        
//    }
/*    else {
        printf(ctx, "matching built-in ATRs");
        for (i = 0; ctx->card_drivers[i] != NULL; i++) {
            struct sc_card_driver *drv = ctx->card_drivers[i];
            const struct card_operations *ops = drv->ops;

            printf(ctx, "trying driver '%s'", drv->short_name);
            if (ops == NULL || ops->match_card == NULL)   {
                continue;
            }
            else if (!ctx->enable_default_driver && !strcmp("default", drv->short_name))   {
                printf(ctx , "ignore 'default' card driver");
                continue;
            }

            /* Needed if match_card() needs to talk with the card (e.g. card-muscle) */
/*            *card->ops = *ops;
            if (ops->match_card(card) != 1)
                continue;
            printf(ctx, "matched: %s", drv->name);
            memcpy(card->ops, ops, sizeof(struct sc_card_operations));
            card->driver = drv;
            r = ops->init(card);
            if (r) {
                printf(ctx, "driver '%s' init() failed: %s", drv->name, sc_strerror(r));
                if (r == SC_ERROR_INVALID_CARD) {
                    card->driver = NULL;
                    continue;
                }
                goto err;
            }
            break;
        }
    }
*/
/*    if (card->driver == NULL) {
        printf(ctx, "unable to find driver for inserted card");
        r = SC_ERROR_INVALID_CARD;
        goto err;
    }
    if (card->name == NULL)
        card->name = card->driver->name;
    *card_out = card;
*/

        /*  Override card limitations with reader limitations.
 *           *  Note that zero means no limitations at all.
 *                */

    *card_out = card;
        // Taken from 'opensc.conf.in'
        card->max_send_size = 255;
        card->max_recv_size = 256;

    printf("card info name:'%s', flags:0x%lX, max_send/recv_size:%li/%li\n",
        card->name,  card->flags, card->max_send_size, card->max_recv_size);

    LOG_FUNC_RETURN(SC_SUCCESS);
err:
    if (connected)
        pcsc_disconnect(reader);
    if (card != NULL)
        card_free(card);
    LOG_FUNC_RETURN(r);
}
