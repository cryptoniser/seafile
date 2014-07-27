#ifndef OPENPGP_H
#define OPENPGP_H


enum _type {        /* DO type */
    SIMPLE      = SC_FILE_TYPE_WORKING_EF,
    CONSTRUCTED = SC_FILE_TYPE_DF
};


enum _version {     /* 2-byte BCD-alike encoded version number */
    OPENPGP_CARD_1_0 = 0x0100,
    OPENPGP_CARD_1_1 = 0x0101,
    OPENPGP_CARD_2_0 = 0x0200
};

enum _access {      /* access flags for the respective DO/file */
    READ_NEVER   = 0x0010,
    READ_PIN1    = 0x0011,
    READ_PIN2    = 0x0012,
    READ_PIN3    = 0x0014,
    READ_ALWAYS  = 0x0018,
    READ_MASK    = 0x00FF,
    WRITE_NEVER  = 0x1000,
    WRITE_PIN1   = 0x1100,
    WRITE_PIN2   = 0x1200,
    WRITE_PIN3   = 0x1400,
    WRITE_ALWAYS = 0x1800,
    WRITE_MASK   = 0x1F00
};


struct do_info {
    unsigned int    id;     /* ID of the DO in question */

    enum _type  type;       /* constructed DO or not */
    enum _access    access;     /* R/W access levels for the DO */

    /* function to get the DO from the card:
 *  *      * only != NULL is DO if readable and not only a part of a constructed DO */
    int     (*get_fn)(card_t *, unsigned int, u8 *, size_t);
    /* function to write the DO to the card:
 *  *      * only != NULL if DO is writeable under some conditions */
    int     (*put_fn)(card_t *, unsigned int, const u8 *, size_t);
};


struct blob {
    struct blob *   next;   /* pointer to next sibling */
    struct blob *   parent; /* pointer to parent */
    struct do_info *info;     

    sc_file_t * file;         
    unsigned int    id;
    int     status;           

    unsigned char * data;     
    unsigned int    len;
    struct blob *   files;  /* pointer to 1st child */                                                                                                                                                                                 
};

enum _card_state {
    CARD_STATE_UNKNOWN        = 0x00,
    CARD_STATE_INITIALIZATION = 0x03,
    CARD_STATE_ACTIVATED      = 0x05
};

enum _ext_caps {    /* extended capabilities/features */
    EXT_CAP_ALG_ATTR_CHANGEABLE = 0x0004,
    EXT_CAP_PRIVATE_DO          = 0x0008,
    EXT_CAP_C4_CHANGEABLE       = 0x0010,
    EXT_CAP_KEY_IMPORT          = 0x0020,
    EXT_CAP_GET_CHALLENGE       = 0x0040,
    EXT_CAP_SM                  = 0x0080,
    EXT_CAP_CHAINING            = 0x1000,
    EXT_CAP_APDU_EXT            = 0x2000
};

struct pgp_priv_data {
    struct blob *       mf;
    struct blob *       current;    /* currently selected file */

    enum _version       bcd_version;
  struct do_info      *pgp_objects;

    enum _card_state    state;      /* card state */   
    enum _ext_caps      ext_caps;   /* extended capabilities */

    size_t          max_challenge_size;
    size_t          max_cert_size; 

//    sc_security_env_t   sec_env;
};


int pgp_init(card_t *card);
int pgp_get_data(card_t *card, unsigned int tag, u8 *buf, size_t buf_len);
int pgp_finish(card_t *card);
int pgp_pin_cmd(card_t *card, struct sc_pin_cmd_data *data, int *tries_left);
int pgp_get_pubkey_pem(card_t *card, unsigned int tag, u8 *buf, size_t buf_len);

#endif // OPENPGP_H
