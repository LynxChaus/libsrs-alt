/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* (C)2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   hmac.h

   <no description>
*/


#define mHMAC_MAX_BLOCK_SIZE          64
#define mHMAC_MAX_HASH_LEN            20


/* Structures */

typedef struct mHMAC_DIGEST_s   {
    int             block_size;
    int             digest_length;
    int             digest_struct_size;
    int             (*DIGEST_start)(void *);
    int             (*DIGEST_block)(void *, unsigned char *);
    int             (*DIGEST_process)(void *, unsigned char *, int);
    int             (*DIGEST_end)(void *, unsigned char *);
} mHMAC_DIGEST;


typedef struct mHMAC_s   {
    char            secret[mHMAC_MAX_BLOCK_SIZE];
    char            hash[mHMAC_MAX_HASH_LEN];
    void           *digest_struct;
    mHMAC_DIGEST    *hmac_digest;
} mHMAC;



/* Function Prototypes */

int mHMAC_start(mHMAC *hmac, mHMAC_DIGEST *hmac_digest, char *secret, int secret_len);
int mHMAC_process(mHMAC *hmac, unsigned char *data, int data_len);
int mHMAC_end(mHMAC *hmac, unsigned char *hash_buffer);
int mHMAC_gethash(mHMAC *hmac, unsigned char *hash_buffer);

