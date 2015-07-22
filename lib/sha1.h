/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* (C)2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   sha1.h

   <no description>
*/

#include <sys/types.h>

#include "hmac.h"


/* Structures */

typedef struct mSHA1_s   {
    unsigned long long  len;
    unsigned int        blen;
    unsigned char       b[64];
             u_int32_t  H[5];
} mSHA1;


/* HMAC Declaration */

extern mHMAC_DIGEST mHMACD_SHA1;


/* Function Prototypes */

int mSHA1_start(mSHA1 *sha1);
int mSHA1_block(mSHA1 *sha1, unsigned char *block);
int mSHA1_process(mSHA1 *sha1, unsigned char *data, int data_len);
int mSHA1_end(mSHA1 *sha1, unsigned char *hash_buffer);
int mSHA1_gethash(mSHA1 *sha1, unsigned char *hash_buffer);

