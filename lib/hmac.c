/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* (C)2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   hmac.c

   Perform HMAC
*/


#include <stdlib.h>
#include <string.h>

#include "hmac.h"




/***********************************************************
    mHMAC_start - Init HMAC structure and start DIGEST

*/

int mHMAC_start(mHMAC *hmac, mHMAC_DIGEST *hmac_digest, char *secret, int secret_len)
{
    char ipad[mHMAC_MAX_BLOCK_SIZE];
    int n;

    if(!hmac_digest)
        return -1;

    // Setup hmac
    hmac->hmac_digest = hmac_digest;
    hmac->digest_struct = malloc(hmac_digest->digest_struct_size);

    // Compile secret
    if(secret_len > hmac_digest->block_size)
    {
        // Digest the secret because it's too long
        hmac_digest->DIGEST_start(hmac->digest_struct);
        hmac_digest->DIGEST_process(hmac->digest_struct, secret, secret_len);
        hmac_digest->DIGEST_end(hmac->digest_struct, hmac->secret);
        memset(hmac->secret + hmac_digest->digest_length, 0, hmac_digest->block_size - hmac_digest->digest_length);
    }
    else
    {
        memcpy(hmac->secret, secret, secret_len);
        memset(hmac->secret + secret_len, 0, hmac_digest->block_size - secret_len);
    }

    // Start DIGEST, beginning with compiled secret XORed with 0x36
    memcpy(ipad, hmac->secret, hmac_digest->block_size);
    for(n = 0; n < hmac_digest->block_size; n++)
        ipad[n] ^= 0x36;

    hmac_digest->DIGEST_start(hmac->digest_struct);
    hmac_digest->DIGEST_process(hmac->digest_struct, ipad, hmac_digest->block_size);
        
    return 0;
}


/***********************************************************
    mHMAC_process - Add a string to hash

*/

int mHMAC_process(mHMAC *hmac, unsigned char *data, int data_len)
{
    return hmac->hmac_digest->DIGEST_process(hmac->digest_struct, data, data_len);
}


/***********************************************************
    mHMAC_end - Finalise hash

*/

int mHMAC_end(mHMAC *hmac, unsigned char *hash_buffer)
{
    char opad[mHMAC_MAX_BLOCK_SIZE];
    int n;

    hmac->hmac_digest->DIGEST_end(hmac->digest_struct, hmac->hash);

    // Start second DIGEST, beginning with compiled secret XORed with 0x5C
    memcpy(opad, hmac->secret, hmac->hmac_digest->block_size);
    for(n = 0; n < hmac->hmac_digest->block_size; n++)
        opad[n] ^= 0x5C;

    hmac->hmac_digest->DIGEST_start(hmac->digest_struct);
    hmac->hmac_digest->DIGEST_process(hmac->digest_struct, opad, hmac->hmac_digest->block_size);

    // Append our first hash
    hmac->hmac_digest->DIGEST_process(hmac->digest_struct, hmac->hash, hmac->hmac_digest->digest_length);

    // And finish
    hmac->hmac_digest->DIGEST_end(hmac->digest_struct, hmac->hash);

    if(hash_buffer)
        mHMAC_gethash(hmac, hash_buffer);

    return 0;
}


/***********************************************************
    mHMAC_gethash - Get hash string

*/

int mHMAC_gethash(mHMAC *hmac, unsigned char *hash_buffer)
{
    memcpy(hash_buffer, hmac->hash, hmac->hmac_digest->digest_length);

    return 0;
}


