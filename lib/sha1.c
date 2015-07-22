/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* (C)2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   sha1.c

   Perform SHA1
*/

#include <string.h>

#include "sha1.h"


/* mHMAC Structure */

mHMAC_DIGEST mHMACD_SHA1 = {
    64,
    20,
    sizeof(mSHA1),
    mSHA1_start,
    mSHA1_block,
    mSHA1_process,
    mSHA1_end
};


/***********************************************************
    mSHA1_start - Init SHA1 structure

*/

int mSHA1_start(mSHA1 *sha1)
{
    sha1->len = 0;
    sha1->blen = 0;
    sha1->H[0] = 0x67452301;
    sha1->H[1] = 0xEFCDAB89;
    sha1->H[2] = 0x98BADCFE;
    sha1->H[3] = 0x10325476;
    sha1->H[4] = 0xC3D2E1F0;

    return 0;
}


/***********************************************************
    mSHA1_block - Process 512-bit block

*/

int mSHA1_block(mSHA1 *sha1, unsigned char *block)
{
    u_int32_t A, B, C, D, E;
    u_int32_t W[80];
    int t;

    // Compute Ws
    for(t = 0; t < 16; t++)
    {
        W[t] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]; // Ensure byte order
        block += 4;
    }
    for(t = 16; t < 80; t++)
    {
        register u_int32_t X = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
        W[t] = (X << 1) | (X >> 31);
    }

    A = sha1->H[0];
    B = sha1->H[1];
    C = sha1->H[2];
    D = sha1->H[3];
    E = sha1->H[4];

    // Digest (in 4 runs for different f-functions/K-values)
    for(t = 0; t < 20; t++)
    {
        register u_int32_t TEMP = ((A << 5) | (A >> 27)) + ((B & C) | ((~B) & D)) + E + W[t] + 0x5A827999;
        E = D;
        D = C;
        C = (B << 30) | (B >> 2);
        B = A;
        A = TEMP;
    }
    for(; t < 40; t++)
    {
        register u_int32_t TEMP = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W[t] + 0x6ED9EBA1;
        E = D;
        D = C;
        C = (B << 30) | (B >> 2);
        B = A;
        A = TEMP;
    }
    for(; t < 60; t++)
    {
        register u_int32_t TEMP = ((A << 5) | (A >> 27)) + ((B & C) | (B & D) | (C & D)) + E + W[t] + 0x8F1BBCDC;
        E = D;
        D = C;
        C = (B << 30) | (B >> 2);
        B = A;
        A = TEMP;
    }
    for(; t < 80; t++)
    {
        register u_int32_t TEMP = ((A << 5) | (A >> 27)) + (B ^ C ^ D) + E + W[t] + 0xCA62C1D6;
        E = D;
        D = C;
        C = (B << 30) | (B >> 2);
        B = A;
        A = TEMP;
    }

    // Update hash
    sha1->H[0] += A;
    sha1->H[1] += B;
    sha1->H[2] += C;
    sha1->H[3] += D;
    sha1->H[4] += E;

    return 0;
}


/***********************************************************
    mSHA1_process - Add a string to hash

*/
int mSHA1_process(mSHA1 *sha1, unsigned char *data, int data_len)
{
    int b, n = 0;

    // Fulfill buffered data obligations
    if(sha1->blen)
    {
        b = 64 - sha1->blen;
        if(b > data_len)
        {
            // Just add data to buffer and return
            memcpy(&sha1->b[sha1->blen], data, data_len);
            sha1->blen += data_len;
            return 0;
        }
        else
        {
            // Fill buffer and process block
            memcpy(&sha1->b[sha1->blen], data, b);
            n += b;
            mSHA1_block(sha1, sha1->b);
        }
    }

    // Go until we don't have a full block
    while(data_len - n >= 64)
    {
        mSHA1_block(sha1, &data[n]);
        sha1->len += 512;
        n += 64;
    }

    // copy remaining data to buffer
    sha1->blen = data_len - n;
    memcpy(sha1->b, &data[n], sha1->blen);

    return 0;
}


/***********************************************************
    mSHA1_end - Finalise hash

*/
int mSHA1_end(mSHA1 *sha1, unsigned char *hash_buffer)
{
    // sha1->blen should _NEVER_ be 64
    sha1->b[sha1->blen] = 0x80;

    // Calculate final length
    sha1->len += sha1->blen << 3;

    // Pad remaining data
    if(sha1->blen > 55)
    {
        memset(&sha1->b[sha1->blen+1], 0, 63 - sha1->blen);
        mSHA1_block(sha1, sha1->b);

        memset(sha1->b, 0, 56);
    }
    else
        memset(&sha1->b[sha1->blen+1], 0, 55 - sha1->blen);

    // Add length (ensuring byte order)
    sha1->b[56] = (sha1->len >> 56) & 0xFF;
    sha1->b[57] = (sha1->len >> 48) & 0xFF;
    sha1->b[58] = (sha1->len >> 40) & 0xFF;
    sha1->b[59] = (sha1->len >> 32) & 0xFF;
    sha1->b[60] = (sha1->len >> 24) & 0xFF;
    sha1->b[61] = (sha1->len >> 16) & 0xFF;
    sha1->b[62] = (sha1->len >> 8) & 0xFF;
    sha1->b[63] = sha1->len & 0xFF;

    // Process final block
    mSHA1_block(sha1, sha1->b);

    // Get hash
    if(hash_buffer)
        mSHA1_gethash(sha1, hash_buffer);

    return 0;
}


/***********************************************************
    mSHA1_gethash - Get hash string (fills 20 bytes)

*/
int mSHA1_gethash(mSHA1 *sha1, unsigned char *hash_buffer)
{
    int n;

    for(n = 0; n < 5; n++)
    {
        *hash_buffer++ = (sha1->H[n] >> 24) & 0xFF;
        *hash_buffer++ = (sha1->H[n] >> 16) & 0xFF;
        *hash_buffer++ = (sha1->H[n] >> 8) & 0xFF;
        *hash_buffer++ = sha1->H[n] & 0xFF;
    }

    return 0;
}


