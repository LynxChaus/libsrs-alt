/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   timestamp.c

   <no description>
*/

#include <string.h>

#include "hash.h"
#include "address.h"



/***********************************************************
    srs__hash

*/

srs_result srs__hash(srs_t *srs, int secret_no, char *data, uint data_len, char *md, uint *md_len)
{
    mHMAC hmac;
   
    if(secret_no < 0 || secret_no > srs->no_secrets)
        mHMAC_start(&hmac, &mHMACD_SHA1, srs->secret, srs->secret_len);
    else
        mHMAC_start(&hmac, &mHMACD_SHA1, srs->secrets[secret_no].secret, srs->secrets[secret_no].secret_len);
    mHMAC_process(&hmac, data, data_len);
    mHMAC_end(&hmac, md);

    *md_len = 20;

    return SRS_RESULT_OK;
}


/***********************************************************
    srs__hash_verify

*/

srs_result srs__hash_verify(srs_t *srs, char *data, uint data_len, char *hash, uint hash_len)
{
    char buf[128];
    char md[mHMAC_MAX_HASH_LEN];
    uint n;
    int m;

    if(hash_len < srs->hash_min)
        return SRS_RESULT_HASHTOOSHORT;

    for(m = -1; m < (signed)srs->no_secrets; m++)
    {
        // Perform hash
        srs__hash(srs, m, data, data_len, md, &n);

        // Base64 encode it
        srs__base64enc(md, n, buf, 128);

        if(strncmp(buf, hash, hash_len) == 0)
            return SRS_RESULT_OK;
        if(strncasecmp(buf, hash, hash_len) == 0)
            return SRS_RESULT_CASEBROKEN;
    }

    return SRS_RESULT_FAIL;
}

