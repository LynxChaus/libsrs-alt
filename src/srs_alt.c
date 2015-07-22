/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* (C)2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   srs_alt.c

   <no description>
*/

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "srs_alt.h"
#include "address.h"
#include "timestamp.h"
#include "hash.h"



/***********************************************************
    srs_open - open a srs handle

*/

srs_t *srs_open(char *secret, uint secret_len, uint max_age, uint hash_len, uint hash_min)
{
    srs_t *srs;

    // Minimum requirement - we must have a valid secret
    if(secret == NULL)
        return NULL;
    if(secret_len < SRS_MIN_SECRET_LENGTH || secret_len > SRS_MAX_SECRET_LENGTH)
        return NULL;
    if(strnlen(secret, SRS_MAX_SECRET_LENGTH) < SRS_MIN_SECRET_LENGTH)
        return NULL;

    // Allocate some memory
    if((srs = (srs_t *)malloc(sizeof(srs_t))) == NULL)
        return NULL;

    // Fill in with our params and/or defaults
    memcpy(srs->secret, secret, secret_len);
    srs->secret_len = secret_len;

    if(max_age)
        srs->max_age = max_age;
    else
        srs->max_age = SRS_DEFAULT_MAX_AGE;

    if(hash_len)
        srs->hash_len = hash_len;
    else
        srs->hash_len = (hash_min > SRS_DEFAULT_HASH_LEN ? hash_min : SRS_DEFAULT_HASH_LEN);

    if(hash_min)
        srs->hash_min = hash_min;
    else
        srs->hash_min = (hash_len < SRS_DEFAULT_HASH_MIN ? hash_len : SRS_DEFAULT_HASH_MIN);

    // Defaults
    srs->sep = '=';
    srs->use_timestamp = 1;
    srs->use_hash = 1;
    srs->use_db = 0;
    srs->db_insert = NULL;
    srs->db_lookup = NULL;

    srs->no_secrets = 0;
    srs->secrets = NULL;
    srs->secrets_alloc = 0;

    return srs;
}


/***********************************************************
    srs_set_separator - change SRS separator

    (can only be one of '=', '+' or '-')

*/

srs_result srs_set_separator(srs_t *srs, char separator)
{
    if(!(separator == '=' || separator == '+' || separator == '-'))
        return SRS_RESULT_BADPARAM;

    srs->sep = separator;

    return SRS_RESULT_OK;
}


/***********************************************************
    srs_close - close a srs handle

*/

srs_result srs_close(srs_t *srs)
{
    free(srs);

    return SRS_RESULT_OK;
}


/***********************************************************
    srs_forward - create a return-path

*/

srs_result srs_forward(srs_t *srs, char *orig_sender, char *return_domain,
        char *return_path, uint return_path_len)
{
    uint osl, osd, rdl, rdd, n, r, lp_cut, sz, lbp;
    int mode;
    char ts[2];
    char buf[SRS_MAX_ADDRESS_LENGTH+1];
    char lbuf[SRS_MAX_ADDRESS_LENGTH+1];
    char md[mHMAC_MAX_HASH_LEN];

    if(!srs)
        return SRS_RESULT_BADHANDLE;

    // Split up original sender and do some basic validation
    if((osd = srs__get_domain_start(orig_sender)) < 0)
        return SRS_RESULT_BADPARAM;
    osl = strnlen(orig_sender, SRS_MAX_ADDRESS_LENGTH);
    if(osd < 2 || osd >= osl)
        return SRS_RESULT_BADPARAM;

    if((rdd = srs__get_domain_start(return_domain)) != 0)
        return SRS_RESULT_BADPARAM;
    rdl = strnlen(return_domain, SRS_MAX_ADDRESS_LENGTH);
    if(rdd >= rdl)
        return SRS_RESULT_BADPARAM;

    // Check if orig_sender is already an SRS address
    mode = 0;
    if(orig_sender[4] == '=' || orig_sender[4] == '+' || orig_sender[4] == '-')
    {
        if(strncasecmp(orig_sender, "SRS1", 4) == 0)
        {
            mode = 2;
            lp_cut = 5;
            while(orig_sender[lp_cut] != '=' && lp_cut < osd)
                lp_cut++;
            if(orig_sender[lp_cut] != '=')
                return SRS_RESULT_BADSRS;
            lp_cut++;
        }
        else if(strncasecmp(orig_sender, "SRS0", 4) == 0)
        {
            mode = 1;
            lp_cut = 4;
        }
    }

    // Now generate SRS data
    lbp = 0;
    if(mode == 0)
    {
        // Create hash data (even if no hash needed, we still need the data)
        if(srs->use_timestamp)
        {
            // SRS0 uses a timestamp (unless turned off)
            srs_timestamp_create(time(NULL), ts);

            strncpy(buf, ts, 2);
            buf[2] = 0;
            strncat(buf, "=", 1);
            sz = 3;

            lbp += strncpytolower(&lbuf[lbp], buf, 2);
        }
        else
        {
            buf[0] = 0;
            sz = 0;
        }

        // Check for db
        if(srs->use_db)
        {
            // Use db id instead of address data
            if(!srs->db_insert)
                return SRS_RESULT_DBERROR;

            if((r = srs->db_insert(srs, orig_sender, osl, &buf[sz], SRS_MAX_ADDRESS_LENGTH - sz)) & SRS_RESULT_FAIL)
                return r;

            lbp += strncpytolower(&lbuf[lbp], &buf[sz], SRS_MAX_ADDRESS_LENGTH - sz);
        }
        else
        {
            // Use SRS address format
            if(osl + sz + 1 > SRS_MAX_ADDRESS_LENGTH)
                return SRS_RESULT_ADDRESSTOOLONG;

            strncat(buf, &orig_sender[osd], osl - osd);
            strncat(buf, "=", 1);
            strncat(buf, orig_sender, osd - 1);

            lbp += strncpytolower(&lbuf[lbp], &orig_sender[osd], osl - osd);
            lbp += strncpytolower(&lbuf[lbp], orig_sender, osd - 1);
        }
    }
    else
    {
        // Create hash data
        if(osd + rdl - 1 > SRS_MAX_ADDRESS_LENGTH)
            return SRS_RESULT_ADDRESSTOOLONG;

        buf[0] = 0;
        if(mode == 1)
        {
            strncat(buf, &orig_sender[osd], osl - osd);
            strncat(buf, "=", 1);

            lbp += strncpytolower(&lbuf[lbp], &orig_sender[osd], osl - osd);
            lbp += strncpytolower(&lbuf[lbp], &orig_sender[lp_cut], osd - lp_cut - 1);
        }
        else
        {
            n = lp_cut;
            while(orig_sender[n++] != '=' && n < osl);
            
            lbp += strncpytolower(&lbuf[lbp], &orig_sender[lp_cut], n - lp_cut - 1);
            lbp += strncpytolower(&lbuf[lbp], &orig_sender[n], osd - n - 1);            
        }
        
        strncat(buf, &orig_sender[lp_cut], osd - lp_cut - 1);
    }

    // Only do the hash if we need to
    if(mode != 0 || srs->use_hash)
    {
#ifdef DEBUG
    lbuf[lbp] = 0;
    printf("Hash: text='%s' lp_cut='%d'\n", lbuf, lp_cut);
#endif

        // Use OpenSSL HMAC to perform hash
        if(srs__hash(srs, -1, lbuf, lbp, md, &n) != SRS_RESULT_OK)
            return SRS_RESULT_INTERNALERROR;

        // Base64 encode it
        if(srs__base64enc(md, n, lbuf, SRS_MAX_ADDRESS_LENGTH) != SRS_RESULT_OK)
            return SRS_RESULT_INTERNALERROR;

        sz += srs->hash_len + 1;
    }

    if(mode == 0)
    {
        r = strlen(buf);

        if(7 + sz + r + rdl > return_path_len)
            return SRS_RESULT_BUFFERTOOSMALL;

        strncpy(return_path, "SRS0", 5);
        strncat(return_path, &srs->sep, 1);
        if(srs->use_hash)
        {
            strncat(return_path, lbuf, srs->hash_len);
            strncat(return_path, "=", 1);
        }
        strncat(return_path, buf, r);
        strncat(return_path, "@", 1);
        strncat(return_path, return_domain, rdl);
    }
    else
    {
        if(3 + srs->hash_len + osl + rdl - lp_cut > return_path_len - 1)
            return SRS_RESULT_BUFFERTOOSMALL;

        strncpy(return_path, "SRS1", 5);
        strncat(return_path, &srs->sep, 1);
        strncat(return_path, lbuf, srs->hash_len);
        if(mode == 1)
        {
            strncat(return_path, "=", 1);
            strncat(return_path, &orig_sender[osd], osl - osd);
        }
        strncat(return_path, "=", 1);
        strncat(return_path, &orig_sender[lp_cut], osd - lp_cut);
        strncat(return_path, return_domain, rdl);        
    }
    
    return SRS_RESULT_OK;
}


/***********************************************************
    srs_generate_unique_id

*/

srs_result srs_generate_unique_id(srs_t *srs, char *address, char *id_buffer, uint id_buffer_len)
{
    char md[mHMAC_MAX_HASH_LEN];
    char buf[SRS_MAX_ADDRESS_LENGTH];
    int n;

    if(!srs)
        return SRS_RESULT_BADHANDLE;

    // Perform hash on address
    if(srs__hash(srs, -1, address, strlen(address), md, &n) != SRS_RESULT_OK)
        return SRS_RESULT_INTERNALERROR;

    // Base64 encode it
    if(srs__base64enc(md, n, buf, SRS_MAX_ADDRESS_LENGTH) != SRS_RESULT_OK)
        return SRS_RESULT_INTERNALERROR;
    
    // Copy as much as we can to buffer
    strncpy(id_buffer, buf, id_buffer_len);
    id_buffer[id_buffer_len-1] = 0;

    return SRS_RESULT_OK;
}


/***********************************************************
    srs_reverse - retrieve and validate original sender

*/

srs_result srs_reverse(srs_t *srs, char *address, char *destination, uint destination_len)
{
    uint add, adl, n, m, vhash, lbp, hl;
    int mode;
    char lbuf[SRS_MAX_ADDRESS_LENGTH+1];
    char md[mHMAC_MAX_HASH_LEN];

    if(!srs)
        return SRS_RESULT_BADHANDLE;

    // Split up sender and do some basic validation
    if((add = srs__get_domain_start(address)) <= 0)
        return SRS_RESULT_BADPARAM;
    adl = strnlen(address, SRS_MAX_ADDRESS_LENGTH);
    if(add < 2 || add >= adl)
        return SRS_RESULT_BADPARAM;

    // Check if address is already an SRS address (should be!)
    lbp = 0;
    if(address[4] == '=' || address[4] == '+' || address[4] == '-')
    {
        if(strncasecmp(address, "SRS1", 4) == 0)
            mode = 1;
        else if(strncasecmp(address, "SRS0", 4) == 0)
            mode = 0;
        else
            return SRS_RESULT_NOTSRS;

        n = 5;

        // Check for hash and save position if we need to
        if(mode != 0 || srs->use_hash)
        {
            while(address[n] != '=' && n < add)
                n++;
            if(address[n] != '=')
                return SRS_RESULT_BADSRS;

            hl = n - 5;

            n++;
        }
        else
            vhash = SRS_RESULT_OK;

        if(mode == 0)
        {
            if(srs->use_timestamp)
            {
                // Check timestamp
                m = srs_timestamp_check(srs, &address[n], time(NULL));
                if(m == SRS_RESULT_BADCHAR)
                    return SRS_RESULT_BADTIMESTAMP;
                else if(m & SRS_RESULT_FAIL)
                    return SRS_RESULT_TIMESTAMPEXPIRED;

                // Extract address
                if(address[n+2] != '=')
                    return SRS_RESULT_BADSRS;
                
                lbp += strncpytolower(&lbuf[lbp], &address[n], 2);

                n += 3;
            }

            if(srs->use_db)
            {
                // Lookup db id
                if(!srs->db_lookup)
                    return SRS_RESULT_DBERROR;

                // It's all down to the db lookup - but wait for hash verification
                lbp += strncpytolower(&lbuf[lbp], &address[n], add - n - 1);
            }
            else
            {
                // SRS address syntax
                m = n;
                while(address[m] != '=' && m < add)
                    m++;
                if(address[m] != '=')
                    return SRS_RESULT_BADSRS;

                // Fill destination buffer
                if(add - n > destination_len)
                    return SRS_RESULT_BUFFERTOOSMALL;

                destination[0] = 0;
                strncat(destination, &address[m+1], add - m - 1);
                strncat(destination, &address[n], m - n);

                lbp += strncpytolower(&lbuf[lbp], &address[n], m - n);
                lbp += strncpytolower(&lbuf[lbp], &address[m+1], add - m - 2);
            }
        }
        else
        {
            // Extract address
            m = n;
            while(address[m] != '=' && m < add)
                m++;
            if(address[m] != '=')
                return SRS_RESULT_BADSRS;

            // Fill destination buffer
            if(add - n + 4 > destination_len)
                return SRS_RESULT_BUFFERTOOSMALL;

            strncpy(destination, "SRS0", 5);
            strncat(destination, &address[m+1], add - m - 1);
            strncat(destination, &address[n], m - n);

            lbp += strncpytolower(&lbuf[lbp], &address[n], m - n);
            lbp += strncpytolower(&lbuf[lbp], &address[m+1], add - m - 2);
        }


        // Verify hash now we have the data
        if(mode != 0 || srs->use_hash)
        {
#ifdef DEBUG
    lbuf[lbp] = 0;
    printf("Hash verify: text='%s'\n", lbuf);
#endif
            // Verify hash
            vhash = srs__hash_verify(srs, lbuf, lbp, &address[5], hl);
            if(vhash & SRS_RESULT_FAIL)
                return SRS_RESULT_BADHASH;
        }

        if(mode == 0 && srs->use_db)
            return srs->db_lookup(srs, &address[n], add - n - 1, destination, destination_len);

        return vhash; // vhash in case 'case was broken'
    }

    return SRS_RESULT_NOTSRS;
}


/***********************************************************
    srs_add_secret

*/
srs_result srs_add_secret(srs_t *srs, char *secret, uint secret_len)
{
    int n;
    srs_secret_t *sptr;


    if(!srs)
        return SRS_RESULT_BADHANDLE;
    if(secret == NULL)
        return SRS_RESULT_BADPARAM;
    if(secret_len < SRS_MIN_SECRET_LENGTH || secret_len > SRS_MAX_SECRET_LENGTH)
        return SRS_RESULT_BADPARAM;
    if(strnlen(secret, SRS_MAX_SECRET_LENGTH) < SRS_MIN_SECRET_LENGTH)
        return SRS_RESULT_BADPARAM;

    if(srs->secrets_alloc == srs->no_secrets)
    {
        // Allocate more memory
        n = srs->secrets_alloc + 8;

        if(srs->secrets == NULL)
            sptr = malloc(n * sizeof(srs_secret_t));
        else
            sptr = realloc(srs->secrets, n * sizeof(srs_secret_t));

        if(sptr == NULL)
            return SRS_RESULT_OUTOFMEMORY;

        srs->secrets = sptr;
        srs->secrets_alloc = n;
    }

    // Add secret to list
    n = srs->no_secrets++;
    memcpy(srs->secrets[n].secret, secret, secret_len);
    srs->secrets[n].secret_len = secret_len;

    return SRS_RESULT_OK;
}


/***********************************************************
    srs_set_option

*/

srs_result srs_set_option(srs_t *srs, int option, int value)
{
    if(!srs)
        return SRS_RESULT_BADHANDLE;

    switch(option)
    {
        case SRS_OPTION_USETIMESTAMP:
            srs->use_timestamp = (value ? 1 : 0);
            break;
        case SRS_OPTION_USEHASH:
            srs->use_hash = (value ? 1 : 0);
            break;
        default:
            return SRS_RESULT_BADPARAM;
    }

    return SRS_RESULT_OK;
}


/***********************************************************
    srs_set_db_functions

*/

srs_result srs_set_db_functions(srs_t *srs, srs_db_callback *insert_function,
        srs_db_callback *lookup_function)
{
    if(!srs)
        return SRS_RESULT_BADHANDLE;

    srs->db_insert = insert_function;
    srs->db_lookup = lookup_function;

    srs->use_db = (insert_function || lookup_function);

    return (srs->use_db ? SRS_RESULT_OK : SRS_RESULT_DBOFF);
}


/***********************************************************
    srs_geterrormsg - turn an srs_result into some kind
                      of helpful text

*/

char *srs_geterrormsg(srs_result result)
{
    char *msg;

    switch(result)
    {
        case SRS_RESULT_OK:
            msg = "The call was successful";
            break;
        case SRS_RESULT_CASEBROKEN:
            msg = "Hash matched but case was broken";
            break;
        case SRS_RESULT_DBOFF:
            msg = "Database not in use";
            break;
        case SRS_RESULT_BADHANDLE:
            msg = "Invalid SRS handle passed";
            break;
        case SRS_RESULT_BADPARAM:
            msg = "One of the parameters passed was invalid";
            break;
        case SRS_RESULT_BADCHAR:
            msg = "There was an invalid character found (usually in an address)";
            break;
        case SRS_RESULT_BADSRS:
            msg = "The SRS syntax was faulty";
            break;
        case SRS_RESULT_NOTSRS:
            msg = "Address is not a SRS address";
            break;
        case SRS_RESULT_HASHTOOSHORT:
            msg = "Hash shorter than minimum length";
            break;
        case SRS_RESULT_BADHASH:
            msg = "Hash verification failed (forged)";
            break;
        case SRS_RESULT_BADTIMESTAMP:
            msg = "Time stamp contained bad characters";
            break;
        case SRS_RESULT_TIMESTAMPEXPIRED:
            msg = "Time stamp expired";
            break;
        case SRS_RESULT_BADDBID:
            msg = "Database ID lookup failed";
            break;
        case SRS_RESULT_OUTOFMEMORY:
            msg = "Out of memory";
            break;
        case SRS_RESULT_BUFFERTOOSMALL:
            msg = "Return buffer is too small for data";
            break;
        case SRS_RESULT_ADDRESSTOOLONG:
            msg = "Address was too long (either a given address or the processed return data)";
            break;
        case SRS_RESULT_DBERROR:
            msg = "An error occurred querying database";
            break;
        case SRS_RESULT_INTERNALERROR:
            msg = "Internal error";
            break;

            msg = "No error message available.";
            break;
        default:
            msg = "No such SRS error number.";
            break;
    }
    
    return msg;
}
