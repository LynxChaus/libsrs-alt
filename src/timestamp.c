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

#include "timestamp.h"
#include "address.h"


/***********************************************************
    srs_timestamp_create - buffer must be a 2 byte buffer

*/

srs_result srs_timestamp_create(time_t usetime, char *buffer)
{
    usetime /= 86400;

    buffer[0] = srs__BASE32[(usetime >> 5) & 31];
    buffer[1] = srs__BASE32[usetime & 31];

    return SRS_RESULT_OK;
}


/***********************************************************
    srs_timestamp_check - time_stamp must be a 2 byte buffer

*/

srs_result srs_timestamp_check(srs_t *srs, char *time_stamp, time_t tstime)
{
    uint n, m;

    if(time_stamp[0] > 0)
        n = srs__BASE32rev[time_stamp[0]];
    else
        return SRS_RESULT_BADCHAR;
    if(n < 0 || n == 0x40)
        return SRS_RESULT_BADCHAR;

    if(time_stamp[1] > 0)
        m = srs__BASE32rev[time_stamp[1]];
    else
        return SRS_RESULT_BADCHAR;
    if(m < 0 || m == 0x40)
        return SRS_RESULT_BADCHAR;

    n = ((n << 5) + m);


    tstime /= 86400;
    m = (tstime - srs->max_age) & 1023;
    tstime &= 1023;

    if(n < m)
    {
        if(m <= tstime)
            return SRS_RESULT_FAIL;
        if(n > tstime)
            return SRS_RESULT_FAIL;
    }

    return SRS_RESULT_OK;
}

