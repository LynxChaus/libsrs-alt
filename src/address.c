/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   address.c

   <no description>
*/

#include <string.h>

#include "../config.h"
#include "address.h"


#ifndef SRS_BASE64COMPAT
char srs__BASE64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char srs__BASE64rev[128] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFE, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x40, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#else
char srs__BASE64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.";
char srs__BASE64rev[128] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFE, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0x3F, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x40, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E,
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#endif
char srs__BASE32[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
char srs__BASE32rev[128] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFE, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x20, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };


/***********************************************************
    srs__get_domain_start

*/

int srs__get_domain_start(char *address)
{
    int n = 0;

    // Check we actually have an address
    if(address == NULL)
        return -1;
    if(strnlen(address, SRS_MAX_ADDRESS_LENGTH) <= 0)
        return -1;

    // Scan for '@' character, avoiding '\@'
    while(address[n] != 0 && address[n] != '@' && n < SRS_MAX_ADDRESS_LENGTH)
        if(address[n++] == '\\')
        {
            if(address[n] == '@')
                return -1;
            else
                n++;
        }

    if(address[n] == 0 || n >= SRS_MAX_ADDRESS_LENGTH)
        return 0;

    return ++n;
}


/***********************************************************
    srs__base64enc - hopefully an efficient base64 encoder

    (comments as to compatibility welcome)

*/

srs_result srs__base64enc(unsigned char *data, uint data_len, char *buffer, uint buffer_len)
{
    uint n = 0, m = 0;
    uint dl3 = data_len % 3;

    if((data_len / 3 + (dl3 ? 1 : 0)) << 2 > buffer_len - 1)
        return SRS_RESULT_BUFFERTOOSMALL;
    dl3 = data_len - dl3;

    while(n < dl3)
    {
        buffer[m++] = srs__BASE64[data[n] >> 2];
        buffer[m++] = srs__BASE64[(((data[n] << 8) + data[n+1]) >> 4) & 63];
        n++;
        buffer[m++] = srs__BASE64[(((data[n] << 8) + data[n+1]) >> 6) & 63];
        n++;
        buffer[m++] = srs__BASE64[data[n++] & 63];
    }
    dl3 = data_len - dl3;
    if(dl3 == 1)
    {
        buffer[m++] = srs__BASE64[data[n] >> 2];
        buffer[m++] = srs__BASE64[(data[n++] << 4) & 63];
        buffer[m++] = '=';
        buffer[m++] = '=';
    }
    else if(dl3 == 2)
    {
        buffer[m++] = srs__BASE64[data[n] >> 2];
        buffer[m++] = srs__BASE64[(((data[n] << 8) + data[n+1]) >> 4) & 63];
        n++;
        buffer[m++] = srs__BASE64[(data[n++] << 2) & 63];
        buffer[m++] = '=';
    }

    buffer[m] = 0;

    return SRS_RESULT_OK;
}


/***********************************************************
    srs__base64dec - hopefully an efficient base64 decoder

    (comments as to compatibility welcome)

*/

srs_result srs__base64dec(unsigned char *data, uint data_len, char *buffer, uint buffer_len)
{
    int n = 0, m = 0;
    uint dl4 = data_len & 3;

    if(((data_len >> 2) - (dl4 ? 0 : 1)) * 3 > buffer_len)
        return SRS_RESULT_BUFFERTOOSMALL;
    dl4 = data_len - dl4;

    while(n < dl4)
    {
        n++;
    }
}


/***********************************************************
    srs__base32enc - hopefully an efficient base32 encoder

    (comments as to compatibility welcome)

*/

srs_result srs__base32enc(unsigned char *data, uint data_len, char *buffer, uint buffer_len)
{
    uint n = 0, m = 0;
    uint dl5 = data_len % 5;

    if((data_len / 5 + (dl5 ? 1 : 0)) << 3 > buffer_len-1)
        return SRS_RESULT_BUFFERTOOSMALL;
    dl5 = data_len - dl5;

    while(n < dl5)
    {
        buffer[m++] = srs__BASE32[data[n] >> 3];
        buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 6) & 31];
        n++;
        buffer[m++] = srs__BASE32[(data[n] >> 1) & 31];
        buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 4) & 31];
        n++;
        buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 7) & 31];
        n++;
        buffer[m++] = srs__BASE32[(data[n] >> 2) & 31];
        buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 5) & 31];
        n++;
        buffer[m++] = srs__BASE32[data[n++] & 31];
    }
    dl5 = data_len - dl5;
    if(dl5 & 1)
    {
        if(dl5 & 2)
        {
            // 3 bytes left
            buffer[m++] = srs__BASE32[data[n] >> 3];
            buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 6) & 31];
            n++;
            buffer[m++] = srs__BASE32[(data[n] >> 1) & 31];
            buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 4) & 31];
            n++;
            buffer[m++] = srs__BASE32[(data[n++] >> 1) & 31];
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
        }
        else
        {
            // 1 byte left
            buffer[m++] = srs__BASE32[data[n] >> 3];
            buffer[m++] = srs__BASE32[(data[n++] << 2) & 31];
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
        }
    }
    else
    {
        if(dl5 & 2)
        {
            // 2 bytes left
            buffer[m++] = srs__BASE32[data[n] >> 3];
            buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 6) & 31];
            n++;
            buffer[m++] = srs__BASE32[(data[n] >> 1) & 31];
            buffer[m++] = srs__BASE32[(data[n++] << 4) & 31];
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
            buffer[m++] = '=';
        }
        else
        {
            // 4 bytes left
            buffer[m++] = srs__BASE32[data[n] >> 3];
            buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 6) & 31];
            n++;
            buffer[m++] = srs__BASE32[(data[n] >> 1) & 31];
            buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 4) & 31];
            n++;
            buffer[m++] = srs__BASE32[(((data[n] << 8) + data[n+1]) >> 7) & 31];
            n++;
            buffer[m++] = srs__BASE32[(data[n] >> 2) & 31];
            buffer[m++] = srs__BASE32[(data[n++] << 3) & 31];
            buffer[m++] = '=';
        }
    }

    buffer[m] = 0;

    return SRS_RESULT_OK;
}


/***********************************************************
    strncpytolower

*/

int strncpytolower(char *dest, char *src, int c_max)
{
    int n = 0;

    while(n < c_max)
    {
        if(src[n] >= 'A' && src[n] <= 'Z')
            dest[n] = src[n] + 32;
        else
            dest[n] = src[n];

        if(src[n] == 0)
            break;

        n++;
    }

    return n;
}

