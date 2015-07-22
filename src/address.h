/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   address.h

   <no description>
*/

#ifndef __LIBSRS_ALT__ADDRESS_H__
#define __LIBSRS_ALT__ADDRESS_H__

#include "srs_alt.h"


/* Prototypes */

extern char srs__BASE64[];
extern char srs__BASE64rev[];
extern char srs__BASE32[];
extern char srs__BASE32rev[];


int srs__get_domain_start(char *address);
int strncpytolower(char *dest, char *src, int c_max);

#ifdef __cplusplus
extern "C" {
#endif

extern srs_result srs__base64enc(unsigned char *data, uint data_len, char *buffer, uint buffer_len);
extern srs_result srs__base64dec(unsigned char *data, uint data_len, char *buffer, uint buffer_len);
extern srs_result srs__base32enc(unsigned char *data, uint data_len, char *buffer, uint buffer_len);

#ifdef __cplusplus
}
#endif


#endif
