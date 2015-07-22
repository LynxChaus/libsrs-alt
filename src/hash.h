/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   hash.h

   <no description>
*/

#ifndef __LIBSRS_ALT__HASH_H__
#define __LIBSRS_ALT__HASH_H__

#include "srs_alt.h"
#include "../lib/sha1.h"

#include <time.h>



/* Prototypes */

srs_result srs__hash(srs_t *srs, int secret_no, char *data, uint data_len, char *md, uint *md_len);
srs_result srs__hash_verify(srs_t *srs, char *data, uint data_len, char *hash, uint hash_len);


#endif
