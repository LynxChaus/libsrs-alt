/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   timestamp.h

   <no description>
*/

#ifndef __LIBSRS_ALT__TIMESTAMP_H__
#define __LIBSRS_ALT__TIMESTAMP_H__

#include <time.h>

#include "srs_alt.h"




/* Prototypes */

srs_result srs_timestamp_create(time_t time, char *buffer);
srs_result srs_timestamp_check(srs_t *srs, char *time_stamp, time_t tstime);


#endif
