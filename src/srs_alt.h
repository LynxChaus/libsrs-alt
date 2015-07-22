/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   srs_alt.h

   <no description>
*/

#ifndef __LIBSRS_ALT__SRS_ALT_H__
#define __LIBSRS_ALT__SRS_ALT_H__

#include <sys/types.h>



/* Some defs */

#define SRS_MAX_SECRET_LENGTH       32
#define SRS_MIN_SECRET_LENGTH       1

#define SRS_DEFAULT_MAX_AGE         31
#define SRS_DEFAULT_HASH_LEN        6
#define SRS_DEFAULT_HASH_MIN        6

#define SRS_MAX_ADDRESS_LENGTH      256


/* Typedefs */

typedef int srs_result;
typedef struct srs_s srs_t;

typedef srs_result (srs_db_callback)(srs_t *srs, char *data, uint data_len, char *result, uint result_len);


/* Structures */

typedef struct srs_secret_s
{
    char                secret[SRS_MAX_SECRET_LENGTH];
    uint                secret_len;
} srs_secret_t;
/*
   WARNING: The srs_s structure is an internal structure and may be
   fundamentally altered in future versions so should NEVER be
   referenced directly. Use the srs functions.
*/
struct srs_s
{
    char                secret[SRS_MAX_SECRET_LENGTH];
    uint                secret_len;
    uint                max_age;
    uint                hash_len;
    uint                hash_min;
    char                sep;
    int                 use_timestamp;
    int                 use_hash;
    int                 use_db;

    srs_db_callback    *db_insert;
    srs_db_callback    *db_lookup;

    uint                no_secrets;
    srs_secret_t       *secrets;
    uint                secrets_alloc;
};


/* Result codes */

// Bit mask for testing success  eg: if(srs_result & SRS_RESULT_FAIL) ERROR();
#define SRS_RESULT_FAIL             0xFF00

// Success
#define SRS_RESULT_OK               0x0000
// Success with warning
#define SRS_RESULT_CASEBROKEN       0x0001
#define SRS_RESULT_DBOFF            0x0002
// Input error
#define SRS_RESULT_BADHANDLE        0x0101
#define SRS_RESULT_BADPARAM         0x0102
#define SRS_RESULT_BADCHAR          0x0103
#define SRS_RESULT_BADSRS           0x0104
#define SRS_RESULT_NOTSRS           0x0105
#define SRS_RESULT_HASHTOOSHORT     0x0106
#define SRS_RESULT_BADHASH          0x0107
#define SRS_RESULT_BADTIMESTAMP     0x0108
#define SRS_RESULT_TIMESTAMPEXPIRED 0x0109
#define SRS_RESULT_BADDBID          0x0110
// Process error
#define SRS_RESULT_OUTOFMEMORY      0x0201
#define SRS_RESULT_BUFFERTOOSMALL   0x0202
#define SRS_RESULT_ADDRESSTOOLONG   0x0203
#define SRS_RESULT_DBERROR          0x0204
// Custom errors (for callbacks 0xF000 through 0xF0FF)
#define SRS_RESULT_CUSTOM           0xF000
// Don't want this one
#define SRS_RESULT_INTERNALERROR    0xFF01


/* Options */

#define SRS_OPTION_USETIMESTAMP     1
#define SRS_OPTION_USEHASH          2


/* Prototypes */

// PUBLIC
#ifdef __cplusplus
extern "C" {
#endif

extern srs_t       *srs_open(char *secret, uint secret_len, uint max_age, uint hash_len, uint hash_min);
extern srs_result   srs_set_separator(srs_t *srs, char separator);
extern srs_result   srs_close(srs_t *srs);
extern srs_result   srs_forward(srs_t *srs, char *orig_sender, char *return_domain,
                        char *return_path, uint return_path_len);
extern srs_result   srs_generate_unique_id(srs_t *srs, char *address, char *id_buffer, uint id_buffer_len);
extern srs_result   srs_reverse(srs_t *srs, char *address, char *destination, uint destination_len);
extern srs_result   srs_add_secret(srs_t *srs, char *secret, uint secret_len);
extern srs_result   srs_set_option(srs_t *srs, int option, int value);
extern srs_result   srs_set_db_functions(srs_t *srs, srs_db_callback *insert_function,
                        srs_db_callback *lookup_function);
extern char        *srs_geterrormsg(srs_result result);

#ifdef __cplusplus
}
#endif


#endif
