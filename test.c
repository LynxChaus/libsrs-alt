#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>

#include "src/srs_alt.h"
#include "src/address.h"


int main(int argc, char **argv);
srs_result do_db_insert(char *data, uint data_len, char *result, uint result_len);
srs_result do_db_lookup(char *data, uint data_len, char *result, uint result_len);


int main(int argc, char **argv)
{
    char buf[1024];
    char res[1024];
    char starbuf[1204];
    int n, m, errs = 0, star;
    srs_t *srs;
    struct timeb start, finish;

    printf("\nlibsrs_alt test program\n(C)2004 Miles Wilton <miles@mirtol.com>\n\n");

    if(argc < 3 && !(argc == 2 && argv[1][0] == '~'))
    {
        printf("FORWARD Syntax: test <sender address> [*]<return/local domain>+\n\n");
        printf("REVERSE Syntax: test ~<SRS address>\n\nOptional * in front of domain causes a 10000 repeat loop\non that domain. It is recommended to redirect to a file\nas output affects speed report.\n\nPrefixing ~ to first parameter performs reverse SRS on that\naddress (and no further parameters are processed)\n\n");
        printf("The test utility uses a set of default values and will only successfully reverse hashes made by itself.\n\n");
        exit(0);
    }

    printf("Encoding test on '%s':\n", argv[1]);
    n = srs__base64enc(argv[1], strlen(argv[1]), buf, 256);
    if(n == SRS_RESULT_OK)
        printf("  - base64enc: %s\n", buf);
    else
    {
        printf("  - base64enc: Error %d - %s\n", n, srs_geterrormsg(n));
        errs++;
    }
    
    n = srs__base32enc(argv[1], strlen(argv[1]), buf, 256);
    if(n == SRS_RESULT_OK)
        printf("  - base32enc: %s\n", buf);
    else
    {
        printf("  - base32enc: Error %d - %s\n", n, srs_geterrormsg(n));
        errs++;
    }

    printf("\nStarting SRS test:\n\n");
    
    ftime(&start);

    if((srs = srs_open("mysecret", 8, 0, 0, 0)) == NULL)
    {
        printf("srs_open: Failed (returned NULL)\n");
        errs++;
    }
    else
    {
//        srs_set_separator(srs, '+');
//        srs_set_option(srs, SRS_OPTION_USETIMESTAMP, 0);
//        srs_set_option(srs, SRS_OPTION_USEHASH, 0);
//        srs_set_db_functions(srs, do_db_insert, do_db_lookup);

        if(argv[1][0] == '~')
        {
            strcpy(buf, &argv[1][1]);

            while(strncasecmp(buf, "SRS", 3) == 0)
            {
                printf("Resolving SRS address <%s>\n", buf);

                n = srs_reverse(srs, buf, res, 1024);
                if(n & SRS_RESULT_FAIL)
                {
                    printf("srs_forward: Error %d - %s\n", n, srs_geterrormsg(n));
                    errs++;
                    break;
                }
                else if(n != SRS_RESULT_OK)
                    printf("srs_forward: Warning %d - %s\n", n, srs_geterrormsg(n));

                printf("  - SRS forward to: <%s>\n", res);

                strcpy(buf, res);
            }
        }
        else
        {
            strcpy(buf, argv[1]);
            star = 0;

            for(m = 2; m < argc; m++)
            {
                if(argv[m][0] == '*')
                {
            	    sprintf(starbuf, "%d-%s", star, &argv[m][1]);
            	    star++;
            	    if(star < 10000)
	                m--;
	            else
	                star = 0;
            	}
            	else
            	   strcpy(starbuf, argv[m]);
            	
                printf("Fowarding MAIL FROM:<%s> on DOMAIN %s\n", buf, argv[m]);

                n = srs_forward(srs, buf, starbuf, res, 1024);
                if(n == SRS_RESULT_OK)
                    printf("  - SRS return path: <%s>\n", res);
                else
                {
                    printf("srs_forward: Error %d - %s\n", n, srs_geterrormsg(n));
                    errs++;
                    break;
                }
                strcpy(buf, res);
            }
        }

        srs_close(srs);
    }
    
    ftime(&finish);

    if(errs)
        printf("\n\nThere were errors: %d\n\n", errs);
    else
        printf("\n\nTests completed successfully (%.3f seconds).\n\n", (float)(finish.time - start.time) + (float)(finish.millitm - start.millitm) / 1000);

    exit(errs);
}



srs_result do_db_insert(char *data, uint data_len, char *result, uint result_len)
{
    strncpy(result, "DATABASE_ID", result_len);

    return SRS_RESULT_OK;
}


srs_result do_db_lookup(char *data, uint data_len, char *result, uint result_len)
{
    strncpy(result, "DATABASE_EMAIL", result_len);

    return SRS_RESULT_OK;
}
