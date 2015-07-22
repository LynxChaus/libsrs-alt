/***********************************************************
*       libsrs_alt - A simple SRS implementation           *
***********************************************************/

/* ©2004 Miles Wilton <miles@mirtol.com> */

/* License: GPL */

/* This file:

   srs.c

   srs command line tool and daemon
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>


#include "src/srs_alt.h"

/* Prototypes */

int main(int argc, char **argv, char **env);
int display_help(void);
int add_secret(char *secret);
int do_forward(FILE *fh, char *add, char *als);
int do_reverse(FILE *fh, char *add);
int start_srs(void);
int srsd(void);
void handle_signal(int signum);


/* Defs */

#define MAX_FILE_LINE_LENGTH            1024
#define MAX_SOCKET_LINE_LENGTH          1024
#define MAX_SOCKET_WAITING              8


/* Global vars */

char *alias = NULL;
int hashlength = SRS_DEFAULT_HASH_LEN;
char separator = '=';
char **secrets = NULL;
int secrets_size = 0;
int secrets_count = 0;
int mode = 0;
char *socket_name = "/tmp/srsd";

srs_t *srs;
srs_t **srsa;


/***********************************************************
    main

*/

int main(int argc, char **argv, char **env)
{
    int n, m, r;
    char *add;
    char srsbuf[SRS_MAX_ADDRESS_LENGTH+1];

    /*
       -- PROCESS COMMAND LINE --
    */
    for(n = 1; n < argc; n++)
    {
        if(argv[n][0] == '-')
        {
            // Flag
            if(argv[n][1] == '-')
                m = 2;
            else
                m = 1;

            if(strncasecmp(&argv[n][m], "address=", 8) == 0)
            {
                // Ok, savr for later
            }
            else if(strncasecmp(&argv[n][m], "alias=", 6) == 0)
            {
                if((alias = strchr(&argv[n][m+6], '@')) == NULL)
                    alias = &argv[n][m+6];
                else
                    alias++;
            }
            else if(strncasecmp(&argv[n][m], "d", 2) == 0)
            {
                if(mode != 0)
                {
                    fprintf(stderr, "ERROR: reverse, forward and d flags are mutually exclusive\n\n");
                    exit(1);
                }
                mode = -1;
            }
            else if(strncasecmp(&argv[n][m], "forward", 8) == 0)
            {
                if(mode != 0)
                {
                    fprintf(stderr, "ERROR: reverse, forward and d flags are mutually exclusive\n\n");
                    exit(1);
                }
                mode = 1;
            }
            else if(strncasecmp(&argv[n][m], "hashlength=", 11) == 0)
            {
                hashlength = atoi(&argv[n][m+11]);
                if(hashlength < 1)
                {
                    fprintf(stderr, "ERROR: Invalid hash length\n\n");
                    exit(1);
                }
            }
            else if(strncasecmp(&argv[n][m], "help", 5) == 0)
            {
                display_help();
                exit(0);
            }
            else if(strncasecmp(&argv[n][m], "reverse", 8) == 0)
            {
                if(mode != 0)
                {
                    fprintf(stderr, "ERROR: reverse, forward and d flags are mutually exclusive\n\n");
                    exit(1);
                }
                mode = 2;
            }
            else if(strncasecmp(&argv[n][m], "secret=", 7) == 0)
            {
                if(add_secret(&argv[n][m+7]))
                {
                    fprintf(stderr, "ERROR: Out of memory\n\n");
                    exit(1);
                }
            }
            else if(strncasecmp(&argv[n][m], "secretfile=", 11) == 0)
            {
                FILE *fh;
                char buf[MAX_FILE_LINE_LENGTH];
                int l;

                if((fh = fopen(&argv[n][m+11], "r")) == NULL)
                {
                    fprintf(stderr, "ERROR: Could not open file '%s'\n\n", &argv[n][m+11]);
                    exit(1);
                }

                // Read in file and add secrets
                while(fgets(buf, MAX_FILE_LINE_LENGTH, fh))
                {
                    l = strnlen(buf, MAX_FILE_LINE_LENGTH);
                    if(buf[l-1] == '\n')
                    {
                        buf[l-1] = 0;
                        l--;
                    }

                    if(l > 0)
                    {
                        if(add_secret(strdup(buf)))
                        {
                            fprintf(stderr, "ERROR: Out of memory\n\n");
                            exit(1);
                        }
                    }
                }

                fclose(fh);
            }
            else if(strncasecmp(&argv[n][m], "separator=", 10) == 0)
            {
                char c = argv[n][m+10];
                if(c == '+' || c == '-' || c == '=')
                    separator = c;
                else
                {
                    fprintf(stderr, "ERROR: Invalid separtor '%c'\n\n", c);
                    exit(1);
                }
            }
            else if(strncasecmp(&argv[n][m], "socket=", 7) == 0)
            {
                if(mode != -1)
                {
                    fprintf(stderr, "ERROR: socket must come after d\n\n");
                    exit(1);
                }
                socket_name = &argv[n][m+7];
            }
            else
            {
                fprintf(stderr, "ERROR: Unknown flag '%s'\n\n", argv[n]);
                exit(1);
            }
        }
    }


    /*
       -- CHECK SETTINGS --
    */
    if(mode == 1 && alias == NULL)
    {
        fprintf(stderr, "ERROR: You must specify an alias\n\n");
        exit(1);
    }

    if(secrets_count == 0)
    {
        fprintf(stderr, "ERROR: No secret specified\n\n");
        exit(1);
    }


    /*
       -- SET UP SRS HANDLES --
    */
    start_srs();


    /*
       -- PERFORM TASK --
    */
    if(mode == 1 || mode == 2)
    {
        // Command line call
        n = 1;
        for(n = 1; n < argc; n++)
        {
            if(argv[n][0] == '-')
            {
                // Flag
                if(argv[n][1] == '-')
                    m = 2;
                else
                    m = 1;

                // If not address flag, go on to next param
                if(strncasecmp(&argv[n][m], "address=", 8) != 0)
                    continue;

                // Set pointer
                add = &argv[n][m+8];
            }
            else
                add = argv[n];

            // Do it
            if(mode == 1)
                do_forward(stdout, add, alias);
            else
                do_reverse(stdout, add);
        }
    }
    else if(mode == -1)
        // Daemonise
        srsd();
    else
    {
        printf("ERROR: You must specify one of forward, reverse or d\n\n");
        exit(1);
    }

    // Should never get here!
    return -1;
}


/***********************************************************
    display_help - show help text

*/
int display_help(void)
{
    printf("srs - libsrs_alt library http://srs.mirtol.com/\n(C)2004 Miles Wilton\n\n");
    printf("Syntax: srs <flags> <address>+\n\n");
    printf("    Actions\n");
    printf("        -d               Run daemon\n");
    printf("        --forward        Perform SRS forward on address\n");
    printf("        --reverse        Perform SRS reverse on address\n");
    printf("\n    Options\n");
    printf("        --address=       Different way of specifying addresses to process\n");
    printf("        --alias=         Alias domain (or address) for SRS forward\n");
    printf("        --hashlength=    Characters in hash length\n");
    printf("        --help           Display this help\n");
    printf("        --secret=        SRS secret\n");
    printf("        --secretfile=    Read file for SRS secret(s)\n");
    printf("        --separator=     SRS separator, must be + - or =\n");
    printf("        --socket=        Specify SRS socket for daemon\n");
    printf("\nSyntax compatible with perl implementation Mail::SRS\nMultiple secrets and addresses supported, can also use - instead of --\n\n");

    return 0;
}


/***********************************************************
    add_secret

*/

int add_secret(char *secret)
{
    // Check array space
    if(secrets == NULL)
    {
        secrets = (char **)malloc(32 * sizeof(char *));
        if(secrets == NULL)
            return 1;
        secrets_size = 32;
    }

    if(secrets_size == secrets_count)
    {
        char **ra;

        ra = (char **)realloc(secrets, (secrets_count + 32) * sizeof(char *));
        if(ra == NULL)
            return 1;
        secrets = (char **)ra;
        secrets_count += 32;
    }

    // Add to array
    secrets[secrets_count++] = secret;

    return 0;
}


/***********************************************************
    do_forward

*/

int do_forward(FILE *fh, char *add, char *als)
{
    char srsbuf[SRS_MAX_ADDRESS_LENGTH];
    int r;

    // SRS Forward
    if((r = srs_forward(srs, add, als, srsbuf, SRS_MAX_ADDRESS_LENGTH)) & SRS_RESULT_FAIL)
        fprintf(fh, "ERROR: Address '%s' failed - %s\n", add, srs_geterrormsg(r));
    else
        fprintf(fh, "%s\n", srsbuf);

    return 0;
}


/***********************************************************
    do_reverse

*/

int do_reverse(FILE *fh, char *add)
{
    char srsbuf[SRS_MAX_ADDRESS_LENGTH];
    int m, r;

    // SRS Reverse
    for(m = 0; m < secrets_count; m++)
    {
        if((r = srs_reverse(srsa[m], add, srsbuf, SRS_MAX_ADDRESS_LENGTH)) & SRS_RESULT_FAIL)
        {
            if(r == SRS_RESULT_NOTSRS || r == SRS_RESULT_BADSRS || r == SRS_RESULT_HASHTOOSHORT
                    || r == SRS_RESULT_BADTIMESTAMP || r == SRS_RESULT_BADTIMESTAMP)
                m = secrets_count;
        }
        else
            break;
    }

    if(m >= secrets_count)
        fprintf(fh, "ERROR: Could not validate address '%s' - %s\n", add, srs_geterrormsg(r));
    else
    {
        fprintf(fh, "%s\n", srsbuf);
        if(r == SRS_RESULT_CASEBROKEN)
            fprintf(fh, "WARNING: Case broken on hash in address '%s'\n", add);
    }
}


/***********************************************************
    start_srs

*/

int start_srs(void)
{
    int n;

    if(mode == 1)
    {
        // Only one secret required, even if multiple secrets given
        if((srs = srs_open(secrets[0], strnlen(secrets[0], SRS_MAX_SECRET_LENGTH), 0, hashlength, hashlength)) == NULL)
        {
            fprintf(stderr, "ERROR: SRS initialisation failed\n\n");
            exit(1);
        }
    }
    else
    {
        // For reverse or daemon, all secrets required
        if((srsa = (srs_t **)malloc(secrets_count * sizeof(srs_t *))) == NULL)
        {
            fprintf(stderr, "ERROR: Out of memory\n\n");
            exit(1);
        }

        for(n = 0; n < secrets_count; n++)
            if((srsa[n] = srs_open(secrets[n], strnlen(secrets[n], SRS_MAX_SECRET_LENGTH), 0, hashlength, hashlength)) == NULL)
            {
                fprintf(stderr, "ERROR: SRS initialisation failed\n\n");
                exit(1);
            }

        srs = srsa[0];
    }

    return 0;
}


/***********************************************************
    srsd

*/

int srsd(void)
{
    int n, children = 0;

    if((n = fork()) == 0)
    {
        // Child - open a socket and wait...

        int s, sl, ns, csl;
        struct sockaddr_un *sa, cs;

        if((s = socket(AF_UNIX, SOCK_STREAM, 0)) == 0)
        {
            printf("ERROR: Could not create socket\n\n");
            exit(1);
        }

        // Setup socket bind
        sl = sizeof(sa->sun_family) + strlen(socket_name);
        if((sa = (struct sockaddr_un *)malloc(sl)) == NULL)
        {
            printf("ERROR: Out of memory\n\n");
            exit(1);
        }
        
        sa->sun_family = AF_UNIX;
        strcpy(sa->sun_path, socket_name);

        // Delete any file that might obstruct socket
        unlink(socket_name);

        // Bind to socket
        if(bind(s, (struct sockaddr *)sa, sl) != 0)
        {
            printf("ERROR: Could not bind to socket\n\n");
            exit(1);
        }

        // Listen for connections
        if(listen(s, MAX_SOCKET_WAITING) != 0)
        {
            printf("ERROR: Could not listen to socket\n\n");
            exit(1);
        }

        // Setup SIGCHLD handler
        signal(SIGCHLD, handle_signal);

        // Accept connections
        csl = sizeof(cs);

        while((ns = accept(s, (struct sockaddr *)&cs, &csl)) > 0)
        {
            // Start thread to process request
            if(fork() == 0)
            {
                FILE *sr;
                char buf[MAX_SOCKET_LINE_LENGTH];
                int nn, nl;

                // Open for reading
                if((sr = fdopen(ns, "r+")) == NULL)
                {
                    printf("ERROR: Failed to open descriptor\n");

                    // Close socket and continue
                    close(ns);
                    continue;
                }

                // Wait for command
                fgets(buf, MAX_SOCKET_LINE_LENGTH, sr);
                nl = strnlen(buf, MAX_SOCKET_LINE_LENGTH);

                // Remove \n from end of string
                {
                if(buf[nl-1] == '\n')
                    buf[nl-1] = 0;
                    nl--;
                }

                // Process command
                if(strncasecmp(buf, "forward ", 8) == 0)
                {
                    for(nn = 8; nn < nl; nn++)
                        if(buf[nn] == ' ')
                            break;
                    if(nn >= nl)
                        fprintf(sr, "ERROR\n");
                    else
                    {
                        buf[nn++] = 0;
                        do_forward(sr, &buf[n+8], &buf[nn]);
                    }
                }
                else if(strncasecmp(buf, "reverse ", 8) == 0)
                    do_reverse(sr, &buf[n+8]);
                else
                    fprintf(sr, "ERROR\n");

                // Close stream
                fclose(sr);

                // Close socket
                close(ns);

                // End thread
                exit(0);
            }
            else
            {
                // Close socket handle as far as parent is concerned
                close(ns);
            }

            // Reset csl
            csl = sizeof(cs);
        }
      
        // Close socket
        close(s);

        // Close handles and free memory
        for(n = 0; n < secrets_count; n++)
            srs_close(srsa[n]);
        free(srsa);
        free(secrets);

        exit(0);
    }
    else
    {
        // Parent - quits peacably if successful
        printf("srs - libsrs_alt library http://srs.mirtol.com/\n©2004 Miles Wilton\n\n");
        if(n == -1)
        {
            printf("ERROR: fork() failed\n");
            exit(1);
        }

        printf("Daemon started\n");
        exit(0);
    }
}


/***********************************************************
    srsd

*/

void handle_signal(int signum)
{
    if(signum == SIGCHLD)
        wait(NULL);
}

