/*
 * main.c - main program driver
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */


#include "nfex.h"
#include "sessionlist.h"
#include "config.h"
#include "util.h"
#include "confy.h"
#include "search.h"

int
main(int argc, char *argv[])
{
    int c;
    ncc_t *ncc;
    char *device;
    u_int16_t flags;
    char capfname[128];
    char yyinfname[128];
    char output_dir[128];
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc == 1)
    {
        usage(argv[0]);
    }

    flags = 0;
    device = NULL;
    memset(capfname,   0, sizeof (capfname));
    memset(yyinfname,  0, sizeof (yyinfname));
    memset(output_dir, 0, sizeof (output_dir));
    while ((c = getopt(argc, argv, "c:d:gf:o:hVv")) != EOF)
    {
        switch (c)
        {
            case 'f':
                strncpy(capfname, optarg, 127);
                break;
            case 'd':
                device = strdup(optarg);
                break;
            case 'c':
                strncpy(yyinfname, optarg, 127);
                break;
            case 'g':
                flags |= NFEX_GEOIP;
                break;
            case 'o':
                if (optarg[strlen(optarg) - 1] != '/')
                {
                    strncpy(output_dir, optarg, 126);
                    output_dir[strlen(optarg)] = '/';
                    output_dir[strlen(optarg) + 1] = '\0';
                }
                else
                {
                    strncpy(output_dir, optarg, 127); 
                }
                break;
            case 'h':
                usage(argv[0]);
                break;
            case 'V':
                flags |= NFEX_VERBOSE;
                break;
            case 'v':
                printf("%s v%s\n", PACKAGE, VERSION);
                return (EXIT_SUCCESS);
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    if (optind < argc)
    {
        if (!device)
        {
            device = argv[optind];
        }
    }

    printf("nfex - realtime network file extraction engine\n");
    ncc = control_context_init(output_dir, yyinfname, device, capfname, flags,
            errbuf);
    if (ncc == NULL)
    {
        fprintf(stderr, "can't initialize program, we're done here..\n\n");
        return (EXIT_FAILURE);
    }

    printf("program initialized, now the game can start...\n");

    the_game(ncc);
    stats(ncc);
    control_context_destroy(ncc);
    printf("program completed, normal exit\n");

    return(EXIT_SUCCESS);
}

void
usage(char *progname)
{
    printf("Usage: %s [OPTIONS] [[-d <DEVICE>] || [-f <FILE>]]\n"
           "  -f <FILE>       specify an input capture file\n"
           "  -d <DEVICE>     to specify a network device\n"
           "  -c <FILE>       specify config file\n"
           "  -g              toggle geoIP mode on\n"
           "  -o <DIRECTORY>  dump files here instead of cwd\n"
           "  -V              toggle verbose mode on\n"
           "  -v              display the version number\n"
           "  -h              this\n", progname);
    exit(1);    
}

/** EOF */
