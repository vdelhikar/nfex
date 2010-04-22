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
    u_int16_t flags = 0;
    char *device;
    char capfname[128];
    char yyinfname[128];
    char output_dir[128];
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc == 1)
    {
        usage(argv[0]);
    }

    memset(capfname,   0, sizeof (capfname));
    memset(yyinfname,  0, sizeof (yyinfname));
    memset(output_dir, 0, sizeof (output_dir));
    device = NULL;
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] =
        {
            {"file",    1, 0, 'f'},
            {"device",  1, 0, 'd'},
            {"config",  1, 0, 'c'},
            {"output",  1, 0, 'o'},
            {"version", 0, 0, 'v'},
            {"help",    0, 0, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "f:d:o:c:hv", long_options, &option_index);

        if (c == -1)
        {
            break;
        }

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
    printf("Usage: %s [OPTIONS] [[-d <DEVICE>] [-f <FILE>]]\n"
           "Valid options include:\n"
           "  --file, -f <FILE>         specify an input capture file\n"
           "  --device, -d <DEVICE>     to specify a network device\n"
           "  --config, -c <FILE>       specify config file\n"
           "  --output, -o <DIRECTORY>  dump files here instead of cwd\n"
           "  --version, -v             display the version number\n"
           "  --help, -h                this\n", progname);
    exit(1);    
}

/** EOF */
