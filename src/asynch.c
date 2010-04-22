/*
 * asynch.c - asynchronous routines
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

#include "nfex.h" 
#include "config.h"

int
the_game(ncc_t *ncc)
{
    int c, n;
    fd_set read_set;

    /** file extraction */
    while (ncc->capfname[1])
    {
        c = pcap_dispatch(ncc->p, 10, process_packet, (u_char *)ncc);
        /** hand the keypress off be processed */
        switch (process_keypress(ncc))
        {
            case 2:
                /** user hit 'q'uit */
                return (2);
            default:
                break;
        }

        sweep_sessions(&ncc->sessions);
        if (c < 0)
        {
            error(pcap_geterr(ncc->p));
        }
        else
        {
            if (c == 0)
            {
                return (1);
            }
        }
    }

    /** network extraction */
    for (; ;)
    {
        /** we multiplex input across the network and STDIN */
        FD_ZERO(&read_set);
        FD_SET(STDIN_FILENO, &read_set);
        FD_SET(ncc->pcap_fd, &read_set);

        /** check the status of our file descriptors */
        c = select(FD_SETSIZE, &read_set, 0, 0, NULL);
        if (c > 0)
        {
            /** input from the network */
            if (FD_ISSET(ncc->pcap_fd, &read_set))
            {
                n = pcap_dispatch(ncc->p, 100, process_packet, (u_char *)ncc);
                sweep_sessions(&ncc->sessions);
                if (n == 0)
                {
                    return (EXIT_SUCCESS);
                }
            }
            /** input from the user */
            if (FD_ISSET(STDIN_FILENO, &read_set))
            {
                /** hand the keypress off be processed */
                switch (process_keypress(ncc))
                {
                    case 2:
                        /** user hit 'q'uit */
                        return (1);
                    default:
                        break;
                }
            }
        }
        if (c == -1)
        {
            perror("error fatal select");
            return (-1);
        }
    }
    /* NOTREACHED */
    return (1);
}

int
process_keypress(ncc_t *ncc)
{
    char buf[1];

    if (read(STDIN_FILENO, buf, 1) == -1)
    {
        /** nonfatal, silent failure */
        return (-2);
    }

    switch (buf[0])
    {
        case 'C':
            /* clear screen */
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            break;
        case 'c':
            /* clear stats */
            /** FIXME: save uptime */
            memset(&ncc->stats, 0, sizeof (ncc->stats));
            printf("statistics cleared\n");
            break;
        case 's':
            /* display statistics */
            stats(ncc);
            break;
        case 'q':
            /* quit program */
            return (2);
        case 'v':
            printf("%s v%s\n", PACKAGE, VERSION);
            break;
        case '?':
            /* help */
            printf("\n-[command summary]-\n");
            printf("[C]   - clear screen\n");
            printf("[c]   - clear statistics\n");
            printf("[s]   - display statistics\n");
            printf("[q]   - quit\n");
            printf("[v]   - display program version\n");
            printf("[?]   - help\n");
            break;
        default:
            break;
    }
    return (1);
}

void
stats(ncc_t *ncc)
{
    struct timeval r, e;
    u_int32_t day, hour, min, sec;

    printf("statistics\n");
    gettimeofday(&e, NULL);
    PTIMERSUB(&e, &(ncc->stats.ts_start), &r);
    convert_seconds((u_int32_t)r.tv_sec, &day, &hour, &min, &sec);
    printf("running time:\t\t\t");
    if (day > 0)
    {
        if (day == 1)
        {
            printf("%d day ", day);
        }
        else
        {
            printf("%d days ", day);
        }
    }
    if (hour > 0)
    {
        if (hour == 1)
        {
            printf("%d hour ", hour);
        }
        else
        {
            printf("%d hours ", hour);
        }
    }
    if (min > 0)
    {
        if (min == 1)
        {
            printf("%d minute ", min);
        }
        else
        {
            printf("%d minutes ", min);
        }
    }
    if (sec > 0)
    {
        if (sec == 1)
        {
            printf("%d second ", sec);
        }
        else
        {
            printf("%d seconds ", sec);
        }
    }
    printf("\n");
    printf("number of sessions\t\t%d\n", count_sessions(ncc->sessions));
    printf("packets churned:\t\t%d\n", ncc->stats.total_packets);
    printf("bytes churned:\t\t\t%lld\n", ncc->stats.total_bytes);
    if (ncc->capfname[0])
    {
        printf("approximate progress:\t\t%.2f%%\n", 
            ((double)ncc->stats.total_bytes * 100) / (double)ncc->capfsize);
    }
    printf("files extracted:\t\t%d\n", ncc->stats.total_files);
    fflush(stdout);
}

/** EOF */
