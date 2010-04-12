/*
 * init.c - initialization routines
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 */
 
#include "nfex.h"

extern FILE *yyin;

ncc_t *
control_context_init(char *output_dir, char *yyinfname, char *device, 
char *capfname, u_int16_t flags, char *errbuf)
{
    int f;
    struct stat stat_info;
    ncc_t *ncc;
    struct bpf_program filter;     /* hold compiled program */
    bpf_u_int32 mask;              /* subnet mask */
    bpf_u_int32 net;               /* ip */
    char filter_app[] = "tcp or udp";
    struct termios term;

    /** gather all the memory we need for a control context */  
    ncc = malloc(sizeof (ncc_t));
    if (ncc == NULL)
    {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "malloc(): %s\n", strerror(errno));
        return (NULL);
    }
    memset(ncc, 0, sizeof (ncc_t));
    
    /** initialize elements of the control context */
    ncc->flags         = flags;
    ncc->device        = device;
    strcpy(ncc->capfname, capfname);
    strcpy(ncc->output_dir, output_dir);

    /** setup the output directory prefix stuff */
    if (ncc->output_dir[0])
    {
        if (stat(output_dir, &stat_info) == -1)
        {
            if (mkdir(output_dir, S_IRWXU) == -1)
            {
                fprintf(stderr, "can't create output dir %s:%s\n", output_dir,
                    strerror(errno));
            }
        }
    }

    if (yyinfname == NULL)
    {
        strcpy(ncc->yyinfname, DEFAULT_CONFIG_FILE);
    }
    else
    {
        strcpy(ncc->yyinfname, yyinfname);
    }

    yyin = fopen(ncc->yyinfname, "r");
    if (yyin == NULL)
    {
        fprintf(stderr, "can't open config file %s: %s\n", ncc->yyinfname,
            strerror(errno));
        goto err;
    }
    yyparse((void *)ncc);

    /** if a pcap file was specified, we go that route */
    if (ncc->capfname[0])
    {
        ncc->p = pcap_open_offline(capfname, errbuf);
        if (ncc->p == NULL)
        {
            fprintf(stderr, "can't open pcap file %s: %s\n", ncc->capfname, 
                errbuf);
            goto err;
        }
        ncc->pcap_fd = pcap_get_selectable_fd(ncc->p);

        if (fstat(ncc->pcap_fd, &stat_info) == -1)
        {
            fprintf(stderr, "can't stat %s, progress will be unavailable\n",
                capfname);
        }
        else
        {
            ncc->capfsize = stat_info.st_size;
        }

        /** need STDIN to nonblock if reading from file */
        f = fcntl(STDIN_FILENO, F_GETFL, 0);
        f |= O_NONBLOCK;
        if (fcntl(STDIN_FILENO, F_SETFL, f) == -1)
        {
            fprintf(stderr, "can't set STDIN to non-blocking: %s\n",
                strerror(errno));
            goto err;
        }
    }
    /** otherwise we go the network route */
    else
    {
        if (ncc->device == NULL)
        {
            ncc->device = pcap_lookupdev(errbuf);
            if (ncc->device == NULL)
            {
                fprintf(stderr, "can't find default device: %s\n", errbuf);
                goto err;
            } 
        }
    
        /** find the properties for the device */
        if (pcap_lookupnet(ncc->device, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "can't get netmask for device %s\n", ncc->device);
            net  = 0;
            mask = 0;
        }
    
        /** open the session in promiscuous mode */
        ncc->p = pcap_open_live(ncc->device, BUFSIZ, 1, 0, errbuf);
        if (ncc->p == NULL)
        {
            fprintf(stderr, "can't open device %s: %s\n", ncc->device, errbuf);
            goto err;
        }
        ncc->pcap_fd = pcap_fileno(ncc->p);
    }

    /** compile and apply the filter */
    if (pcap_compile(ncc->p, &filter, filter_app, 0, net) == -1)
    {
        fprintf(stderr, "can't parse filter %s: %s\n", filter_app,
            pcap_geterr(ncc->p));
        goto err;
    }

    if (pcap_setfilter(ncc->p, &filter) == -1)
    {
        fprintf(stderr, "can't install filter %s: %s\n", filter_app,
            pcap_geterr(ncc->p));
       goto err;
    }


   /**
     * We want to change the behavior of stdin to not echo characters
     * typed and more importantly we want each character to be handed
     * off as soon as it is pressed (not waiting for \r).  To do this
     * we have to manipulate the termios structure and change the normal
     * behavior of stdin.  First we get the current terminal state of 
     * stdin.  If any of this fails, we'll warn, but not quit.
     */
    if (tcgetattr(STDIN_FILENO, &(ncc->term)) == -1)
    {
       /** log_msg(MMP_LOG_ERROR, m, 
            "error getting terminal attributes, CLI will act weird: %s\n",
            strerror(errno)); */
        /* nonfatal */
    }
    else
    {
        /** create a copy to modify, we'll save the original to restore later */
        memcpy((struct termios *)&term, (struct termios *)&(ncc->term), 
           sizeof (struct termios));
        /** disable canonical mode and terminal echo */
        term.c_lflag &= ~ICANON;
        term.c_lflag &= ~ECHO;

        /** set our changed state "NOW" */
        if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
        {
        /**log_msg(MMP_LOG_ERROR, m,
            "error setting terminal attributes, CLI will act weird: %s\n",
            strerror(errno)); */
            /** nonfatal */
        }
    }

    /** set start time */
    if (gettimeofday(&(ncc->stats.ts_start), NULL) == -1)
    {
       /** log_msg(MMP_LOG_ERROR, m,
            "error getting timeofday, can't track server uptime: %s\n",
            strerror(errno));*/

        /** nonfatal */
    }

    /** open the index file */
    snprintf(ncc->indexfname, FILENAME_BUFFER_SIZE, "%s%d-index.txt",
        ncc->output_dir == NULL ? "" : ncc->output_dir, getpid());

    ncc->indexfp = fopen(ncc->indexfname, "w");
    if (ncc->indexfp == NULL)
    {
        fprintf(stderr, "can't open index file: %s\n", strerror(errno));
        goto err;
    }

    printf("initializing with:\noutput dir:\t%s\nconfig file:\t%s\n", 
        ncc->output_dir, ncc->yyinfname);
    if (ncc->device)
    {
        printf("device\t\t%s\n", ncc->device);
    }
    else
    {
        printf("pcap file:\t%s\n", ncc->capfname);
    }
    printf("index file:\t%s\n", ncc->indexfname);
    return (ncc);
err:
    control_context_destroy(ncc);
    return (NULL);
}

void
control_context_destroy(ncc_t *ncc)
{
    if (ncc->p)
    {
        pcap_close(ncc->p);
    }
    if (tcsetattr(STDIN_FILENO, TCSANOW, &(ncc->term)) == -1)
    {
        /** nonfatal */
    }

    /** log_close(m); */

    free(ncc);
    ncc = NULL;
}

/** EOF */
