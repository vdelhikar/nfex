/*
 * extract.c - extraction routines
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

/* Copyright (C) 2005 Nicholas Harbour
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* This file is part of
   Tcpxtract, a sniffer that extracts files based on headers
   by Nick Harbour
*/

#include "nfex.h"
#include "extract.h"
#include "util.h"
#include "config.h"

/*
 * called once for each packet, this function starts, updates, and closes
 * file extractions.  this is the one-stop-shop for all your file extraction 
 * needs
 */
void
extract(extract_list_t **elist, srch_results_t *results, slist_t *session, 
const uint8_t *data, size_t size, ncc_t *ncc)
{
    srch_results_t *rptr;
    extract_list_t *eptr;

    /*
     * set all existing segment values to what they would be with no search 
     * results
     */
    for (eptr = *elist; eptr; eptr = eptr->next)
    {
        set_segment_marks(eptr, size);
    }

    /** look for new headers in the results set */
    for (rptr = results; rptr; rptr = rptr->next)
    {
        if (rptr->spectype == HEADER)
        {
            add_extract(elist, rptr->fileid, session, rptr->offset.start, 
                size, ncc);
        }
    }

    /** flip through any footers we found and close out those extracts */
    for (rptr = results; rptr; rptr = rptr->next)
    {
        if (rptr->spectype == FOOTER)
        {
            mark_footer(*elist, rptr);
        }
    }
    /** now lets do all the file writing and whatnot */
    for (eptr = *elist; eptr; eptr = eptr->next)
    {
        extract_segment(eptr, data, ncc);
    }

    /** remove any finished extractions from the list */
    sweep_extract_list(elist);
}

/* Add a new header match to the list of files being extracted */
static void
add_extract(extract_list_t **elist, fileid_t *fileid, slist_t *session, 
int offset, int size, ncc_t *ncc)
{
    extract_list_t *eptr;

    /* add a new entry to the list */
    eptr = ecalloc(1, sizeof *eptr);
    eptr->next = *elist;
    eptr->fileid = fileid;
    if (eptr->next)
    {
        eptr->next->prev = eptr;
    }

    if (ncc->flags & NFEX_VERBOSE)
    {
        report("found \"%s\" (", fileid->ext);
        printip(session->ft.ip_src, ncc);
        report(":%d -> ", ntohs(session->ft.port_src));
        printip(session->ft.ip_dst, ncc);
        report(":%d), extracting to ", ntohs(session->ft.port_dst));
    }
    eptr->fd = open_extract(fileid->ext, session->ft.ip_src, 
        session->ft.port_src, session->ft.ip_dst, session->ft.port_dst, ncc);
    ncc->stats.total_files++;
    eptr->segment.start = offset;

    if (fileid->maxlen <= size - offset)
    {
        eptr->segment.end = offset + fileid->maxlen;
    }
    else   
    {
        eptr->segment.end = size;
    }
    *elist = eptr;
}

/** open the next availible filename for writing */
static int 
open_extract(char *ext, uint32_t src_ip, uint16_t src_prt, uint32_t dst_ip, 
uint16_t dst_prt, ncc_t *ncc)
{
    int n;
    uint8_t ip_addr_s[4], ip_addr_d[4];
    struct tm *time_machine;
    char fname[FILENAME_BUFFER_SIZE] = {'\0'}, timestamp[50] = {'\0'};

    ncc->filenum++;
    snprintf(fname, FILENAME_BUFFER_SIZE, "%s%d-%06d.%s", 
        ncc->output_dir == NULL ? "" : ncc->output_dir, 
        getpid(), ncc->filenum, ext);

    n = open(fname, O_WRONLY|O_CREAT|O_EXCL, S_IRWXU|S_IRWXG|S_IRWXO);
    /** need to catch error */

    if (ncc->flags & NFEX_VERBOSE)
    {
        report("%s\n", fname);
    }

    /** write out details to index file */
    fprintf(ncc->indexfp, "%s, ", ncc->device ? "live-capture" : ncc->capfname);
    memcpy(ip_addr_s, &src_ip, 4);
    memcpy(ip_addr_d, &dst_ip, 4);

    time_machine = gmtime(&ncc->stats.ts_last.tv_sec);
    strftime(timestamp, 50, "%Y-%m-%dT%H:%M:%S", time_machine);

    fprintf(ncc->indexfp, 
           "%s.%ldZ, %d.%d.%d.%d.%d, %d.%d.%d.%d.%d, %d-%06d.%s\n",
           timestamp, (long)ncc->stats.ts_last.tv_usec,
           ip_addr_s[0], ip_addr_s[1], ip_addr_s[2], ip_addr_s[3], 
           ntohs(src_prt),
           ip_addr_d[0], ip_addr_d[1], ip_addr_d[2], ip_addr_d[3],
           ntohs(dst_prt), getpid(), ncc->filenum, ext);

    fflush(ncc->indexfp);
    return (n);
}

/*
 * set segment start and end values to the contraints of the data buffer or 
 * maxlen
 */
static void
set_segment_marks(extract_list_t *elist, size_t size)
{
    extract_list_t *eptr;

    for (eptr = elist; eptr; eptr = eptr->next)
    {
        eptr->segment.start = 0;
        if (eptr->fileid->maxlen - eptr->nwritten < size)
        {
            eptr->segment.end = eptr->fileid->maxlen - eptr->nwritten;
            eptr->finish++;
        }
        else
        {
            eptr->segment.end = size;
        }
    }
}

/** adjust segment end values depending on footers found */
static void
mark_footer(extract_list_t *elist, srch_results_t *footer)
{
    extract_list_t *eptr;

    /*
     * this associates the first footer found with the last header found of a 
     * given type this is to accommodate embedded document types.  Somebody 
     * may have differing needs so this may want to be reworked later...
     */
    for (eptr = elist; eptr; eptr = eptr->next)
    {
        if (footer->fileid->id == eptr->fileid->id && 
            eptr->segment.start < footer->offset.start)
        {
            /** XXX this could extend beyond maxlen */
            eptr->segment.end = footer->offset.end;
            eptr->finish++;
            break;
        }
    }
}

/** write data to a specified extract file */
static void
extract_segment(extract_list_t *elist, const uint8_t *data, ncc_t *ncc)
{
    size_t c, nbytes;

    nbytes = elist->segment.end - elist->segment.start;

    if ((c = write(elist->fd, data + elist->segment.start, nbytes)) != nbytes)
    {
        fprintf(stderr, "error writing file (%d) wrote %ld of %ld bytes: %s", 
            elist->fd, c, nbytes, strerror(errno));
        ncc->stats.extraction_errors++;
        return; 
/** previously hard quit here; will this have sideeffects?
add a flag to let higher logic know to bail on this one */
    }
    elist->nwritten += nbytes;
    sync();
}

/* remove all finished extracts from the list */
static void
sweep_extract_list(extract_list_t **elist)
{
    extract_list_t *eptr, *nxt;

    for (eptr = *elist; eptr; eptr = nxt)
    {
        nxt = eptr->next;
        if (eptr->finish)
        {
            if (eptr->prev)
            {
                eptr->prev->next = eptr->next;
            }
            if (eptr->next)
            {
                eptr->next->prev = eptr->prev;
            }
            if (*elist == eptr)
            {
                *elist = eptr->next;
            }
            close(eptr->fd);
            free(eptr);
        }
    }
}

void
printip(uint32_t ip, ncc_t *ncc)
{
    uint8_t addr[4];
#if (HAVE_GEOIP)
    GeoIPRecord *gir;
#endif

#if (HAVE_GEOIP)
        if (((ncc->flags) & NFEX_GEOIP) && ncc->gi)
        {
            gir = GeoIP_record_by_ipnum(ncc->gi, ntohl(ip));
            if (gir == NULL)
            {
                /** fall back on printing the IP address */
                goto print_simple;
            }
            if (gir->city && gir->country_code)
            {
                printf("%s, %s", gir->city, gir->country_code);
                return;
            }
            if (gir->city && gir->country_code == NULL)
            {
                printf("%s, ?", gir->city);
                return;
            }
            if (gir->city == NULL && gir->country_code)
            {
                printf("?, %s", gir->country_code);
                return;
            }
            if (gir->city == NULL && gir->country_code == NULL)
            {
                goto print_simple;
            }
        }
#else
        goto print_simple;
#endif /** HAVE_GEOIP */

print_simple:
    memcpy(addr, &ip, 4);
    report("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

    return;
}

/** EOF */
