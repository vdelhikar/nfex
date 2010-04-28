/*
 * sessionlist.c - session linkage stuff
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
#include "sessionlist.h"
#include "extract.h"
#include "util.h"

slist_t *
sessions_add(slist_t **slist, four_tuple_t *ft)
{
    slist_t **last_slist;
    slist_t *slist_ptr = NULL;

    /* find where to append a new element (aka. the end) */
    if (*slist == NULL)
    {
        last_slist = slist;
    }
    else
    {
        for (slist_ptr = *slist; slist_ptr->next; slist_ptr = slist_ptr->next);
        last_slist = &slist_ptr->next;
    }

    *last_slist = (slist_t *) emalloc(sizeof (slist_t));

    memcpy(&(*last_slist)->ft, ft, sizeof (*ft));
    (*last_slist)->prev         = slist_ptr;
    (*last_slist)->next         = NULL;
    (*last_slist)->srchptr_list = NULL;
    (*last_slist)->extract_list = NULL;
    return (*last_slist);
}

slist_t *
sessions_find(slist_t **slist, four_tuple_t *ft)
{
    slist_t *slist_ptr;
    uint32_t ip_src;      
 /* keep this so we don't need to dereference conn each time */

    ip_src = ft->ip_src;
    
    for (slist_ptr = *slist; slist_ptr; slist_ptr = slist_ptr->next)
    {
       // if (ip_src == slist_ptr->ft.ip_src && 
       //     memcmp(ft, &slist_ptr->ft, sizeof (four_tuple_t)) == 0)
        if (memcmp(ft, &slist_ptr->ft, sizeof (four_tuple_t)) == 0)
        {
            /* we've found it */
            break;
        }
    }

    if (slist_ptr == NULL)
    {
        /** didn't find it */
        return (NULL);
    }

    /* move the newly found session to the top of the list */
    if (slist_ptr->prev)
    {
        slist_ptr->prev->next = slist_ptr->next;
    }

    if (slist_ptr->next)
    {
        slist_ptr->next->prev = slist_ptr->prev;
    }
    slist_ptr->prev = NULL;

    if (*slist != slist_ptr)
    {
        slist_ptr->next = *slist;
    }
    if (slist_ptr->next)
    {
        slist_ptr->next->prev = slist_ptr;
    }
    *slist = slist_ptr;

    return (slist_ptr);
}

/* This function cleans out any old sessions from the list */
void
sessions_prune(slist_t **slist)
{
    time_t currtime = time(NULL);
    slist_t *slist_ptr, *slist_next;

    for (slist_ptr = *slist; slist_ptr; slist_ptr = slist_next)
    {
        slist_next = slist_ptr->next;
        if (currtime - slist_ptr->last_recvd >= SESSION_THRESHOLD)
        {
#if (DEBUG)
             fprintf(stderr, "pruning stale session, %d total sessions left\n", 
                 count_sessions(*slist));
#endif /** DEBUG */
            if (slist_ptr->prev == NULL)
            {
                *slist = slist_ptr->next;
                if (slist_ptr->next)
                {
                    slist_ptr->next->prev = NULL;
                }
                free(slist_ptr);
            }
            else
            {
                slist_ptr->prev->next = slist_ptr->next;
                if (slist_ptr->next)
                {
                    slist_ptr->next->prev = slist_ptr->prev;
                }
                free(slist_ptr);
            }
        }
    }
}

uint32_t
sessions_count(slist_t *slist)
{
    slist_t *ptr;
    uint32_t n;

    for (n = 0, ptr = slist; ptr; ptr = ptr->next)
    {
        n++;
    }
    return (n);
}

uint32_t
count_extractions(slist_t *slist)
{
    slist_t *s_ptr;
    extract_list_t *e_ptr;
    uint32_t k;

    if (slist == NULL)
    {
        return (0);
    }

    /** walk the sessionlist list */
    for (k = 0, s_ptr = slist; s_ptr; s_ptr = s_ptr->next)
    {
        /** walk the extraction list */
        for (e_ptr = slist->extract_list; e_ptr; e_ptr = e_ptr->next)
        {
            if (e_ptr->fd > 0)
            {
                k++;
            }
        }
    }
    return (k);
}


/** EOF */
