/*
 * sessionlist.c - session list stuff
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
session_add(four_tuple_t *ft, ncc_t *ncc)
{
    slist_t *p;

    /** append new element to the end of the session list */
    if (ncc->sessions == NULL)
    {
        /** the last is the first */
        p = ncc->sessions = emalloc(sizeof (slist_t));
        memset(p, 0, sizeof (slist_t));
        p->prev = NULL;
        p->next = NULL;
    }
    else
    {
        /** the last is the last */
        p = ncc->tail;
        p->next = emalloc(sizeof (slist_t));
        memset(p->next, 0, sizeof (slist_t));
        p->next->prev = p;
        p = p->next;
        p->next = NULL;
    }

    memcpy(&(p->ft), ft, sizeof (*ft));
    p->srchptr_list = NULL;
    p->extract_list = NULL;
    ncc->tail       = p;
    ncc->session_count++;

    return (p);
}

slist_t *
session_find(four_tuple_t *ft, ncc_t *ncc)
{
    slist_t *p;

    for (p = ncc->sessions; p; p = p->next)
    {
        if (memcmp(ft, &p->ft, sizeof (four_tuple_t)) == 0)
        {
            /** we've found it */
            break;
        }
    }

    if (p == NULL)
    {
        /** didn't find it */
        return (NULL);
    }

    /** move the newly found session to the top of the list */
    if (ncc->tail == p)
    {
        /** make sure to update the end of list pointer if need be */
        ncc->tail = p->prev ? p->prev : ncc->sessions;
    }
    if (p->prev)
    {
        p->prev->next = p->next;
    }

    if (p->next)
    {
        p->next->prev = p->prev;
    }
    p->prev = NULL;

    if (ncc->sessions != p)
    {
        p->next = ncc->sessions;
    }
    if (p->next)
    {
        p->next->prev = p;
    }
    ncc->sessions = p;

    return (p);
}

void
session_prune(ncc_t *ncc)
{
    time_t now;
    slist_t *p, *p_next;

    p = ncc->sessions;
    if (p == NULL)
    {
        return;
    }

    if (ncc->flags & NFEX_SESSIONS_LOCK)
    {
#if (DEBUG_MODE)
        fprintf(stderr, 
        "[DEBUG MODE] tried to prune sessions but sessionslist is locked\n");
#endif
        /** try again later, next time we're called */
        return;
    }
    /** lock the session list and walk it */
    ncc->flags |= NFEX_SESSIONS_LOCK;

    now = time(NULL);
    for (; p; p = p_next)
    {
        p_next = p->next;
        if (now - p->last_recvd >= SESSION_THRESHOLD)
        {
#if (DEBUG_MODE)
             fprintf(stderr, 
                 "[DEBUG MODE] pruning stale session, %d sessions left\n", 
                 session_count(ncc));
#endif
            if (p->prev == NULL)
            {
                ncc->sessions = p->next;
                if (p->next)
                {
                    p->next->prev = NULL;
                }
                free(p);
            }
            else
            {
                p->prev->next = p->next;
                if (p->next)
                {
                    p->next->prev = p->prev;
                }
                free(p);
            }
        }
    }
    /** unlock session list */
    ncc->session_count--;
    ncc->flags &= ~NFEX_SESSIONS_LOCK;
}

uint32_t
session_count(ncc_t *ncc)
{
    slist_t *p;
    uint32_t n;

    for (n = 0, p = ncc->sessions; p; p = p->next)
    {
        n++;
    }
    return (n);
}

#if (DEBUG_MODE)
void
session_dump(ncc_t *ncc)
{
    slist_t *p;

    fprintf(stderr, "[DEBUG MODE] sessionslist:\n");

    if (ncc->flags & NFEX_SESSIONS_LOCK)
    {
#if (DEBUG_MODE)
        fprintf(stderr,
        "[DEBUG MODE] tried to dump sessions but sessionslist is locked\n");
#endif
        /** try again later, next time we're called */
        return;
    }
    /** lock the session list and walk it */
    ncc->flags |= NFEX_SESSIONS_LOCK;
    
    for (p = ncc->sessions; p; p = p->next)
    {
        printip(p->ft.ip_src, ncc);
        report(":%d -> ", ntohs(p->ft.port_src));
        printip(p->ft.ip_dst, ncc);
        report(":%d\n", ntohs(p->ft.port_dst));
    }
    /** unlock session list */
    ncc->flags &= ~NFEX_SESSIONS_LOCK;

}
#endif

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
