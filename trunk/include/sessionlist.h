/*
 * sessionlist.h - session tracking headers
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

#ifndef SESSIONLIST_H
#define SESSIONLIST_H

#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "extract.h"
#include "search.h"

#define SESSION_THRESHOLD 30        /** a session will stale out in 30s */

typedef struct
{
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
} four_tuple_t;

typedef struct slist_node
{
    struct slist_node *prev;        /* doubley linked list */
    struct slist_node *next;    
    four_tuple_t ft;                /* four tuple information */
    int last_seqnum;                /* the last sequence number recieved */
    time_t last_recvd;              /* the last time a packet was seen */
    int recording;                  /* flag, are currently extracting data */
    srchptr_list_t *srchptr_list;   /* current search threads */
    extract_list_t *extract_list;   /* list of current files being extracted */
} slist_t;

extern slist_t *sessions_add(slist_t **, four_tuple_t *);
extern slist_t *sessions_find(slist_t **, four_tuple_t *);
extern void sessions_prune(slist_t **);
uint32_t count_extractions(slist_t *);

/* for debugging */
uint32_t sessions_count(slist_t *);

#endif /* SESSIONLIST_H */
