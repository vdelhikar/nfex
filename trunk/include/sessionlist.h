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

#include <sys/types.h>
#include <inttypes.h>
#include "search.h"
#include "extract.h"

#define SESSION_THRESHOLD 30        /** a session will stale out in 30s */

struct four_tuple
{
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
};
typedef struct four_tuple four_tuple_t;

struct slist_node
{
    struct slist_node *prev;        /* doubley linked list */
    struct slist_node *next;    
    four_tuple_t ft;                /* four tuple information */
    int last_seqnum;                /* the last sequence number recieved */
    time_t last_recvd;              /* the last time a packet was seen */
    int recording;                  /* flag, are currently extracting data */
    srchptr_list_t *srchptr_list;   /* current search threads */
    extract_list_t *extract_list;   /* list of current files being extracted */
};
typedef struct slist_node slist_t;

#endif /* SESSIONLIST_H */
