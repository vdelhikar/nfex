/*
 * util.c - utilities
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
#include <stdarg.h>
#include <math.h>

void
report(char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void *
emalloc(size_t size)
{
    void *p = malloc(size);

    if (p == NULL)
    {
        perror("Error in function emalloc()");
        exit(0);
    }

    return (p);
}

void *
ecalloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb, size);

    if (p == NULL)
    {
        perror("Error in function ecalloc()");
        exit(0);
    }

    return (p);
}

void
error(char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(EXIT_FAILURE);
}

void
convert_seconds(u_int32_t seconds, u_int32_t *d, u_int32_t *h, u_int32_t *m,
u_int32_t *s)
{
    u_int32_t d1, s1;

    d1 = floor(seconds / 86400);
    s1 = seconds - 86400 * d1;

    if (s1 < 0)
    {
        d1 -= 1;
        s1 += 86400;
    }

    *d = d1;
    *s = s1;

    *h = floor((*s) / 3600);
    *s -= 3600 * (*h);

    *m = floor((*s) / 60);
    *s -= 60 * (*m);
}

/** EOF */
