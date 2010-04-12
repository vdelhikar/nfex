/*
 * packet.h - network header prototypes and such
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

#define _BSD_SOURCE 1

enum protos
{
    TCP_PROTO = 6,
    UDP_PROTO = 17
    /* anything else on top of ip (like icmp) will be dumped in full */
};

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN];    /* Source host address */
    u_short ether_type;                    /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip
{
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int ip_hl:4,                  /* header length */
    ip_v:4;                         /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int ip_v:4,                   /* version */
    ip_hl:4;                        /* header length */
#endif
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                /* reserved fragment flag */
#define IP_DF 0x4000                /* dont fragment flag */
#define IP_MF 0x2000                /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

/* TCP header */
struct sniff_tcp
{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int   th_x2:4,                /* (unused) */
    th_off:4;                       /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int   th_off:4,               /* data offset */
    th_x2:4;                        /* (unused) */
#endif
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
/* UDP header */
struct sniff_udp
{
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_length;              /* message length */
    u_short uh_sum;                 /* checksum */
};

/** EOF */
