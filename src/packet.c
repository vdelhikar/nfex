/*
 * packet.c - pcap callback
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
#include "packet.h"

void
process_packet(u_char *user, const struct pcap_pkthdr *header, 
const u_char *packet)
{
    ncc_t *ncc;

    /* Define pointers for packet's attributes */
    struct sniff_ethernet *ethernet;  /* The ethernet header */
    struct sniff_ip *ip;              /* The IP header */
    struct sniff_tcp *tcp;            /* The TCP header */
    struct sniff_udp *udp;            /* The UDP header */
    uint8_t *payload;                 /* The data */
    
    /* And define the size of the structures we're using */
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip;
    int size_tcp;
    int size_udp = 8;  /* just trust me */
    
    long header_size, payload_size;
    slist_t *session = NULL;
    connection_t conn;
    srch_results_t *results;

    ncc = (ncc_t *)user;

    ncc->stats.total_packets++;

    /* -- Define our packet's attributes -- */
    ethernet = (struct sniff_ethernet*)(packet);
    ip       = (struct sniff_ip*)(packet + size_ethernet);
    size_ip  = ip->ip_hl << 2;
    tcp      = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
    size_tcp = tcp->th_off << 2;
    udp      = (struct sniff_udp*)(packet + size_ethernet + size_ip);

    /* if it ain't IP, bail, hard */
    if (ethernet->ether_type != 0x08) 
    {
        return;
    }

    switch (ip->ip_p)
    {
        case TCP_PROTO:
            header_size = size_ethernet + size_ip + size_tcp;
            break;
        case UDP_PROTO:
            header_size = size_ethernet + size_ip + size_udp;
            break;
        default:
            return;          
    }

    ncc->stats.total_bytes += header->len;

    payload_size = header->len - header_size;
    if (payload_size <= 0)
    {
        return;
    }
    payload = (uint8_t *)(packet + header_size);

    /** copy over timestamp */
    ncc->stats.ts_last.tv_sec = header->ts.tv_sec;
    ncc->stats.ts_last.tv_usec = header->ts.tv_usec;

    conn.ip_src = ip->ip_src.s_addr;
    conn.ip_dst = ip->ip_dst.s_addr;
    memcpy(conn.eth_src, ethernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(conn.eth_dst, ethernet->ether_dhost, ETHER_ADDR_LEN);
    conn.port_src = tcp->th_sport;
    conn.port_dst = tcp->th_dport;

    if (ncc->sessions)
    {
        session = find_session(&(ncc->sessions), &conn);
    }

    if (session == NULL)
    {
        session = add_session(&(ncc->sessions), &conn);
        assert(session);
    }

    session->last_seqnum = tcp->th_seq;
    session->last_recvd  = time(NULL);

    results = search(ncc->srch_machine, &session->srchptr_list, payload, 
        payload_size);

    extract(&session->extract_list, results, session, payload, payload_size, ncc);
    free_results_list(&results);
}

/** EOF */
