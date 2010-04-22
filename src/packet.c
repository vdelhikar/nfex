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
#include <libnet.h>

void
process_packet(u_char *user, const struct pcap_pkthdr *header, 
const u_char *packet)
{
    ncc_t *ncc;
    uint8_t *payload;
    connection_t conn;
    srch_results_t *results;
    slist_t *session = NULL;
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr  *tcp;
    /** struct libnet_udp_hdr  *udp; */
    struct libnet_ethernet_hdr *eth;
    u_int16_t ip_hl, tcp_hl /*, udp_hl*/;
    uint32_t header_cruft, payload_size;

    ncc = (ncc_t *)user;

    eth = (struct libnet_ethernet_hdr *)(packet);
    if (eth->ether_type != ntohs(ETHERTYPE_IP))
    {
        /** need a way to warn/log? */
        return;
    }

    ip     = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
    ip_hl  = ip->ip_hl << 2;

    /* if IP header isn't 20 octets, bail */
    if (ip_hl != 20) 
    {
        /** need a way to warn/log? */
        return;
    }

    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            tcp    = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + ip_hl);
            tcp_hl = tcp->th_off << 2;
            header_cruft = LIBNET_ETH_H + ip_hl + tcp_hl;
            break;
        case IPPROTO_UDP:
            /** NYI */
            return;
            /*
            udp    = (struct libnet_udp_hdr *)(packet + LIBNET_ETH_H + ip_hl);
            udp_hl = 8;
            header_cruft = LIBNET_ETH_H + ip_hl + udp_hl;
            break;
            */
        default:
            return;          
    }

    ncc->stats.total_packets++;
    ncc->stats.total_bytes += header->len;

    payload_size = header->len - header_cruft;
    if (payload_size <= 0)
    {
        /** need a way to warn/log? */
        return;
    }

    payload = (uint8_t *)(packet + header_cruft);

    /** copy over timestamp */
    ncc->stats.ts_last.tv_sec  = header->ts.tv_sec;
    ncc->stats.ts_last.tv_usec = header->ts.tv_usec;

    conn.ip_src = ip->ip_src.s_addr;
    conn.ip_dst = ip->ip_dst.s_addr;
    memcpy(conn.eth_src, eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(conn.eth_dst, eth->ether_dhost, ETHER_ADDR_LEN);
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

    /** pass payload to search interface to sift for our yumyums */
    results = search(ncc->srch_machine, &session->srchptr_list, payload, 
        payload_size);

    extract(&session->extract_list, results, session, payload, payload_size, 
        ncc);

    free_results_list(&results);
}

/** EOF */
