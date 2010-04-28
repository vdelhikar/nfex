/*
 * search.c - searching routines
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
#include "util.h"
#include "search.h"
#include "conf.h"

static size_t currlen;

void
compile_srch(srch_node_t **srch_tree, int id, char *ext, unsigned long maxlen, 
char *spec, spectype_t type)
{
    int i, speclen;
    srch_node_t *node_ptr;

    /** length of the raw HEADER or FOOTER as specified in config file */
    speclen = strlen(spec);
    if (speclen == 0)
    {
        return;
    }

    /** is this the first node? */
    if (*srch_tree == NULL)
    {
        *srch_tree = new_srch_node(TABLE);
    }

    i = 0;
    currlen = 0;
    node_ptr = *srch_tree;

    /** step through the HEADER or FOOTER and process it piece by piece */
    while (i < speclen)
    {
        if (spec[i] == '\\')
        {
            if (i + 1 >= speclen)
            {
                error("Dangling \'\\\' in file type specifier");
            }
            switch (spec[++i])
            {
                case '\\':
                    node_ptr = add_simple(node_ptr, '\\', speclen - i, id, 
                        ext, maxlen, type);
                    break;
                case 'x':
                    if (i + 2 >= speclen)
                    {
                        error("Invalid hex code in file type specifier");
                    }
                    else
                    {
                        char c;
                        int ch;
                        char code[3] = {'\0'};
                        code[0] = spec[++i];
                        code[1] = spec[++i];
                        sscanf(code, "%02x", &ch);
                        c = (char) ch;
                        node_ptr = add_simple(node_ptr, c, speclen - i, id, 
                            ext, maxlen, type);
                    }
                    break;
                case 'n':
                    node_ptr = add_simple(node_ptr, '\n', speclen - i, id, 
                        ext, maxlen, type);
                    break;
                case 't':
                    node_ptr = add_simple(node_ptr, '\t', speclen - i, id, 
                        ext, maxlen, type);
                    break;
                case 'r':
                    node_ptr = add_simple(node_ptr, '\r', speclen - i, id, 
                        ext, maxlen, type);
                    break;
                case '0':
                    node_ptr = add_simple(node_ptr, '\0', speclen - i, id, 
                        ext, maxlen, type);
                    break;
                case '?':
                    node_ptr = add_wildcard(node_ptr, speclen - i, id, 
                        ext, maxlen, type);
                    break;
                default:
                    error("Invalid escape character in file format specifier");
                    break;
            }
        }
        else
        {
            node_ptr = add_simple(node_ptr, spec[i], speclen - i, id, ext, 
                maxlen, type);
        }
        i++;
    }

    /** this assumes node_ptr is pointing to a COMPLETE node */
    node_ptr->data.fileid.len = currlen;
}


static srch_node_t *
new_srch_node(srch_nodetype_t nodetype)
{
    srch_node_t *p;

    p           = ecalloc(sizeof (srch_node_t), 1);
    p->nodetype = nodetype;

    return (p);
}


static srch_node_t *
add_simple(srch_node_t *node, uint8_t c, int remaining, int id, char *ext, 
unsigned long maxlen, spectype_t type)
{
    srch_node_t *newnode;
    srch_node_t *retval;
    
    currlen++;

    if (remaining == 1)
    {   
        /** if remaining is 1 then we need to point to a COMPLETE node */
        newnode                     = new_srch_node(COMPLETE);
        newnode->spectype           = type;
        newnode->data.fileid.id     = id;
        newnode->data.fileid.ext    = ext;
        newnode->data.fileid.maxlen = maxlen;
        node->data.table[c]         = newnode;
        retval                      = newnode;
    }
    else if (node->data.table[c] == NULL)
    {
        newnode             = new_srch_node(TABLE);
        node->data.table[c] = newnode;
        retval              = newnode;
    }
    else
    {
        retval = node->data.table[c];
    }

    return (retval);
}

static srch_node_t *
add_wildcard(srch_node_t *node, int remaining, int id, char *ext, unsigned long maxlen, spectype_t type)
{
    srch_node_t *newnode;
    int i;
    
    currlen++;

    if (remaining == 1)
    {   
        /** if remaining is 1 then we need to point to a COMPLETE node */
        newnode                     = new_srch_node(COMPLETE);
        newnode->spectype           = type;
        newnode->data.fileid.id     = id;
        newnode->data.fileid.ext    = ext;
        newnode->data.fileid.maxlen = maxlen;
        for (i = 0; i < 256; i++)
        {
            /** a specific char trumps a wildcard */
            if (node->data.table[i] == NULL)
            {
                /** shhh, that indicates a slight "feature" */
                node->data.table[i] = newnode;  
            }
        }
        return (newnode);
    }
    else
    {
        newnode = new_srch_node(TABLE);
        for (i = 0; i < 256; i++)
        {
            if (node->data.table[i] == NULL)
            {
                node->data.table[i] = newnode;
            }
        }
        return (newnode);
    }
}

/*
 * the overall search interface.  You call this bad boy and give it a
 * pointer to your data buffer (i.e. a packet)
 */
srch_results_t *
search(srch_node_t *tree, srchptr_list_t **srchptr_list, uint8_t *buf, 
size_t len)
{
    srch_results_t *retval = NULL;
    int i;
    
    /** called once for every byte of data in the payload */
    for (i = 0; i < len; i++)
    {
        /** can this be optimized, can we run on blocks of data? */
        update_search(tree, srchptr_list, &retval, buf[i], i); 
    }

    return (retval);
}

static void
add_srchptr(srchptr_list_t **srchptr_list, srch_node_t *node)
{
    srchptr_list_t *ptr, *ptr2;
    
    ptr = ecalloc(1, sizeof (srchptr_list_t));
    ptr->next = *srchptr_list;

    if (ptr->next)
    {
        ptr->next->prev = ptr;
    }
    ptr->node = node;
    *srchptr_list = ptr;

    for (ptr2 = ptr->next; ptr2 && ptr2 != ptr; ptr2 = ptr2->next);
}

static void
remv_srchptr(srchptr_list_t **srchptr_list, srchptr_list_t *sptr)
{
    if (sptr->prev)
    {
        sptr->prev->next = sptr->next;
    }

    if (sptr->next)
    {
        sptr->next->prev = sptr->prev;
    }

    if (*srchptr_list == sptr)
    {
        *srchptr_list = sptr->next;
    }

    free(sptr);
}

/*
 * I sincerely apologize for this function.  This is called once for every 
 * byte of data so I don't want to waste cycles with layers and layers of 
 * function calls. The end result is a long, complex and unmaintainable 
 * function that is quick
 *
 * The inner demon of the search mechanism.  This updates all state machine 
 * pointers with the current character and fixes the search results list 
 * appropriately
 *
 * FIXME: perhaps make this inline for speed
 */
static void
update_search(srch_node_t *tree, srchptr_list_t **srchptr_list, 
srch_results_t **results, uint8_t c, int offset)
{
    if (*srchptr_list)
    {   
        /** start by updating existing threads */
        srchptr_list_t *ptr;
        srchptr_list_t *nxt;
        for (ptr = *srchptr_list; ptr; ptr = nxt)
        {
            nxt = ptr->next;
            if (ptr->node->data.table[c])
            {
                srch_node_t *node = ptr->node->data.table[c];
                switch (node->nodetype)
                {
                    case TABLE:
                        ptr->node = node;
                        break;
                    case COMPLETE:
                        add_result(results, &node->data.fileid, node->spectype,
                            offset);
                        remv_srchptr(srchptr_list, ptr);
                        break;
                    default:
                        error("Unknown node type");
                        break;
                }
            }
            else
            {
                remv_srchptr(srchptr_list, ptr);
            }
        }
    }

    /** now see if we want to start a new thread (i.e. a new potential match) */
    if (tree->data.table[c])
    {
        srch_node_t *node = tree->data.table[c];

        switch (node->nodetype)
        {
            case TABLE:
                /** this should be 99.99% of them */
                add_srchptr(srchptr_list, node);
                break;
            case COMPLETE:
                /* In the unlikely event of a one byte header */
                /* note to all ideots: if you carve for a one byte header,
                 * you deserve the enormous flood of files that will spew forth.
                 */
                add_result(results, &node->data.fileid, node->spectype, offset);
                break;
            default:
                error("Unknown node type");
                break;     
        }
    }
}

static void
update_search2(srch_node_t *tree, srchptr_list_t **srchptr_list, 
srch_results_t **results, uint8_t c, int offset)
{
    if (*srchptr_list)
    {   /** start by updating existing threads */
        srchptr_list_t *ptr;
        srchptr_list_t *nxt = NULL, *prv = NULL;
                
        for (ptr = *srchptr_list; ptr; prv = ptr, nxt = ptr->next, ptr = nxt)
        {
            if (ptr->node->data.table[c])
            {
                srch_node_t *node = ptr->node->data.table[c];
                switch (node->nodetype)
                {
                    case TABLE:
                        ptr->node = node;
                        break;
                    case COMPLETE:
                        add_result(results, &node->data.fileid, node->spectype,
                            offset);
                    
                        /* remove thread from list */
                        if (prv)
                        {
                            prv->next = nxt;
                        }
                        else
                        {
                            *srchptr_list = nxt;
                        }
                        if (nxt)
                        {
                            nxt->prev = prv;
                        }
                        free(ptr);
                        break;
                    default:
                        error("Unknown node type");
                        break;
                }
            }
            else
            { /*remove thread from list */
                if (prv)
                {
                    prv->next = nxt;
                }
                else
                {
                    *srchptr_list = nxt;
                }
                if (nxt)
                {
                    nxt->prev = prv;
                }
                free(ptr);
            }
        }
    }

    /* now see if we want to start a new thread (i.e. a new potential match) */
    if (tree->data.table[c])
    {
        srch_node_t *node = tree->data.table[c];
        srchptr_list_t *ptr;

        switch (node->nodetype)
        {
        case TABLE:            /* this should be 99.99% of them */
            if (*srchptr_list == NULL)
            {
                *srchptr_list = ecalloc(1, sizeof **srchptr_list);
                (*srchptr_list)->next = NULL;
                (*srchptr_list)->prev = NULL;
                ptr = *srchptr_list;
            }
            else
            {
                for (ptr = *srchptr_list; ptr->next; ptr = ptr->next);
                ptr->next = emalloc(sizeof *ptr->next);
                ptr->next->prev = ptr;
                ptr = ptr->next;
                ptr->next = NULL;
            }
            ptr->node = node;
            break;
        case COMPLETE:       /* In the unlikely event of a one byte header */
            /* note to all ideots: if you carve for a one byte header,
             * you deserve the enormous flood of files that will spew forth.
             */
            add_result(results, &node->data.fileid, node->spectype, offset);
            break;
        default:
            error("Unknown node type");
            break;     
        }
    }
}

/* Add a result to a results list, allocating as needed */
static void 
add_result(srch_results_t **results, fileid_t *fileid, spectype_t spectype, 
int offset)
{
    srch_results_t **ptr, *prev = NULL;

    /* find the last element in the list, for setting prev */
    for (ptr = results; *ptr && (*ptr)->next; ptr = &(*ptr)->next);

    if (*ptr)
    {
        prev = *ptr;
        ptr = &(*ptr)->next;
    }
        
    *ptr = emalloc(sizeof **ptr);
    (*ptr)->next = NULL;
    (*ptr)->prev = NULL;
    (*ptr)->fileid = fileid;
    (*ptr)->spectype = spectype;
    (*ptr)->offset.start = offset - (fileid->len - 1);
    (*ptr)->offset.end = offset;
}

void
free_results_list(srch_results_t **results)
{
    srch_results_t *rptr, *nxt;

    for (rptr = *results; rptr; rptr = nxt)
    {
        nxt = rptr->next;
        free(rptr);
    }
    *results = NULL;
}

/* EOF */
