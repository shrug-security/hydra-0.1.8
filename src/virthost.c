/*
 *  Hydra, an http server
 *  Copyright (C) 2002 Nikos Mavroyanopoulos <nmav@gnutls.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* $Id: virthost.c,v 1.13 2002/11/01 18:56:15 nmav Exp $ */

#include "boa.h"

static virthost *virthost_hashtable[VIRTHOST_HASHTABLE_SIZE];

/*
 * Name: add_virthost
 *
 * Description: add a virtual host to the virthost hash table.
 */

void add_virthost(const char *host, const char *ip, const char* document_root,
	const char* user_dir)
{
    int hash;
    virthost *old, *new;
    int hostlen, iplen, document_root_len, user_dir_len = 0;

    /* sanity checking */
    if (host == NULL || ip == NULL || document_root == NULL) {
        DIE("NULL values sent to add_virthost");
    }

    iplen = strlen(ip);
    
    if (iplen > NI_MAXHOST) {
        DIE("IP in virthost is tooooo long");
    }
    hostlen = strlen(host);
    document_root_len = strlen( document_root);
    if (user_dir) user_dir_len = strlen( user_dir);

    if (iplen == 0 || document_root_len == 0) {
        DIE("empty values sent to add_virthost");
    }

    if ( document_root_len > MAX_PATH_LENGTH || user_dir_len > MAX_USER_DIR_LENGTH) {
        DIE("DocumentRoot or UserDir length is too long.");
    }

    hash = get_host_hash_value( host);

    old = virthost_hashtable[hash];

    if (old) {
        while (old->next) {
            if (!strcmp( host, old->host)) /* don't add twice */
                return;
            old = old->next;
        }
    }

    new = (virthost *) calloc(1, sizeof (virthost));
    if (!new) {
        DIE("out of memory adding virthost to hash");
    }

    if (old)
        old->next = new;
    else
        virthost_hashtable[hash] = new;

    new->host = strdup( host);
    if (!new->host) {
        DIE("failed strdup");
    }
    new->host_len = hostlen;

    if (user_dir && user_dir_len > 0) {
    	new->user_dir = strdup(user_dir);
    	new->user_dir_len = user_dir_len;
    } else {
    	new->user_dir = NULL;
    	new->user_dir_len = 0;
    }

    if (iplen == 0 || !strchr( ip, '*')) { /* if the IP part is '*' then 
                             * we don't bind this virthost to a
                             * specific ip */
        new->ip = strdup( ip);
        if (!new->ip) {
           DIE("failed strdup");
        }
        new->ip_len = iplen;
    } else {
    	new->ip = NULL;
    	new->ip_len = 0;
    }

    /* check for "here" */
    new->document_root = strdup(document_root);
    if (!new->document_root) {
        DIE("strdup of document_root failed");
    }
    new->document_root_len = document_root_len;

    new->next = NULL;
}

/*
 * Name: find_virthost
 *
 * Description: Locates host in the virthost hashtable if it exists.
 *
 * Returns:
 *
 * virthost structure or NULL if not found
 */

virthost *find_virthost(const char *_host, int hostlen)
{
    virthost *current;
    int hash;
    char host[MAX_SITENAME_LENGTH], *p;

    /* Find Hostname, IP, document root */
    if (_host==NULL) return NULL;

    if (hostlen == 0)
        hostlen = strlen(_host);
        
    if (hostlen >= MAX_SITENAME_LENGTH)
    	return NULL;

    /* Remove port number.. Ie www.site.gr:8080 
     */
    strcpy( host, _host);
    p = strrchr( host, ':');
    if (p) {
    	*p = 0;
    	hostlen = strlen( host);
    }

    hash = get_host_hash_value( host);

    current = virthost_hashtable[hash];
    while (current) {
#ifdef FASCIST_LOGGING
        fprintf(stderr,
                "%s:%d - comparing \"%s\" (request) to \"%s\" (virthost): ",
                __FILE__, __LINE__, host, current->host);
#endif
        /* current->host_len must always be:
         *  equal to the host
         */
        if (current->host_len == hostlen &&
            !memcmp(host, current->host, current->host_len)) {
#ifdef FASCIST_LOGGING
                fprintf(stderr, "Got it!\n");
#endif
                return current;
        }
#ifdef FASCIST_LOGGING
        else
            fprintf(stderr, "Don't Got it!\n");
#endif
        current = current->next;
    }
    return current;
}



/*
 * Empties the virthost hashtable, deallocating any allocated memory.
 */

void dump_virthost(void)
{
    int i;
    virthost *temp;

    for (i = 0; i < VIRTHOST_HASHTABLE_SIZE; ++i) { /* these limits OK? */
        if (virthost_hashtable[i]) {
            temp = virthost_hashtable[i];
            while (temp) {
                virthost *temp_next;

                if (temp->host)
                    free(temp->host);
                free(temp->access_nodes);
                if (temp->ip)
                    free(temp->ip);
                if (temp->document_root)
                    free(temp->document_root);
                if (temp->user_dir)
                    free(temp->user_dir);
                dump_alias( temp); /* clear all aliases */

                temp_next = temp->next;
                free(temp);
                temp = temp_next;
            }
            virthost_hashtable[i] = NULL;
        }
    }
}
